using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Core.Protection;

internal static class MonitorTests
{
    private static void Check(bool ok, string message = "Monitoring assertion failed") { if (!ok) throw new Exception(message); }
    private static async Task Until(Func<bool> condition, string message)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try { while (!condition()) await Task.Delay(10, deadline.Token); }
        catch (OperationCanceledException) { throw new Exception(message); }
    }
    private sealed class Temporary : IDisposable
    {
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory, "monitor-test-" + Guid.NewGuid().ToString("N"));
        public Temporary() { Directory.CreateDirectory(Root); }
        public string PathFor(string name) => Path.Combine(Root, name);
        public void Dispose() { Directory.Delete(Root, true); }
    }
    private sealed class Clock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(GetTimestamp());
        public void Advance() => Interlocked.Add(ref ticks, TimeSpan.FromSeconds(31).Ticks);
    }
    private static VerifiedFeed Feed(params byte[][] fixtures)
    {
        using var key = RSA.Create(3072); var now = DateTimeOffset.UtcNow;
        var payload = JsonSerializer.SerializeToUtf8Bytes(new FeedPayload(1, 1, now, now.AddDays(1),
            fixtures.Select((value, index) => new HashIndicator(Convert.ToHexString(SHA256.HashData(value)), "Harmless monitoring fixture " + index, "Sentinel test fixture")).ToArray()), FeedVerifier.Json);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(payload),
            Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))), FeedVerifier.Json);
        return FeedVerifier.Verify(envelope, key.ExportSubjectPublicKeyInfoPem(), now);
    }
    private static FileFinding Finding(int number, FileVerdict verdict = FileVerdict.NeedsReview) => new("file-" + number, verdict, "Benign bounded inbox fixture", number.ToString("x64"));
    public static void Register(Action<string, Func<Task>> test)
    {
        test("Monitoring checks pre-existing files with independent signed intelligence", async () => {
            using var tmp = new Temporary(); var bytes = Encoding.UTF8.GetBytes("Sentinel harmless initial monitoring fixture"); var feed = Feed(bytes);
            var path = tmp.PathFor("existing.bin"); await File.WriteAllBytesAsync(path, bytes);
            var findings = new ConcurrentQueue<FileFinding>();
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed), findings.Enqueue, _ => { });
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Initial recovery did not finish");
            Check(findings.Any(x => x.Path == path && x.Verdict == FileVerdict.KnownThreat));
            Check(monitor.RecoveryStatus.Scanned == 1 && monitor.RecoveryStatus.Detected == 1 && !monitor.RecoveryStatus.Incomplete);
        });
        test("Recovery excludes storage before reading and respects sibling path boundaries", async () => {
            using var tmp = new Temporary(); var bytes = Encoding.UTF8.GetBytes("Sentinel harmless excluded-storage fixture"); var feed = Feed(bytes);
            var excluded = tmp.PathFor("storage"); var sibling = tmp.PathFor("storage-sibling"); Directory.CreateDirectory(excluded); Directory.CreateDirectory(sibling);
            await File.WriteAllBytesAsync(Path.Combine(excluded, "private.bin"), bytes); await File.WriteAllBytesAsync(Path.Combine(sibling, "included.bin"), bytes);
            var findings = new ConcurrentQueue<FileFinding>();
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed), findings.Enqueue, _ => { }, [excluded]);
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Excluded initial scan did not finish");
            Check(monitor.RecoveryStatus.Scanned == 1 && monitor.RecoveryStatus.Skipped == 1);
            Check(!findings.Any(x => x.Path.EndsWith("private.bin")) && findings.Any(x => x.Path.EndsWith("included.bin") && x.Verdict == FileVerdict.KnownThreat));
            Check(findings.Any(x => x.Path == excluded && x.Verdict == FileVerdict.Skipped));
            var observed = monitor.ObservedChanges; await File.WriteAllBytesAsync(Path.Combine(excluded, "later.bin"), bytes); await Task.Delay(200);
            Check(monitor.ObservedChanges == observed);
        });
        test("Monitoring recovery requests coalesce and changed files run during cooldown", async () => {
            using var tmp = new Temporary(); var bytes = Encoding.UTF8.GetBytes("Sentinel harmless cooldown fixture"); var feed = Feed(bytes); var clock = new Clock();
            var found = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed), value => { if (value.Verdict == FileVerdict.KnownThreat) found.TrySetResult(); }, _ => { }, time: clock);
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Initial scan did not finish");
            for (var i = 0; i < 10_000; i++) Check(monitor.RequestRecovery());
            await File.WriteAllBytesAsync(tmp.PathFor("changed.bin"), bytes); await found.Task.WaitAsync(TimeSpan.FromSeconds(20));
            Check(monitor.RecoveryStatus.Completed == 1 && monitor.RecoveryStatus.Pending && monitor.DroppedEvents == 0);
            clock.Advance(); monitor.RequestRecovery();
            await Until(() => monitor.RecoveryStatus.Completed == 2, "Coalesced recovery did not finish");
            Check(monitor.RecoveryStatus.Detected == 1 && !monitor.RecoveryStatus.Pending);
        });
        test("A populated directory moved into the watched folder queues recovery", async () => {
            using var tmp = new Temporary(); var watched = tmp.PathFor("watched"); var incoming = tmp.PathFor("incoming"); Directory.CreateDirectory(watched); Directory.CreateDirectory(incoming);
            var bytes = Encoding.UTF8.GetBytes("Sentinel harmless moved-directory fixture"); var feed = Feed(bytes); var clock = new Clock();
            await File.WriteAllBytesAsync(Path.Combine(incoming, "payload.bin"), bytes);
            var findings = new ConcurrentQueue<FileFinding>();
            await using var monitor = new FolderMonitor(watched, () => new FileScanner(feed), findings.Enqueue, _ => { }, time: clock);
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Initial empty scan did not finish");
            Directory.Move(incoming, Path.Combine(watched, "moved"));
            await Until(() => monitor.RecoveryStatus.Pending, "Directory move did not request recovery");
            clock.Advance(); monitor.RequestRecovery();
            await Until(() => monitor.RecoveryStatus.Completed >= 2, "Directory recovery did not finish");
            Check(findings.Any(x => x.Path.EndsWith("payload.bin") && x.Verdict == FileVerdict.KnownThreat));
        });
        test("Event overflow stays bounded and queues recovery while a scan is paused", async () => {
            using var tmp = new Temporary(); var control = new ScanControl(); control.Pause(); var clock = new Clock();
            var bytes = Encoding.UTF8.GetBytes("Sentinel harmless overflow fixture"); var feed = Feed(bytes);
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed, control: control), _ => { }, _ => { }, time: clock);
            await Until(() => monitor.RecoveryStatus.Scanning, "Initial scan did not enter paused checkpoint");
            for (var i = 0; i < 650; i++) await File.WriteAllBytesAsync(tmp.PathFor("burst-" + i + ".bin"), bytes);
            await Until(() => monitor.DroppedEvents > 0, "Overflow did not reach the bounded file queue");
            Check(monitor.PendingFiles <= 512 && monitor.RecoveryStatus.Pending);
            control.Resume(); await Until(() => monitor.RecoveryStatus.Completed == 1, "Recovery of the burst did not finish");
            Check(monitor.RecoveryStatus.Scanned == 650 && monitor.RecoveryStatus.Detected == 650);
            clock.Advance(); monitor.RequestRecovery(); await Until(() => monitor.RecoveryStatus.Completed >= 2, "Overflow recovery did not finish");
            Check(monitor.RecoveryStatus.Scanned == 650 && monitor.IsRunning);
        });
        test("Stopping a paused recovery cancels promptly and releases pending work", async () => {
            using var tmp = new Temporary(); var control = new ScanControl(); control.Pause();
            var findings = new ConcurrentQueue<FileFinding>();
            var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(control: control), findings.Enqueue, _ => { });
            try
            {
                await Until(() => monitor.RecoveryStatus.Scanning, "Recovery did not start");
                await File.WriteAllTextAsync(tmp.PathFor("pending.txt"), "Benign pending file");
                await monitor.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3));
                await monitor.DisposeAsync();
                Check(!monitor.IsRunning && !monitor.RecoveryStatus.Scanning && monitor.PendingFiles == 0 && !monitor.RequestRecovery() && findings.IsEmpty);
            }
            finally { control.Resume(); await monitor.DisposeAsync(); }
        });
        test("Monitoring checks a rewrite after delivery without dropping the new generation", async () => {
            using var tmp = new Temporary(); var first = Encoding.UTF8.GetBytes("Sentinel harmless rewrite one"); var second = Encoding.UTF8.GetBytes("Sentinel harmless rewrite two"); var feed = Feed(first, second);
            var path = tmp.PathFor("rewrite.bin"); var found = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var rewritten = 0;
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed), value => {
                if (value.Sha256 == Convert.ToHexString(SHA256.HashData(first)) && Interlocked.Exchange(ref rewritten, 1) == 0) File.WriteAllBytes(path, second);
                if (value.Sha256 == Convert.ToHexString(SHA256.HashData(second))) found.TrySetResult();
            }, _ => { });
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Initial scan did not finish");
            await File.WriteAllBytesAsync(path, first); await found.Task.WaitAsync(TimeSpan.FromSeconds(20));
            Check(monitor.CompletedScans >= 2 && monitor.IsRunning);
        });
        test("Recovery time budget reports partial coverage and leaves change monitoring alive", async () => {
            using var tmp = new Temporary(); var control = new ScanControl(); control.Pause();
            var bytes = Encoding.UTF8.GetBytes("Sentinel harmless recovery-timeout fixture"); var feed = Feed(bytes);
            var found = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed, control: control), value => {
                if (value.Verdict == FileVerdict.KnownThreat) found.TrySetResult();
            }, _ => { }, recoveryTimeout: TimeSpan.FromSeconds(1));
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Recovery deadline did not end a paused scan");
            Check(monitor.RecoveryStatus.Canceled && monitor.RecoveryStatus.Incomplete && monitor.IsRunning);
            control.Resume(); await File.WriteAllBytesAsync(tmp.PathFor("later.bin"), bytes); await found.Task.WaitAsync(TimeSpan.FromSeconds(20));
            Check(monitor.CompletedScans == 1);
        });
        test("Recovery coverage limits remain explicit and delivery failures do not stop the worker", async () => {
            using var tmp = new Temporary(); var bytes = Encoding.UTF8.GetBytes("Sentinel harmless bounded recovery fixture"); var feed = Feed(bytes);
            for (var i = 0; i < 4; i++) await File.WriteAllBytesAsync(tmp.PathFor(i + ".bin"), bytes);
            var messages = new ConcurrentQueue<string>();
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed, new(MaxFiles: 3)), _ => throw new Exception("Private observer failure"), messages.Enqueue);
            await Until(() => monitor.RecoveryStatus.Completed == 1, "Bounded recovery did not finish");
            Check(monitor.RecoveryStatus.Scanned == 2 && monitor.RecoveryStatus.LimitReached && monitor.IsRunning);
            Check(messages.Any(x => x.Contains("could not be delivered")) && messages.Any(x => x.Contains("coverage gaps")) && !messages.Any(x => x.Contains("Private")));
        });
        test("Scanner exclusions are bounded and never hide an implicit scan limit", async () => {
            using var tmp = new Temporary(); var excluded = tmp.PathFor("excluded"); Directory.CreateDirectory(excluded);
            await File.WriteAllTextAsync(Path.Combine(excluded, "skip.txt"), "benign");
            var report = await new FileScanner().ScanPathAsync(tmp.Root, excludedDirectories: [excluded]);
            Check(report.Scanned == 0 && report.Skipped == 1 && report.Incomplete && !report.LimitReached);
            try { await new FileScanner().ScanPathAsync(tmp.Root, excludedDirectories: Enumerable.Repeat(excluded, 33)); throw new Exception("Expected exclusion bound"); } catch (ArgumentException) { }
            try { await new FileScanner().ScanPathAsync(tmp.Root, excludedDirectories: ["relative"]); throw new Exception("Expected absolute exclusion"); } catch (ArgumentException) { }
        });
        test("Live inbox deduplicates evidence and prioritizes exact detections under pressure", () => {
            var inbox = new FindingInbox(32);
            for (var i = 0; i < 32; i++) { inbox.Add(Finding(i)); inbox.Add(Finding(i)); }
            for (var i = 32; i < 42; i++) inbox.Add(Finding(i, FileVerdict.KnownThreat));
            Check(inbox.Count == 32 && inbox.Dropped == 10);
            var batch = inbox.Drain(32); Check(batch.Count(x => x.Verdict == FileVerdict.KnownThreat) == 10 && inbox.Count == 0);
            inbox.Add(batch[0]); Check(inbox.Drain().Length == 1);
            return Task.CompletedTask;
        });
        test("Live inbox never replaces an exact detection with a lower priority result", () => {
            var inbox = new FindingInbox(4); for (var i = 0; i < 4; i++) inbox.Add(Finding(i, FileVerdict.KnownThreat));
            inbox.Add(Finding(99, FileVerdict.Error)); inbox.Add(Finding(98, FileVerdict.TestFile));
            Check(inbox.Count == 4 && inbox.Dropped == 2 && inbox.Drain().All(x => x.Verdict == FileVerdict.KnownThreat));
            return Task.CompletedTask;
        });
        test("Concurrent live bursts retain bounded evidence without duplicate identities", async () => {
            var inbox = new FindingInbox(512);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(worker => Task.Run(() => {
                for (var i = 0; i < 20_000; i++) inbox.Add(Finding(i % 800, i % 3 == 0 ? FileVerdict.KnownThreat : FileVerdict.NeedsReview));
            })));
            Check(inbox.Count == 512 && inbox.Dropped > 0);
            var batches = new List<FileFinding>(); while (inbox.Count > 0) batches.AddRange(inbox.Drain(128));
            Check(batches.Count == 512 && batches.DistinctBy(x => (x.Path, x.Sha256, x.Verdict)).Count() == 512);
            Check(inbox.Drain().Length == 0);
        });
    }
}
