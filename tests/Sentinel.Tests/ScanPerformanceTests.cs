using System.IO.Compression;
using System.Text;
using Sentinel.Core.Protection;

internal static class ScanPerformanceTests
{
    private const string Marker = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    private const string Fixture = "Sentinel harmless resource fixture v0.7\n";
    private static readonly System.Security.Cryptography.RSA Signer = System.Security.Cryptography.RSA.Create(3072);
    private static VerifiedFeed FixtureFeed()
    {
        var now = DateTimeOffset.UtcNow;
        var payload = new FeedPayload(1, 1, now, now.AddDays(1), [new(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(Fixture))), "Harmless test fixture", "Unit tests")]);
        var data = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(payload, FeedVerifier.Json);
        var signature = Signer.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var envelope = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(data), Convert.ToBase64String(signature)), FeedVerifier.Json);
        return FeedVerifier.Verify(envelope, Signer.ExportSubjectPublicKeyInfoPem(), now);
    }
    private static void Check(bool ok) { if (!ok) throw new Exception("Scan control/resource assertion failed"); }
    private static async Task Fails<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private sealed class Temporary : IDisposable
    {
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory, "scan-resource-test-" + Guid.NewGuid().ToString("N"));
        public Temporary() { Directory.CreateDirectory(Root); }
        public string File(string name) => Path.Combine(Root, name);
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
    private sealed class InlineProgress(Action<ScanProgress> action) : IProgress<ScanProgress>
    { public void Report(ScanProgress value) => action(value); }
    private static ScanReport Evidence(Temporary tmp, int count = 1, string? reason = null) => new(DateTimeOffset.UtcNow,
        TimeSpan.FromSeconds(1), count, 0, count, 0, 0, false, false, 16, 0, true,
        Enumerable.Range(0, count).Select(i => new FileFinding(tmp.File("item-" + i), FileVerdict.NeedsReview, reason ?? "Review fixture", Bytes: 16)).ToArray());

    public static void Register(Action<string, Func<Task>> test)
    {
        test("Wide folder traversal retains one directory level and checks every file", async () => {
            using var tmp = new Temporary();
            for (var i = 0; i < 256; i++) await System.IO.File.WriteAllTextAsync(tmp.File($"file-{i}.txt"), "ordinary fixture");
            var report = await new FileScanner().ScanPathAsync(tmp.Root);
            Check(report.Scanned == 256 && !report.Incomplete && report.PeakPendingDirectories == 1);
        });
        test("Streaming traversal distinguishes an exact entry budget from omitted entries", async () => {
            using var tmp = new Temporary();
            await System.IO.File.WriteAllTextAsync(tmp.File("one.txt"), "one"); await System.IO.File.WriteAllTextAsync(tmp.File("two.txt"), "two");
            var exact = await new FileScanner(limits: new(MaxFiles: 3)).ScanPathAsync(tmp.Root);
            var bounded = await new FileScanner(limits: new(MaxFiles: 2)).ScanPathAsync(tmp.Root);
            Check(exact.Scanned == 2 && !exact.LimitReached && bounded.Scanned == 1 && bounded.LimitReached && bounded.Incomplete);
        });
        test("Directory depth remains bounded and the skipped subtree stays explicit", async () => {
            using var tmp = new Temporary(); var nested = tmp.Root;
            for (var i = 0; i < 66; i++) { nested = Path.Combine(nested, "d"); Directory.CreateDirectory(nested); }
            await System.IO.File.WriteAllTextAsync(Path.Combine(nested, "too-deep.txt"), "fixture");
            var report = await new FileScanner().ScanPathAsync(tmp.Root);
            Check(report.Scanned == 0 && report.Skipped == 1 && report.PeakPendingDirectories == 64 && report.Incomplete);
        });
        test("Streaming traversal preserves exact detections when retained findings fill up", async () => {
            using var tmp = new Temporary();
            for (var i = 0; i < 6; i++) await System.IO.File.WriteAllTextAsync(tmp.File($"review-{i}.pdf.exe"), "benign review fixture");
            for (var i = 0; i < 2; i++) await System.IO.File.WriteAllTextAsync(tmp.File($"test-{i}.txt"), Fixture);
            var report = await new FileScanner(FixtureFeed(), limits: new(MaxFindings: 2)).ScanPathAsync(tmp.Root);
            Check(report.Detected == 2 && report.Review == 6 && report.FindingsTruncated && report.Findings.All(x => x.Verdict == FileVerdict.KnownThreat));
        });
        test("Pause prevents content reads until resume, which reads the current file", async () => {
            using var tmp = new Temporary(); var path = tmp.File("paused.txt");
            await System.IO.File.WriteAllTextAsync(path, "ordinary fixture");
            var control = new ScanControl(); Check(control.Pause() && !control.Pause() && control.IsPaused);
            var task = new FileScanner(FixtureFeed(), control: control).ScanPathAsync(path);
            Check(!task.IsCompleted);
            await System.IO.File.WriteAllTextAsync(path, Fixture);
            Check(control.Resume() && !control.Resume() && !control.IsPaused);
            var report = await task.WaitAsync(TimeSpan.FromSeconds(5));
            Check(report.Detected == 1 && report.Scanned == 1 && !report.Canceled);
        });
        test("Cancellation releases a paused scan without requiring resume", async () => {
            using var tmp = new Temporary(); await System.IO.File.WriteAllTextAsync(tmp.File("file.txt"), "fixture");
            var control = new ScanControl(ScanMode.LowImpact); control.Pause();
            using var cancel = new CancellationTokenSource();
            var task = new FileScanner(control: control).ScanPathAsync(tmp.Root, token: cancel.Token);
            Check(!task.IsCompleted); cancel.Cancel();
            var report = await task.WaitAsync(TimeSpan.FromSeconds(5));
            Check(report.Canceled && report.Incomplete && report.Scanned == 0 && report.Mode == ScanMode.LowImpact);
        });
        test("Pause then cancellation retains completed findings and releases directory handles", async () => {
            using var tmp = new Temporary();
            for (var i = 0; i < 3; i++) await System.IO.File.WriteAllTextAsync(tmp.File($"file-{i}.txt"), Fixture);
            var control = new ScanControl(); using var cancel = new CancellationTokenSource();
            var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var progress = new InlineProgress(p => { if (p.Scanned == 1) { control.Pause(); stopped.TrySetResult(); } });
            var task = new FileScanner(FixtureFeed(), control: control).ScanPathAsync(tmp.Root, progress, cancel.Token);
            await stopped.Task.WaitAsync(TimeSpan.FromSeconds(5)); Check(!task.IsCompleted); cancel.Cancel();
            var report = await task.WaitAsync(TimeSpan.FromSeconds(5));
            Check(report.Scanned == 1 && report.Detected == 1 && report.Findings.Count == 1 && report.Canceled);
            // Subsequent operations on the folder must still work after cancellation.
            var renamed = tmp.Root + "-renamed"; Directory.Move(tmp.Root, renamed); Directory.Move(renamed, tmp.Root);
        });
        test("Low impact scans preserve file and archive verdicts with mode recorded", async () => {
            using var tmp = new Temporary();
            for (var i = 0; i < 35; i++) await System.IO.File.WriteAllTextAsync(tmp.File($"ordinary-{i}.txt"), "fixture");
            await System.IO.File.WriteAllTextAsync(tmp.File("invoice.pdf.exe"), "review fixture");
            using (var zip = ZipFile.Open(tmp.File("sample.zip"), ZipArchiveMode.Create))
            { await using var writer = new StreamWriter(zip.CreateEntry("test.txt").Open()); await writer.WriteAsync(Fixture); }
            var feed = FixtureFeed();
            var balanced = await new FileScanner(feed).ScanPathAsync(tmp.Root);
            var low = await new FileScanner(feed, control: new(ScanMode.LowImpact)).ScanPathAsync(tmp.Root);
            Check(low.Mode == ScanMode.LowImpact && low.Scanned == balanced.Scanned && low.ArchiveEntries == 1 && low.Detected == 1 && low.Review == 1 && !low.Incomplete);
            Check(low.Findings.OrderBy(x => x.DisplayPath).SequenceEqual(balanced.Findings.OrderBy(x => x.DisplayPath)));
        });
        test("Small prefix preserves standard test padding and full script review prefix", async () => {
            using var tmp = new Temporary();
            var padded = Marker + new string(' ', 128 - Marker.Length);
            var paddedBytes = Encoding.ASCII.GetBytes(padded);
            Check(FileScanner.IsStandardTestFile(paddedBytes, paddedBytes.Length));
            await System.IO.File.WriteAllTextAsync(tmp.File("review.PS1"), new string('x', 20_000) + " FromBase64String Invoke-Expression");
            Check((await new FileScanner().ScanFileAsync(tmp.File("review.PS1"))).Verdict == FileVerdict.NeedsReview);
        });
        test("Low impact chunk pacing preserves the complete hash of a multi-megabyte file", async () => {
            using var tmp = new Temporary(); var bytes = new byte[5 * 1024 * 1024]; bytes[^1] = 42;
            var path = tmp.File("large.bin"); await System.IO.File.WriteAllBytesAsync(path, bytes);
            var result = await new FileScanner(control: new(ScanMode.LowImpact)).ScanFileAsync(path);
            Check(result.Bytes == bytes.Length && result.Sha256 == Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)));
        });
        test("Unsupported and corrupt archive signatures remain incomplete without filename extensions", async () => {
            using var tmp = new Temporary();
            byte[][] signatures = [[0x37,0x7a,0xbc,0xaf,0x27,0x1c], [0x1f,0x8b,0,0], Encoding.ASCII.GetBytes("Rar!")];
            for (var i = 0; i < signatures.Length; i++) {
                var path = tmp.File($"archive-{i}.bin"); await System.IO.File.WriteAllBytesAsync(path, signatures[i]);
                var result = await new FileScanner().ScanFileDetailedAsync(path);
                Check(result.ArchiveFindings.Single().Verdict == (i == 1 ? FileVerdict.Error : FileVerdict.Skipped));
            }
        });
        test("Streamed reports retain long evidence, scan mode and traversal metrics", async () => {
            using var tmp = new Temporary(); var report = Evidence(tmp, 2000, new string('x', 4000)) with { Mode = ScanMode.LowImpact, PeakPendingDirectories = 32 };
            await ScanReports.SaveAsync(report, tmp.File("report.json")); var loaded = ScanReports.Load(tmp.File("report.json"));
            Check(loaded.Findings.SequenceEqual(report.Findings) && loaded.Mode == ScanMode.LowImpact && loaded.PeakPendingDirectories == 32);
        });
        test("Streamed export overflow retains the old destination and removes staging", async () => {
            using var tmp = new Temporary(); var path = tmp.File("report.json"); await System.IO.File.WriteAllTextAsync(path, "keep existing content");
            var report = Evidence(tmp, 400, new string('\u0001', 8192));
            await Fails<InvalidDataException>(() => ScanReports.SaveAsync(report, path));
            Check(await System.IO.File.ReadAllTextAsync(path) == "keep existing content" && !Directory.EnumerateFiles(tmp.Root, ".sentinel-report-*.tmp").Any());
        });
        test("Canceled streamed export retains the destination and removes staging", async () => {
            using var tmp = new Temporary(); var path = tmp.File("report.json"); await System.IO.File.WriteAllTextAsync(path, "keep existing content");
            using var cancel = new CancellationTokenSource(); cancel.Cancel();
            await Fails<OperationCanceledException>(() => ScanReports.SaveAsync(Evidence(tmp), path, cancel.Token));
            Check(await System.IO.File.ReadAllTextAsync(path) == "keep existing content" && !Directory.EnumerateFiles(tmp.Root, ".sentinel-report-*.tmp").Any());
        });
        test("Report validation rejects unsupported modes and unbounded traversal metrics", async () => {
            using var tmp = new Temporary();
            await Fails<InvalidDataException>(() => ScanReports.SaveAsync(Evidence(tmp) with { Mode = (ScanMode)99 }, tmp.File("invalid.json")));
            await Fails<InvalidDataException>(() => ScanReports.SaveAsync(Evidence(tmp) with { PeakPendingDirectories = 65 }, tmp.File("invalid.json")));
            await Fails<ArgumentOutOfRangeException>(() => Task.Run(() => new ScanControl((ScanMode)99)));
        });
        test("Historical reports without v0.7 metadata load with balanced defaults", async () => {
            using var tmp = new Temporary();
            var json = System.Text.Json.Nodes.JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(Evidence(tmp), ScanReports.Json))!.AsObject();
            json.Remove("mode"); json.Remove("peakPendingDirectories");
            await System.IO.File.WriteAllTextAsync(tmp.File("historical.json"), json.ToJsonString());
            var loaded = ScanReports.Load(tmp.File("historical.json"));
            Check(loaded.Mode == ScanMode.Balanced && loaded.PeakPendingDirectories == 0 && loaded.Review == 1);
        });
        test("Catalog compaction preserves signed payload text, order and hash lookup", () => {
            var now = DateTimeOffset.UtcNow;
            var payload = new FeedPayload(1, 9, now, now.AddDays(1), [
                new(new string('a',64), "Case-sensitive label", "shared source"),
                new(new string('b',64), "case-sensitive label", "shared source"),
                new(new string('c',64), "Case-sensitive label", "shared source")]);
            var data = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(payload, FeedVerifier.Json);
            var signature = Signer.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            var envelope = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(data), Convert.ToBase64String(signature)), FeedVerifier.Json);
            var feed = FeedVerifier.Verify(envelope, Signer.ExportSubjectPublicKeyInfoPem(), now);
            Check(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(feed.Payload, FeedVerifier.Json).SequenceEqual(data));
            Check(feed.Hashes[new string('B',64)].Label == "case-sensitive label" && feed.Hashes.Count == 3);
            return Task.CompletedTask;
        });
        test("Streaming metadata never follows symbolic-link children outside the scan root", async () => {
            if (OperatingSystem.IsWindows()) return; // Windows junctions are in the manual acceptance matrix.
            using var tmp = new Temporary(); var folder = tmp.File("scanned"); Directory.CreateDirectory(folder);
            var target = tmp.File("outside.txt"); await System.IO.File.WriteAllTextAsync(target, Fixture);
            System.IO.File.CreateSymbolicLink(Path.Combine(folder,"link.txt"), target);
            var report = await new FileScanner(FixtureFeed()).ScanPathAsync(folder);
            Check(report.Scanned == 0 && report.Detected == 0 && report.Skipped == 1 && report.Incomplete);
        });
    }
}
