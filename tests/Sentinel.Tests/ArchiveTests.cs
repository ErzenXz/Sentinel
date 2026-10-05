using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Core.Protection;

internal static class ArchiveTests
{
    private static void Check(bool ok) { if (!ok) throw new Exception("Archive/report assertion failed"); }
    private static async Task Fails<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private sealed class Temporary : IDisposable
    {
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory, "archive-test-" + Guid.NewGuid().ToString("N"));
        public Temporary() { Directory.CreateDirectory(Root); }
        public string File(string name) => Path.Combine(Root, name);
        public void Dispose() { Directory.Delete(Root, true); }
    }
    private static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var memory = new MemoryStream();
        using (var zip = new ZipArchive(memory, ZipArchiveMode.Create, true))
            foreach (var item in entries) { using var output = zip.CreateEntry(item.Name, CompressionLevel.NoCompression).Open(); output.Write(item.Data); }
        return memory.ToArray();
    }
    private static VerifiedFeed FeedFor(params byte[][] files)
    {
        var now = DateTimeOffset.UtcNow;
        var payload = new FeedPayload(1, 1, now, now.AddDays(1), files.Select(data => new HashIndicator(Convert.ToHexString(SHA256.HashData(data)), "Harmless archive fixture", "Unit tests")).ToArray());
        using var key = RSA.Create(3072); var data = JsonSerializer.SerializeToUtf8Bytes(payload, FeedVerifier.Json);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(data), Convert.ToBase64String(key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))), FeedVerifier.Json);
        return FeedVerifier.Verify(envelope, key.ExportSubjectPublicKeyInfoPem(), now);
    }
    private static int Central(byte[] zip) { for (var i = 0; i < zip.Length - 3; i++) if (BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(i, 4)) == 0x02014b50) return i; throw new Exception("Missing central header"); }
    private sealed class TestProtector : IKeyProtector
    {
        public byte[] Protect(byte[] key) => key.ToArray();
        public byte[] Unprotect(byte[] key) => key.ToArray();
    }
    private sealed class InlineProgress(Action<ScanProgress> action) : IProgress<ScanProgress> { public void Report(ScanProgress value) => action(value); }
    public static void Register(Action<string, Func<Task>> test)
    {
        test("ZIP detects contained exact hashes without extracting any files", async () => {
            using var tmp = new Temporary(); var payload = Encoding.UTF8.GetBytes("harmless contained fixture"); var path = tmp.File("download.zip");
            await System.IO.File.WriteAllBytesAsync(path, Zip(("folder/payload.bin", payload)));
            var result = await new FileScanner(FeedFor(payload)).ScanFileDetailedAsync(path);
            var finding = result.ArchiveFindings.Single(x => x.Verdict == FileVerdict.KnownThreat);
            Check(result.File.Verdict == FileVerdict.NoKnownMatch && finding.Path == path && finding.ArchiveEntry == "folder/payload.bin" && finding.ContainerSha256 == result.File.Sha256);
            Check(result.ArchiveEntries == 1 && result.ArchiveBytesRead == payload.Length && Directory.GetFileSystemEntries(tmp.Root).Length == 1);
            Check((await new FileScanner(FeedFor(payload)).ScanFileAsync(path)).Verdict == FileVerdict.KnownThreat);
            var report = await new FileScanner(FeedFor(payload)).ScanPathAsync(path); Check(report.Detected == 1 && report.Scanned == 1 && report.ArchiveEntries == 1 && !report.Incomplete);
        });
        test("Archive quarantine confirms and backs up the whole container, never an entry path", async () => {
            using var tmp = new Temporary(); var payload = Encoding.UTF8.GetBytes("archive quarantine fixture"); var bytes = Zip(("payload.bin", payload), ("other.txt", [1,2,3]));
            var path = tmp.File("container.zip"); await System.IO.File.WriteAllBytesAsync(path, bytes);
            var scanner = new FileScanner(FeedFor(payload)); var finding = (await scanner.ScanFileDetailedAsync(path)).ArchiveFindings.Single();
            var vault = new QuarantineVault(tmp.File("vault"), new TestProtector());
            await Fails<ArgumentException>(() => vault.QuarantineAsync(finding));
            var confirmed = await scanner.ConfirmQuarantineAsync(finding); Check(confirmed.ArchiveEntry is null && confirmed.Sha256 == finding.ContainerSha256);
            var quarantined = await vault.QuarantineAsync(confirmed); await vault.RestoreAsync(quarantined.Id,tmp.File("restored.zip"));
            Check(!System.IO.File.Exists(path) && System.IO.File.ReadAllBytes(tmp.File("restored.zip")).SequenceEqual(bytes));
        });
        test("Archive quarantine refuses changed containers and revoked contained detections", async () => {
            using var tmp = new Temporary(); var payload = Encoding.UTF8.GetBytes("changed archive fixture"); var path = tmp.File("container.zip");
            var scanner = new FileScanner(FeedFor(payload)); await System.IO.File.WriteAllBytesAsync(path, Zip(("payload", payload)));
            var finding = (await scanner.ScanFileDetailedAsync(path)).ArchiveFindings.Single();
            await Fails<IOException>(() => new FileScanner().ConfirmQuarantineAsync(finding));
            await System.IO.File.WriteAllBytesAsync(path, Zip(("payload", payload), ("added", [1])));
            await Fails<IOException>(() => scanner.ConfirmQuarantineAsync(finding)); Check(System.IO.File.Exists(path));
        });
        test("Nested ZIP detection preserves the outer container identity", async () => {
            using var tmp = new Temporary(); var bytes = Encoding.UTF8.GetBytes("nested harmless fixture"); var path = tmp.File("outer.bin");
            await System.IO.File.WriteAllBytesAsync(path, Zip(("inner.bin", Zip(("payload.bin", bytes)))));
            var result = await new FileScanner(FeedFor(bytes)).ScanFileDetailedAsync(path);
            Check(result.ArchiveEntries == 2 && result.ArchiveFindings.Single().ArchiveEntry == "inner.bin → payload.bin");
        });
        test("ZIP unsafe names and symlinks are skipped without filesystem writes", async () => {
            using var tmp = new Temporary(); var bytes = Zip(("../escape.bin", [1]), ("C:/escape", [2]), ("link", [3]));
            var central = Central(bytes); for (var i = central + 4; i < bytes.Length - 46; i++) if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i, 4)) == 0x02014b50) central = i;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(central + 38, 4), 0xa0000000);
            await System.IO.File.WriteAllBytesAsync(tmp.File("unsafe.zip"), bytes);
            var report = await new FileScanner().ScanPathAsync(tmp.File("unsafe.zip")); Check(report.Skipped == 3 && report.ArchiveEntries == 0 && report.Incomplete);
            Check(Directory.GetFileSystemEntries(tmp.Root).Length == 1);
        });
        test("ZIP encrypted and unsupported methods are explicitly incomplete", async () => {
            using var tmp = new Temporary();
            foreach (var encrypted in new[] { true, false })
            {
                var bytes = Zip(("file.bin", [1,2,3])); var central = Central(bytes);
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(encrypted ? 6 : 8, 2), (ushort)(encrypted ? 1 : 99));
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(central + (encrypted ? 8 : 10), 2), (ushort)(encrypted ? 1 : 99));
                await System.IO.File.WriteAllBytesAsync(tmp.File("unsupported.zip"), bytes);
                var report = await new FileScanner().ScanPathAsync(tmp.File("unsupported.zip")); Check(report.Skipped == 1 && report.Incomplete && report.ArchiveEntries == 0);
            }
        });
        test("ZIP CRC corruption cannot produce a contained exact detection", async () => {
            using var tmp = new Temporary(); var payload = Encoding.UTF8.GetBytes("CRC harmless fixture"); var bytes = Zip(("file.bin", payload));
            bytes[14] ^= 1; bytes[Central(bytes) + 16] ^= 1;
            await System.IO.File.WriteAllBytesAsync(tmp.File("corrupt.zip"), bytes);
            var report = await new FileScanner(FeedFor(payload)).ScanPathAsync(tmp.File("corrupt.zip")); Check(report.Detected == 0 && report.Errors == 1 && report.Incomplete);
        });
        test("ZIP directory preflight rejects forged counts and truncated local headers", async () => {
            using var tmp = new Temporary(); var path = tmp.File("broken.zip");
            var bytes = Zip(("one.bin", [1])); BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(bytes.Length - 22 + 10, 2), 2049);
            await System.IO.File.WriteAllBytesAsync(path, bytes); Check((await new FileScanner().ScanPathAsync(path)).Incomplete);
            bytes = Zip(("one.bin", [1])); bytes[0] = 0; await System.IO.File.WriteAllBytesAsync(path, bytes); Check((await new FileScanner().ScanPathAsync(path)).Skipped == 1);
        });
        test("ZIP entry, expansion, entry-count, ratio and depth budgets remain incomplete", async () => {
            using var tmp = new Temporary(); var path = tmp.File("bounded.zip"); var bytes = Zip(("first", new byte[64]), ("second", new byte[64]));
            foreach (var limits in new[] { new ScanLimits(MaxArchiveEntryBytes:32), new ScanLimits(MaxArchiveExpandedBytes:64), new ScanLimits(MaxArchiveEntries:1) })
            { await System.IO.File.WriteAllBytesAsync(path, bytes); Check((await new FileScanner(limits:limits).ScanPathAsync(path)).Incomplete); }
            using var memory = new MemoryStream(); using (var zip = new ZipArchive(memory, ZipArchiveMode.Create, true)) { using var output = zip.CreateEntry("highly-compressed", CompressionLevel.SmallestSize).Open(); output.Write(new byte[100000]); }
            await System.IO.File.WriteAllBytesAsync(path, memory.ToArray()); var ratio = await new FileScanner().ScanPathAsync(path); Check(ratio.Skipped == 1 && ratio.ArchiveBytesRead == 0);
            await System.IO.File.WriteAllBytesAsync(path, Zip(("nested.zip", Zip(("payload", [1])))));
            var depth = await new FileScanner(limits:new(MaxArchiveDepth:0)).ScanPathAsync(path); Check(depth.ArchiveEntries == 1 && depth.Skipped == 1);
            var memoryLimit = await new FileScanner(limits:new(MaxNestedArchiveBytes:32)).ScanPathAsync(path); Check(memoryLimit.Skipped == 1);
        });
        test("Unsupported archives and malformed ZIPs never imply complete coverage", async () => {
            using var tmp = new Temporary(); await System.IO.File.WriteAllTextAsync(tmp.File("file.rar"), "fixture"); await System.IO.File.WriteAllTextAsync(tmp.File("file.zip"), "broken fixture");
            var report = await new FileScanner().ScanPathAsync(tmp.Root); Check(report.Skipped == 2 && report.Incomplete);
        });
        test("Canceled folder scans retain completed detections and serialize their status", async () => {
            using var tmp = new Temporary(); var payload = Encoding.UTF8.GetBytes("cancellation fixture");
            for (var i = 0; i < 3; i++) await System.IO.File.WriteAllBytesAsync(tmp.File($"file{i}.bin"), payload);
            using var stop = new CancellationTokenSource();
            var report = await new FileScanner(FeedFor(payload)).ScanPathAsync(tmp.Root, new InlineProgress(p => { if (p.Scanned > 0) stop.Cancel(); }), stop.Token);
            Check(report.Canceled && report.Incomplete && report.Detected == 1 && report.Findings.Count == 1);
            await ScanReports.SaveAsync(report, tmp.File("report.json")); var loaded = ScanReports.Load(tmp.File("report.json")); Check(loaded.Canceled && loaded.Findings.Single().Sha256 == report.Findings.Single().Sha256);
        });
        test("Scan report history is bounded and export replaces through unique staging", async () => {
            using var tmp = new Temporary(); await System.IO.File.WriteAllTextAsync(tmp.File("file.bin"), "ordinary"); var report = await new FileScanner().ScanPathAsync(tmp.File("file.bin"));
            for (var i = 0; i < 32; i++) await ScanReports.SaveHistoryAsync(report, tmp.File("reports"));
            Check(ScanReports.List(tmp.File("reports")).Count == 30 && Directory.GetFiles(tmp.File("reports")).Length == 30);
            await ScanReports.SaveHistoryAsync(report with { Canceled=true },tmp.File("reports"));
            Check(ScanReports.Latest(tmp.File("reports"))!.Canceled && Directory.GetFiles(tmp.File("reports")).Length == 30);
            await ScanReports.SaveAsync(report, tmp.File("export.json")); await ScanReports.SaveAsync(report with { Canceled=true }, tmp.File("export.json"));
            Check(ScanReports.Load(tmp.File("export.json")).Canceled && !Directory.EnumerateFiles(tmp.Root, "*.tmp").Any());
        });
        test("Report import rejects malformed counts, missing hashes and oversized files", async () => {
            using var tmp = new Temporary(); var now = DateTimeOffset.UtcNow;
            var report = new ScanReport(now, TimeSpan.Zero, 1, 1, 0, 0, 0, false, false, 1, 1, false, [new(tmp.File("fixture"),FileVerdict.KnownThreat,"fixture")]);
            await Fails<InvalidDataException>(() => ScanReports.SaveAsync(report,tmp.File("bad.json")));
            await Fails<InvalidDataException>(() => ScanReports.SaveAsync(report with { Scanned=-1 },tmp.File("bad.json")));
            using (var output = new FileStream(tmp.File("huge.json"), FileMode.CreateNew)) output.SetLength(ScanReports.MaxReportBytes + 1);
            await Fails<InvalidDataException>(() => Task.Run(() => ScanReports.Load(tmp.File("huge.json"))));
        });
        test("Output path validation rejects relative paths and Windows alternate streams before creation", async () => {
            await Fails<ArgumentException>(() => Task.Run(() => FileSafety.NormalizeLocalPath("relative.json")));
            if (OperatingSystem.IsWindows())
            {
                foreach (var path in new[] { @"C:\reports\file.json:stream", @"\\server\share\report.json", @"\\?\C:\reports\report.json" })
                    await Fails<IOException>(() => Task.Run(() => FileSafety.NormalizeLocalPath(path)));
            }
        });
        test("v0.2 reports load with safe defaults for added v0.3 fields", async () => {
            using var tmp = new Temporary();
            var report = new ScanReport(DateTimeOffset.UtcNow, TimeSpan.Zero, 1, 0, 0, 0, 0, false, false, 1, 0, false, []);
            var json = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(report,ScanReports.Json))!.AsObject();
            json.Remove("canceled"); json.Remove("archiveEntries"); json.Remove("archiveBytesRead");
            await System.IO.File.WriteAllTextAsync(tmp.File("legacy.json"),json.ToJsonString());
            var loaded = ScanReports.Load(tmp.File("legacy.json")); Check(!loaded.Canceled && loaded.ArchiveEntries == 0 && loaded.ArchiveBytesRead == 0);
        });
        test("Monitor excludes own storage before reads and disposal is idempotent", async () => {
            using var tmp = new Temporary(); var excluded = tmp.File("excluded"); Directory.CreateDirectory(excluded);
            var calls = 0; var monitor = new FolderMonitor(tmp.Root, () => { Interlocked.Increment(ref calls); return new(); }, _ => {}, _ => {}, [excluded]);
            await System.IO.File.WriteAllTextAsync(Path.Combine(excluded,"private.bin"), "fixture"); await Task.Delay(800);
            Check(calls == 0 && monitor.ObservedChanges == 0);
            await monitor.DisposeAsync(); await monitor.DisposeAsync(); Check(!monitor.IsRunning && monitor.PendingFiles == 0);
            Check(!FolderMonitor.IsWithin(tmp.File("excluded-other/file"), excluded));
        });
        test("Monitor rescans rewrites arriving during the previous scan callback", async () => {
            using var tmp = new Temporary(); var first = Encoding.UTF8.GetBytes("first harmless monitor fixture"); var second = Encoding.UTF8.GetBytes("second harmless monitor fixture");
            var feed = FeedFor(first, second); var path = tmp.File("rewrite.bin"); var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var rewrite = 0;
            await using var monitor = new FolderMonitor(tmp.Root, () => new FileScanner(feed), finding => {
                if (finding.Sha256 == Convert.ToHexString(SHA256.HashData(second))) done.TrySetResult();
                else if (Interlocked.Exchange(ref rewrite,1) == 0) { System.IO.File.WriteAllBytes(path, second); Thread.Sleep(200); }
            }, problem => done.TrySetException(new Exception(problem)));
            await System.IO.File.WriteAllBytesAsync(path, first); await done.Task.WaitAsync(TimeSpan.FromSeconds(8)); Check(monitor.CompletedScans >= 2);
        });
        test("Schedule status uses current-user task and preserves Windows result codes", async () => {
            var runner = new FakeRunner(_ => "{\"Exists\":true,\"State\":\"Ready\",\"LastResult\":2}");
            var status = await new ScanScheduler(runner).StatusAsync(); Check(status.Exists && status.LastResult == 2 && runner.LastScript.Contains("Get-ScheduledTaskInfo") && runner.LastScript.Contains("User.Value"));
        });
    }
}
