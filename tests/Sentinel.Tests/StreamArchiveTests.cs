using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Core.Protection;

internal static class StreamArchiveTests
{
    private static void Check(bool value, string reason = "Streaming archive assertion failed") { if (!value) throw new Exception(reason); }
    private sealed class Temporary : IDisposable
    {
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory, "stream-archive-" + Guid.NewGuid().ToString("N"));
        public Temporary() => Directory.CreateDirectory(Root);
        public string PathFor(string name) => Path.Combine(Root, name);
        public void Dispose() => Directory.Delete(Root, true);
    }
    private static byte[] Tar(TarEntryFormat format, params (string Name, byte[] Data)[] files)
    {
        using var output = new MemoryStream();
        using (var writer = new TarWriter(output, format, leaveOpen: true))
            foreach (var (name, bytes) in files)
            {
                TarEntry entry = format switch {
                    TarEntryFormat.V7 => new V7TarEntry(TarEntryType.V7RegularFile, name),
                    TarEntryFormat.Ustar => new UstarTarEntry(TarEntryType.RegularFile, name),
                    TarEntryFormat.Pax => new PaxTarEntry(TarEntryType.RegularFile, name),
                    _ => throw new ArgumentOutOfRangeException(nameof(format))
                };
                using var input = new MemoryStream(bytes); entry.DataStream = input; writer.WriteEntry(entry);
            }
        return output.ToArray();
    }
    private static byte[] Gzip(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var writer = new GZipStream(output, CompressionLevel.NoCompression, leaveOpen: true)) writer.Write(bytes);
        return output.ToArray();
    }
    private static byte[] Zip(string name, byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        { using var entry = zip.CreateEntry(name, CompressionLevel.NoCompression).Open(); entry.Write(bytes); }
        return output.ToArray();
    }
    private static VerifiedFeed Feed(byte[] fixture)
    {
        using var key = RSA.Create(3072); var now = DateTimeOffset.UtcNow;
        var data = JsonSerializer.SerializeToUtf8Bytes(new FeedPayload(1, 1, now, now.AddDays(1),
            [new(Convert.ToHexString(SHA256.HashData(fixture)), "Harmless streaming fixture", "Unit tests")]), FeedVerifier.Json);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(data),
            Convert.ToBase64String(key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))), FeedVerifier.Json);
        return FeedVerifier.Verify(envelope, key.ExportSubjectPublicKeyInfoPem(), now);
    }
    private static void Checksum(byte[] tar)
    {
        Array.Fill(tar, (byte)' ', 148, 8); var sum = tar.AsSpan(0, 512).ToArray().Sum(b => (int)b);
        Encoding.ASCII.GetBytes(Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ").CopyTo(tar, 148);
    }
    public static void Register(Action<string, Func<Task>> test)
    {
        test("TAR V7/ustar and magic detection scan regular entries without extraction", async () => {
            using var tmp = new Temporary(); var fixture = "harmless TAR exact fixture"u8.ToArray(); var scanner = new FileScanner(Feed(fixture));
            foreach (var format in new[] { TarEntryFormat.V7, TarEntryFormat.Ustar })
            {
                var path = tmp.PathFor(format == TarEntryFormat.V7 ? "sample.tar" : "sample.bin");
                await File.WriteAllBytesAsync(path, Tar(format, ("folder/payload.bin", fixture), ("ordinary.txt", [1, 2, 3])));
                var report = await scanner.ScanPathAsync(path);
                Check(!report.Incomplete && report.Detected == 1 && report.ArchiveEntries == 2 && report.ArchiveBytesRead == fixture.Length + 3);
                var finding = report.Findings.Single(); Check(finding.Path == path && finding.ArchiveEntry == "folder/payload.bin" && finding.ContainerSha256?.Length == 64);
            }
            Check(Directory.GetFileSystemEntries(tmp.Root).Length == 2);
        });
        test("GZIP and mixed ZIP/TAR/GZIP trees preserve the outer identity and shared budgets", async () => {
            using var tmp = new Temporary(); var fixture = "harmless compressed fixture"u8.ToArray(); var scanner = new FileScanner(Feed(fixture));
            var cases = new[] {
                ("file.bin.gz", Gzip(fixture), "file.bin", 1),
                ("download.tgz", Gzip(Tar(TarEntryFormat.Ustar, ("folder/payload.bin", fixture))), "download.tar → folder/payload.bin", 2),
                ("download.tar", Tar(TarEntryFormat.Ustar, ("nested.zip", Zip("payload.bin.gz", Gzip(fixture)))), "nested.zip → payload.bin.gz → payload.bin", 3)
            };
            foreach (var (file, data, entry, count) in cases)
            {
                var path = tmp.PathFor(file); await File.WriteAllBytesAsync(path, data);
                var result = await scanner.ScanFileDetailedAsync(path);
                Check(result.ArchiveEntries == count && result.ArchiveFindings.Count == 1, file + ": " + JsonSerializer.Serialize(result.ArchiveFindings));
                Check(result.ArchiveFindings.Single() is { Verdict: FileVerdict.KnownThreat } finding && finding.ArchiveEntry == entry && finding.ContainerSha256 == result.File.Sha256);
            }
            var limited = await new FileScanner(limits: new(MaxArchiveEntries: 1)).ScanPathAsync(tmp.PathFor("download.tgz"));
            Check(limited.Incomplete && limited.ArchiveEntries == 1 && limited.Skipped == 1);
            Check(Directory.GetFileSystemEntries(tmp.Root).Length == cases.Length);
        });
        test("TAR links, unsafe names, special files and PAX extensions stay incomplete", async () => {
            using var tmp = new Temporary(); var fixture = "do not interpret as a regular file"u8.ToArray(); var scanner = new FileScanner(Feed(fixture)); var path = tmp.PathFor("unsafe.tar");
            foreach (var type in new byte[] { (byte)'1', (byte)'2', (byte)'3', (byte)'6', (byte)'x', (byte)'g', (byte)'L', (byte)'S' })
            {
                var data = Tar(TarEntryFormat.Ustar, ("entry", fixture)); data[156] = type; Checksum(data);
                await File.WriteAllBytesAsync(path, data); var report = await scanner.ScanPathAsync(path);
                Check(report.Incomplete && report.Detected == 0 && report.Skipped > 0);
            }
            foreach (var name in new[] { "../escape.bin", "C:/escape", "folder\\escape" })
            {
                await File.WriteAllBytesAsync(path, Tar(TarEntryFormat.Ustar, (name, fixture)));
                var report = await scanner.ScanPathAsync(path); Check(report.Incomplete && report.Detected == 0);
            }
            await File.WriteAllBytesAsync(path, Tar(TarEntryFormat.Pax, ("ordinary", fixture)));
            Check((await scanner.ScanPathAsync(path)).Incomplete && Directory.GetFileSystemEntries(tmp.Root).Length == 1);
        });
        test("TAR corrupt headers, forged sizes, truncated content and hidden trailers are rejected", async () => {
            using var tmp = new Temporary(); var fixture = "header validation fixture"u8.ToArray(); var scanner = new FileScanner(Feed(fixture)); var path = tmp.PathFor("corrupt.tar");
            var original = Tar(TarEntryFormat.Ustar, ("entry", fixture));
            var badChecksum = original.ToArray(); badChecksum[0] ^= 1;
            var badSize = original.ToArray(); badSize[124] = 0x80; Checksum(badSize);
            var wrongSize = original.ToArray(); Encoding.ASCII.GetBytes("00000077777\0").CopyTo(wrongSize, 124); Checksum(wrongSize);
            foreach (var data in new[] { badChecksum, badSize, wrongSize, original[..520] })
            {
                await File.WriteAllBytesAsync(path, data); var report = await scanner.ScanPathAsync(path);
                Check(report.Incomplete && report.Detected == 0, "Invalid TAR accepted: " + JsonSerializer.Serialize(report));
            }
            foreach (var data in new[] { original[..1024], original.Concat(original).ToArray(), original.Concat(new byte[] { 1 }).ToArray() })
            {
                await File.WriteAllBytesAsync(path, data); Check((await scanner.ScanPathAsync(path)).Incomplete);
            }
        });
        test("GZIP corruption, truncation, oversized headers, unsafe names and trailing data cannot yield exact detections", async () => {
            using var tmp = new Temporary(); var fixture = "gzip integrity fixture"u8.ToArray(); var scanner = new FileScanner(Feed(fixture)); var path = tmp.PathFor("payload.gz");
            var original = Gzip(fixture);
            var badCrc = original.ToArray(); badCrc[^8] ^= 1;
            var badSize = original.ToArray(); badSize[^4] ^= 1;
            var badFlags = original.ToArray(); badFlags[3] |= 0x80;
            var unsafeName = original[..10].Concat("../escape.bin\0"u8.ToArray()).Concat(original[10..]).ToArray(); unsafeName[3] |= 8;
            var hugeExtra = original[..10].Concat(new byte[] { 0xff, 0xff }).Concat(original[10..]).ToArray(); hugeExtra[3] |= 4;
            var fakeTrailer = original.Concat("hidden ignored bytes"u8.ToArray()).Concat(original[^8..]).ToArray();
            foreach (var data in new[] { badCrc, badSize, badFlags, unsafeName, hugeExtra, original[..^1], original[..^8], fakeTrailer, original.Concat(original).ToArray() })
            {
                await File.WriteAllBytesAsync(path, data); var report = await scanner.ScanPathAsync(path);
                Check(report.Incomplete && report.Detected == 0, "Invalid GZIP accepted: " + JsonSerializer.Serialize(report));
            }
            // Empty payloads and crafted all-zero trailers still require input EOF.
            await File.WriteAllBytesAsync(path, Gzip([]).Concat(new byte[] { 0 }).ToArray());
            Check((await scanner.ScanPathAsync(path)).Incomplete);
        });
        test("GZIP optional names preserve script review without exposing unsafe paths", async () => {
            using var tmp = new Temporary(); var path = tmp.PathFor("renamed.bin");
            var data = Gzip("FromBase64String Invoke-Expression"u8.ToArray());
            data = data[..10].Concat("original.ps1\0"u8.ToArray()).Concat(data[10..]).ToArray(); data[3] |= 8;
            await File.WriteAllBytesAsync(path, data); var report = await new FileScanner().ScanPathAsync(path);
            Check(!report.Incomplete && report.Review == 1 && report.Findings.Single().ArchiveEntry == "original.ps1");
        });
        test("Every GZIP truncation and varied trailing input remains incomplete", async () => {
            using var tmp = new Temporary(); var path = tmp.PathFor("bounded.gz"); var data = Gzip("harmless truncation fixture"u8.ToArray());
            for (var length = 0; length < data.Length; length++)
            {
                await File.WriteAllBytesAsync(path, data.AsMemory(0, length).ToArray());
                var report = await new FileScanner().ScanPathAsync(path); Check(report.Incomplete && report.Detected == 0, "Accepted truncation at " + length);
            }
            foreach (var empty in new[] { false, true })
            {
                var source = empty ? Gzip([]) : data;
                foreach (var junk in new byte[] { 0, 1, 0x1f, 0xff })
                    for (var count = 1; count <= 12; count++)
                    {
                        await File.WriteAllBytesAsync(path, source.Concat(Enumerable.Repeat(junk, count)).ToArray());
                        Check((await new FileScanner().ScanPathAsync(path)).Incomplete, $"Accepted trailing bytes: empty={empty} byte={junk} count={count}");
                    }
            }
        });
        test("Bounded deterministic archive mutation corpus never extracts or exceeds scan budgets", async () => {
            using var tmp = new Temporary(); var random = new Random(111); var fixture = "harmless mutation fixture"u8.ToArray();
            var cases = new[] { ("sample.zip", Zip("entry", fixture)), ("sample.tar", Tar(TarEntryFormat.Ustar, ("entry", fixture))), ("sample.gz", Gzip(fixture)) };
            var limits = new ScanLimits(MaxArchiveEntryBytes: 4096, MaxArchiveExpandedBytes: 8192, MaxNestedArchiveBytes: 4096, MaxArchiveEntries: 8);
            foreach (var (file, original) in cases)
                for (var i = 0; i < 200; i++)
                {
                    var data = original.ToArray();
                    for (var j = 0; j < 1 + i % 4; j++) data[random.Next(data.Length)] ^= (byte)random.Next(1, 256);
                    var path = tmp.PathFor(file); await File.WriteAllBytesAsync(path, data);
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    var result = await new FileScanner(limits: limits).ScanFileDetailedAsync(path, deadline.Token);
                    Check(!result.Canceled && result.ArchiveEntries <= 8 && result.ArchiveBytesRead <= 8193 && result.ArchiveFindings.Count <= 16);
                }
            Check(Directory.GetFileSystemEntries(tmp.Root).Length == cases.Length);
        });
        test("TAR/GZIP limits preserve entry hashes while skipping unsupported nested contents", async () => {
            using var tmp = new Temporary(); var path = tmp.PathFor("bounded.tar");
            await File.WriteAllBytesAsync(path, Tar(TarEntryFormat.Ustar, ("one", new byte[64]), ("two", new byte[64])));
            foreach (var limits in new[] { new ScanLimits(MaxArchiveEntryBytes: 32), new ScanLimits(MaxArchiveExpandedBytes: 64), new ScanLimits(MaxArchiveEntries: 1) })
                Check((await new FileScanner(limits: limits).ScanPathAsync(path)).Incomplete);
            await File.WriteAllBytesAsync(path, Tar(TarEntryFormat.Ustar, ("inner.gz", Gzip([1, 2, 3]))));
            var depth = await new FileScanner(limits: new(MaxArchiveDepth: 0)).ScanPathAsync(path); Check(depth.Incomplete && depth.ArchiveEntries == 1);
            var memory = await new FileScanner(limits: new(MaxNestedArchiveBytes: 1)).ScanPathAsync(path); Check(memory.Incomplete && memory.ArchiveEntries == 1);
            var gzipPath = tmp.PathFor("ratio.gz"); using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, true)) gzip.Write(new byte[100000]);
            await File.WriteAllBytesAsync(gzipPath, output.ToArray()); var ratio = await new FileScanner().ScanPathAsync(gzipPath); Check(ratio.Incomplete && ratio.ArchiveBytesRead == 0);
            await File.WriteAllBytesAsync(gzipPath, Gzip(new byte[100]));
            Check((await new FileScanner(limits: new(MaxArchiveEntryBytes: 32)).ScanPathAsync(gzipPath)).Incomplete);
        });
        test("TAR/GZIP quarantine confirmation revalidates the complete container and current hash set", async () => {
            using var tmp = new Temporary(); var fixture = "quarantine container fixture"u8.ToArray(); var scanner = new FileScanner(Feed(fixture));
            foreach (var (file, data) in new[] { ("item.tar", Tar(TarEntryFormat.Ustar, ("payload", fixture))), ("item.gz", Gzip(fixture)) })
            {
                var path = tmp.PathFor(file); await File.WriteAllBytesAsync(path, data);
                var result = await scanner.ScanFileDetailedAsync(path); var finding = result.ArchiveFindings.Single();
                var confirmed = await scanner.ConfirmQuarantineAsync(finding); Check(confirmed.ArchiveEntry is null && confirmed.Sha256 == result.File.Sha256);
                try { await new FileScanner().ConfirmQuarantineAsync(finding); throw new Exception("Revoked match accepted"); } catch (IOException) { }
                await File.WriteAllBytesAsync(path, data.Concat(new byte[] { 1 }).ToArray());
                try { await scanner.ConfirmQuarantineAsync(finding); throw new Exception("Changed container accepted"); } catch (IOException) { }
                Check(File.Exists(path));
            }
        });
    }
}
