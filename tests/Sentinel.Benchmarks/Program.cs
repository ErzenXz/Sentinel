using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Sentinel.Core.Protection;

int Option(string name, int fallback, int min, int max)
{
    var at = Array.IndexOf(args, name);
    if (at < 0) return fallback;
    if (at + 1 >= args.Length || !int.TryParse(args[at + 1], out var value) || value < min || value > max)
        throw new ArgumentException($"{name} must be {min}..{max}.");
    return value;
}

var files = Option("--files", 2500, 1, 20_000);
var iterations = Option("--iterations", 5, 1, 20);
var feedIndicators = Option("--feed-indicators", 10_000, 1, 100_000);
var root = Path.Combine(AppContext.BaseDirectory, "sentinel-benchmark-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var folder = Path.Combine(root, "files"); Directory.CreateDirectory(folder);
    var content = new byte[8192]; Array.Fill(content, (byte)'a');
    for (var i = 0; i < files; i++) await File.WriteAllBytesAsync(Path.Combine(folder, $"fixture-{i:D5}.txt"), content);
    var report = new ScanReport(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1), 2000, 0, 2000, 0, 0, false, false,
        0, 0, true, Enumerable.Range(0, 2000).Select(i => new FileFinding(Path.Combine(folder, $"report-{i:D4}.ps1"),
            FileVerdict.NeedsReview, new string('x', 4000), Bytes: 16)).ToArray());
    var reportPath = Path.Combine(root, "report.json");
    var beforeCatalog = GC.GetTotalMemory(forceFullCollection: true);
    var catalog = BuiltInCatalog.Current;
    var catalogRetainedManagedBytes = GC.GetTotalMemory(forceFullCollection: true) - beforeCatalog;
    var scanner = new FileScanner(catalog);
    await scanner.ScanPathAsync(folder); await ScanReports.SaveAsync(report, reportPath); _ = ScanReports.Load(reportPath);

    async Task<object> Measure(string workload, Func<Task> work)
    {
        var times = new double[iterations]; var allocations = new long[iterations];
        for (var i = 0; i < iterations; i++)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            var before = GC.GetTotalAllocatedBytes(precise: true);
            var start = Stopwatch.GetTimestamp(); await work();
            times[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            allocations[i] = GC.GetTotalAllocatedBytes(precise: true) - before;
        }
        Array.Sort(times); Array.Sort(allocations);
        return new { workload, medianMilliseconds = times[iterations / 2], allocatedBytesMedian = allocations[iterations / 2] };
    }

    var scan = await Measure("wide-folder-8192-byte-files", async () => {
        var result = await scanner.ScanPathAsync(folder);
        if (result.Scanned != files || result.Incomplete || result.Detected != 0) throw new InvalidDataException("Benchmark coverage mismatch.");
    });
    var reports = await Measure("save-and-load-2000-long-evidence-findings", async () => {
        await ScanReports.SaveAsync(report, reportPath);
        if (ScanReports.Load(reportPath).Findings.Count != 2000) throw new InvalidDataException("Report round-trip mismatch.");
    });
    // Signed harmless metadata, generated once outside the measured refreshes.
    using var signer = RSA.Create(3072);
    var issued = DateTimeOffset.UtcNow;
    var feedData = JsonSerializer.SerializeToUtf8Bytes(new FeedPayload(1, 1, issued, issued.AddDays(7),
        Enumerable.Range(0, feedIndicators).Select(i => new HashIndicator(i.ToString("X64"), "Harmless benchmark indicator", "Local synthetic fixture")).ToArray()), FeedVerifier.Json);
    var envelope = JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(feedData),
        Convert.ToBase64String(signer.SignData(feedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))), FeedVerifier.Json);
    using var feedHttp = new HttpClient(new FixtureFeedHandler(envelope));
    var repository = new FeedRepository(Path.Combine(root, "feed"));
    var settings = new ProtectionSettings("https://example.com/", signer.ExportSubjectPublicKeyInfoPem());
    await repository.UpdateAsync(feedHttp, settings);
    var feedRefresh = await Measure("refresh-unchanged-signed-indicators", async () => {
        var refreshed = await repository.UpdateAsync(feedHttp, settings);
        if (refreshed.Hashes.Count != feedIndicators || refreshed.Payload.Sequence != 1) throw new InvalidDataException("Feed refresh mismatch.");
    });
    Console.WriteLine(JsonSerializer.Serialize(new {
        schemaVersion = 1,
        description = "Warmed synthetic offline core workloads. Process-wide managed allocations; excludes UI, OS protection, AI and startup. Not Windows working-set or throughput certification.",
        os = RuntimeInformation.OSDescription, architecture = RuntimeInformation.ProcessArchitecture.ToString(),
        dotnet = Environment.Version.ToString(), files, iterations, fileBytes = content.Length,
        reportBytes = new FileInfo(reportPath).Length,
        feedIndicators, feedEnvelopeBytes = envelope.Length,
        catalogIndicators = catalog.Hashes.Count, catalogRetainedManagedBytes,
        catalogMeasurement = "Managed heap delta around the first catalog load with forced collection, including serializer metadata; not process working set.",
        results = new[] { scan, reports, feedRefresh }
    }, new JsonSerializerOptions { WriteIndented = true }));
}
finally { Directory.Delete(root, recursive: true); }

sealed class FixtureFeedHandler(byte[] envelope) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(envelope) });
    }
}
