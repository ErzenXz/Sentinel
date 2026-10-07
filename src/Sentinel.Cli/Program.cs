using System.Diagnostics;
using System.Text.Json;
using Sentinel.Core.Protection;
using Sentinel.Core;

string? Option(string name) { var at = Array.IndexOf(args, name); return at >= 0 && at + 1 < args.Length ? args[at + 1] : null; }
try
{
    if (args.Length == 0 || args[0] is "help" or "--help")
    {
        Console.WriteLine("""
            Sentinel independent scanner 0.7
            scan <absolute path> --feed <signed feed.json> --key <public.pem> [--report <report.json>]
            scan <absolute path> --profile <Sentinel local-data folder> [--report <report.json>]
            Add --low-impact to either scan command for brief cooperative yields between chunks/files.
            update --server <base URL> --key <public.pem> --state <local feed-cache folder>
            inspect-feed <feed.json> --key <public.pem>
            demo-test <new file path>
            models --provider <Ollama|OpenAiCompatible|Anthropic> --endpoint <base URL>
            network-snapshot
            network-review <local snapshot.json>
            jev-review <categories/counts evidence.json> --provider <TypeSafe|VercelGateway> [--endpoint <base URL>] [--model <ID>]
            network-benchmark [--iterations <1..10000>]
            Jev uses SENTINEL_JEV_KEY in the environment, makes one opt-in provider request, and changes no firewall rules.
            Network snapshots include private local paths/addresses; Jev evidence uses fixed categories/counts only.
            Remote model credentials come from SENTINEL_AI_KEY, never command-line arguments.
            Scans are offline. No-known-match does not mean safe. ZIP contents are scanned within strict budgets, without extraction. Unsupported/encrypted contents are incomplete.
            Exit codes: 0 no known match, 1 command/update failure, 2 exact detections, 3 incomplete scan, 4 review findings.
            """); return 0;
    }
    if (OperatingSystem.IsWindows()) { try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch (System.ComponentModel.Win32Exception) { } }
    if (args[0] == "network-benchmark") { Console.WriteLine(NetworkBenchmark.Run(Option("--iterations"))); return 0; }
    if (args[0] == "network-snapshot")
    {
        var current = await NetworkCapture.ReadAsync(new PowerShellRunner());
        Console.WriteLine(JsonSerializer.Serialize(current, NetworkReview.Json)); return current.Truncated || current.ConnectionError is not null || current.ProfileError is not null || current.ProcessError is not null ? 3 : 0;
    }
    if (args[0] is "network-review" or "jev-review")
    {
        if (args.Length < 2) throw new ArgumentException("Choose an absolute local JSON input path.");
        var input = FileSafety.NormalizeRegularPath(args[1]);
        if (new FileInfo(input).Length > (args[0] == "network-review" ? 4 * 1024 * 1024 : 16 * 1024)) throw new InvalidDataException("Review input exceeded its size limit.");
        var bytes = await File.ReadAllBytesAsync(input);
        if (args[0] == "network-review")
        {
            var current = JsonSerializer.Deserialize<NetworkSnapshot>(bytes, NetworkReview.Json) ?? throw new InvalidDataException("Missing network snapshot.");
            var apps = NetworkReview.Assess(current);
            var policy = NetworkReview.GlobalDecision(current);
            Console.WriteLine(JsonSerializer.Serialize(new { current.CapturedAt, current.Truncated, historical = !NetworkReview.IsFresh(current,DateTimeOffset.UtcNow), policy, applications = apps }, NetworkReview.Json));
            return policy.Priority > ReviewPriority.Routine || apps.Any(x => x.Decision.Priority > ReviewPriority.Routine) || !NetworkReview.IsFresh(current,DateTimeOffset.UtcNow) ? 4 : 0;
        }
        if (!Enum.TryParse<DecisionProvider>(Option("--provider"),ignoreCase:true,out var provider) || !Enum.IsDefined(provider)) throw new ArgumentException("Choose --provider TypeSafe or VercelGateway.");
        var preset = DecisionSettings.Preset(provider);
        var settings = preset with { Endpoint = Option("--endpoint") ?? preset.Endpoint, Model = Option("--model") ?? preset.Model };
        var evidence = JsonSerializer.Deserialize<FirewallEvidence>(bytes,NetworkReview.Json) ?? throw new InvalidDataException("Missing firewall evidence.");
        using var reviewStop = new CancellationTokenSource(); Console.CancelKeyPress += (_,e) => { e.Cancel=true; reviewStop.Cancel(); };
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(6) };
        var result = await new DecisionReviewService(new JevClient(http)).ReviewAsync(settings, Environment.GetEnvironmentVariable("SENTINEL_JEV_KEY") ?? "", evidence, reviewStop.Token);
        Console.WriteLine(JsonSerializer.Serialize(result,NetworkReview.Json)); return result.Priority > ReviewPriority.Routine ? 4 : 0;
    }
    if (args[0] == "demo-test")
    {
        if (args.Length < 2) throw new ArgumentException("Choose a new test file path.");
        using var output = new FileStream(args[1],FileMode.CreateNew);using var writer = new StreamWriter(output);writer.Write("Sentinel harmless detection fixture v1\n");
        Console.WriteLine("Harmless demonstration fixture created; detection requires your server's demo feed.");return 0;
    }
    if (args[0] == "models")
    {
        if (!Enum.TryParse<ProviderKind>(Option("--provider"),ignoreCase:true,out var provider)) throw new ArgumentException("Choose --provider Ollama, OpenAiCompatible, or Anthropic.");
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        var result = await new AiModelDiscovery(http).ListAsync(provider,Option("--endpoint") ?? throw new ArgumentException("Missing --endpoint."),Environment.GetEnvironmentVariable("SENTINEL_AI_KEY") ?? "");
        Console.WriteLine(JsonSerializer.Serialize(result,FeedVerifier.Json));return 0;
    }
    if (args[0] == "update")
    {
        var settings = new ProtectionSettings(Option("--server") ?? throw new ArgumentException("Missing --server."), File.ReadAllText(Option("--key") ?? throw new ArgumentException("Missing --key.")));
        var repository = new FeedRepository(Option("--state") ?? throw new ArgumentException("Missing --state."));
        repository.Load(settings.PublicKeyPem);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(2) };
        var feed = await repository.UpdateAsync(http, settings);Console.WriteLine(JsonSerializer.Serialize(new { sequence = feed.Payload.Sequence, hashes = feed.Hashes.Count, expires = feed.Payload.ExpiresAt },FeedVerifier.Json));return 0;
    }
    if (args.Length < 2) throw new ArgumentException("Missing file/folder path.");
    VerifiedFeed? catalog;
    if (Option("--profile") is { } profile)
    {
        profile = Path.GetFullPath(profile);
        var settingsPath = Path.Combine(profile,"protection.json");
        var settings = File.Exists(settingsPath) ? JsonSerializer.Deserialize<ProtectionSettings>(File.ReadAllBytes(FileSafety.NormalizeRegularPath(settingsPath))) ?? new() : new();
        var repository = new FeedRepository(Path.Combine(profile,"engine"));
        if (!string.IsNullOrWhiteSpace(settings.PublicKeyPem)) repository.Load(settings.PublicKeyPem);
        catalog = repository.Current;
    }
    else if (Option("--feed") is { } feedPath)
        catalog=FeedVerifier.Verify(File.ReadAllBytes(feedPath),File.ReadAllText(Option("--key") ?? throw new ArgumentException("Missing --key.")),DateTimeOffset.UtcNow,allowExpired:true);
    else if (args[0] == "inspect-feed")
        catalog=FeedVerifier.Verify(File.ReadAllBytes(args[1]),File.ReadAllText(Option("--key") ?? throw new ArgumentException("Missing --key.")),DateTimeOffset.UtcNow,allowExpired:true);
    else catalog=null;
    if (args[0] == "inspect-feed") { if (catalog is null) throw new InvalidDataException("No verified feed.");Console.WriteLine(JsonSerializer.Serialize(new { catalog.Payload.Sequence, hashes=catalog.Hashes.Count, expired=catalog.IsExpired(DateTimeOffset.UtcNow) },FeedVerifier.Json));return 0; }
    if (args[0] != "scan") throw new ArgumentException("Unknown command; use --help.");
    using var stop=new CancellationTokenSource();Console.CancelKeyPress+=(_,e)=>{e.Cancel=true;stop.Cancel();};
    var control = new ScanControl(args.Contains("--low-impact", StringComparer.Ordinal) ? ScanMode.LowImpact : ScanMode.Balanced);
    var report=await new FileScanner(catalog, control:control).ScanPathAsync(Path.GetFullPath(args[1]),token:stop.Token);
    if (Option("--report") is { } reportPath) await ScanReports.SaveAsync(report,reportPath);
    if (Option("--profile") is { } historyProfile) await ScanReports.SaveHistoryAsync(report,Path.Combine(Path.GetFullPath(historyProfile),"reports"));
    await using (var output = Console.OpenStandardOutput())
    {
        await JsonSerializer.SerializeAsync(output,report,ScanReports.Json);
        await output.WriteAsync("\n"u8.ToArray());
    }
    return report.Detected>0 ? 2 : report.Incomplete ? 3 : report.Review>0 ? 4 : 0;
}
catch (OperationCanceledException) { Console.Error.WriteLine("Scan canceled; no files were modified."); return 3; }
catch (Exception ex) { Console.Error.WriteLine(ex.Message);return 1; }
