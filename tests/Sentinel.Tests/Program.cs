using System.Net;
using System.Text;
using System.Text.Json;
using Sentinel.Core;

var tests = new List<(string, Func<Task>)>();
void Test(string name, Func<Task> run) => tests.Add((name, run));
void Assert(bool value, string message = "Assertion failed") { if (!value) throw new Exception(message); }
void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
async Task ThrowsAsync<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
var healthyDefender = new DefenderStatus(true, true, true, true, "Normal", 0, "1.2.3", null);
var profiles = new[] { new FirewallProfile("Domain", true, "Block", "Allow"), new FirewallProfile("Private", true, "Block", "Allow"), new FirewallProfile("Public", true, "Block", "Allow") };
var healthy = new SecuritySnapshot(healthyDefender, profiles, [], null, null, null);
Test("Status fails closed for missing or disabled protection", () => {
    Assert(healthy.IsHealthy);
    Assert(!(healthy with { Defender = null }).IsHealthy);
    Assert(!(healthy with { Defender = healthyDefender with { AMRunningMode = "Passive" } }).IsHealthy);
    Assert(!(healthy with { Defender = healthyDefender with { RealTimeProtectionEnabled = false } }).IsHealthy);
    Assert(!(healthy with { Defender = healthyDefender with { AntivirusSignatureAge = 4 } }).IsHealthy);
    Assert(!(healthy with { Profiles = profiles[..2] }).IsHealthy);
    Assert(!(healthy with { ThreatError = "Access denied" }).IsHealthy);
    Assert(!(healthy with { Threats = [new("1", "test", true, 5)] }).IsHealthy);
    return Task.CompletedTask;
});
Test("PowerShell arguments cannot become commands", () => {
    const string malicious = "C:\\app'; Invoke-Expression 'danger'; #\n$(Get-Content secret)";
    var encoded = PowerShellRunner.Encode("Write-Output $p.Path", new { Path = malicious });
    var script = Encoding.Unicode.GetString(Convert.FromBase64String(encoded));
    Assert(!script.Contains(malicious));
    var start = script.IndexOf("FromBase64String('", StringComparison.Ordinal) + "FromBase64String('".Length;
    var end = script.IndexOf("')", start, StringComparison.Ordinal);
    using var data = JsonDocument.Parse(Convert.FromBase64String(script[start..end]));
    Assert(data.RootElement.GetProperty("Path").GetString() == malicious);
    return Task.CompletedTask;
});
Test("Remote HTTP and credential-bearing endpoints rejected", () => {
    foreach (var url in new[] { "http://example.com/", "file:///tmp", "https://key@example.com/", "https://example.com/?token=x", "https://example.com/#x" }) Throws<ArgumentException>(() => AiClient.ValidateEndpoint(url));
    Assert(AiClient.ValidateEndpoint("http://127.0.0.1:11434").IsLoopback);
    Assert(AiClient.ValidateEndpoint("https://api.openai.com/v1").AbsolutePath == "/v1/");
    return Task.CompletedTask;
});
Test("Partial Windows failures remain visible", async () => {
    var runner = new FakeRunner(script => {
        if (script.Contains("Get-MpComputerStatus")) return JsonSerializer.Serialize(healthyDefender);
        if (script.Contains("Get-NetFirewallProfile")) throw new InvalidOperationException("Access denied");
        return "[]";
    });
    var status = await new WindowsSecurity(runner).SnapshotAsync();
    Assert(status.Defender is not null && status.FirewallError == "Access denied");
    Assert(!status.IsHealthy);
});
Test("Threat history errors cannot report healthy", async () => {
    var runner = new FakeRunner(script => {
        if (script.Contains("Get-MpComputerStatus")) return JsonSerializer.Serialize(healthyDefender);
        if (script.Contains("Get-NetFirewallProfile")) return JsonSerializer.Serialize(profiles);
        throw new InvalidOperationException("No permission");
    });
    Assert(!(await new WindowsSecurity(runner).SnapshotAsync()).IsHealthy);
});
Test("Cancellation is propagated by protection snapshot", async () => {
    var runner = new FakeRunner(_ => throw new OperationCanceledException());
    await ThrowsAsync<OperationCanceledException>(() => new WindowsSecurity(runner).SnapshotAsync());
});
Test("Firewall deletion rejects arbitrary and malformed names", async () => {
    var runner = new FakeRunner(_ => ""); var security = new WindowsSecurity(runner);
    foreach (var name in new[] { "Windows Defender", "Sentinel-evil", "Sentinel-" + new string('z',24) }) await ThrowsAsync<ArgumentException>(() => security.RemoveBlockAsync(name));
    Assert(runner.Calls == 0);
    var valid = WindowsSecurity.BlockRuleName("C:\\Tools\\example.exe");
    Assert(valid == WindowsSecurity.BlockRuleName("c:\\tools\\EXAMPLE.exe"));
    await security.RemoveBlockAsync(valid);
    Assert(runner.LastScript.Contains("$r.Group -ne 'Sentinel application blocks'"));
});
Test("Scans validate targets and select exact scan types", async () => {
    var runner = new FakeRunner(_ => ""); var security = new WindowsSecurity(runner);
    await ThrowsAsync<ArgumentException>(() => security.ScanAsync(ScanKind.Custom, "missing-file-never-exists"));
    await ThrowsAsync<ArgumentOutOfRangeException>(() => security.ScanAsync((ScanKind)42));
    await security.ScanAsync(ScanKind.Full);
    using var data = JsonDocument.Parse(JsonSerializer.Serialize(runner.LastParameters));
    Assert(data.RootElement.GetProperty("Type").GetString() == "FullScan");
});
Test("AI snapshot omits raw errors, paths and IDs", () => {
    var payload = AiClient.SnapshotForAi(healthy with { DefenderError = "private C:\\Users\\secret\\file", Threats = [new("SECRET_ID", "test", false, 1)] });
    Assert(!payload.Contains("SECRET_ID") && !payload.Contains("secret"));
    return Task.CompletedTask;
});
foreach (var provider in new[] { ProviderKind.OpenAiCompatible, ProviderKind.Ollama, ProviderKind.Anthropic }) {
    var kind = provider;
    Test("AI request and response: " + kind, async () => {
        var handler = new FakeHttp(async request => {
            using var data = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            Assert(!data.RootElement.TryGetProperty("tools", out _));
            Assert(data.RootElement.GetProperty("model").GetString() == "test-model");
            var text = await request.Content.ReadAsStringAsync(); Assert(text.Contains("untrusted", StringComparison.OrdinalIgnoreCase));
            if (kind == ProviderKind.Anthropic) { Assert(request.Headers.GetValues("x-api-key").Single() == "secret"); Assert(request.RequestUri!.AbsolutePath == "/v1/messages"); }
            else if (kind == ProviderKind.OpenAiCompatible) { Assert(request.Headers.Authorization?.Parameter == "secret"); Assert(request.RequestUri!.AbsolutePath == "/v1/chat/completions"); }
            else { Assert(request.RequestUri!.AbsolutePath == "/api/chat"); Assert(!data.RootElement.GetProperty("stream").GetBoolean()); }
            var json = kind switch { ProviderKind.Ollama => "{\"message\":{\"content\":\"advice\"}}", ProviderKind.Anthropic => "{\"content\":[{\"type\":\"text\",\"text\":\"advice\"}]}", _ => "{\"choices\":[{\"message\":{\"content\":\"advice\"}}]}" };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) };
        });
        using var http = new HttpClient(handler);
        var settings = new AiSettings(kind, kind == ProviderKind.Ollama ? "http://localhost:11434/" : kind == ProviderKind.Anthropic ? "https://api.anthropic.com/" : "https://api.openai.com/v1/", "test-model");
        Assert(await new AiClient(http).AskAsync(settings, kind == ProviderKind.Ollama ? "" : "secret", "Assess security", AiClient.SnapshotForAi(healthy)) == "advice");
    });
}
Test("Provider error bodies never leak to user", async () => {
    using var http = new HttpClient(new FakeHttp(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("echoed-private-secret") })));
    try { await new AiClient(http).AskAsync(new(ProviderKind.OpenAiCompatible, "https://example.com/v1/", "test"), "key", "question", "{}"); throw new Exception("Expected failure"); }
    catch (InvalidOperationException ex) { Assert(!ex.Message.Contains("private-secret") && ex.Message.Contains("401")); }
});
Test("Missing key and model rejected before sending", async () => {
    var calls = 0;
    using var http = new HttpClient(new FakeHttp(_ => { calls++; throw new Exception("Should not send"); }));
    var client = new AiClient(http);
    await ThrowsAsync<ArgumentException>(() => client.AskAsync(new(ProviderKind.OpenAiCompatible, "https://example.com/v1/", "model"), "", "q", "{}"));
    await ThrowsAsync<ArgumentException>(() => client.AskAsync(new(), "", "q", "{}"));
    await ThrowsAsync<ArgumentException>(() => client.AskAsync(new(ProviderKind.OpenAiCompatible, "https://example.com/v1/", "model"), "secret\nvalue", "q", "{}"));
    Assert(calls == 0);
});
Test("Oversize AI response rejected", async () => {
    using var http = new HttpClient(new FakeHttp(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new string('a', 2 * 1024 * 1024 + 1)) })));
    await ThrowsAsync<InvalidOperationException>(() => new AiClient(http).AskAsync(new(ProviderKind.Ollama, "http://localhost:11434/", "test"), "", "q", "{}"));
});
Test("Codex policy must be explicitly confirmed", () => {
    foreach (var json in new[] { "{}", "{\"sandbox\":{\"type\":\"dangerFullAccess\"},\"approvalPolicy\":\"on-request\"}", "{\"sandbox\":{\"type\":\"readOnly\",\"networkAccess\":true},\"approvalPolicy\":\"on-request\"}", "{\"sandbox\":{\"type\":\"readOnly\"},\"approvalPolicy\":\"never\"}" }) {
        using var bad = JsonDocument.Parse(json);
        Throws<InvalidOperationException>(() => CodexAdvisor.ValidatePolicy(bad.RootElement));
    }
    using var good = JsonDocument.Parse("{\"sandbox\":{\"type\":\"readOnly\",\"networkAccess\":false},\"approvalPolicy\":\"on-request\"}");
    CodexAdvisor.ValidatePolicy(good.RootElement);
    return Task.CompletedTask;
});
ProtectionTests.Register(Test);
ArchiveTests.Register(Test);
SessionTests.Register(Test);
ModelDiscoveryTests.Register(Test);
NetworkTests.Register(Test);
var failed = 0;
foreach (var (name, run) in tests) { try { await run(); Console.WriteLine("PASS " + name); } catch (Exception ex) { failed++; Console.WriteLine("FAIL " + name + ": " + ex.Message); } }
Console.WriteLine($"{tests.Count - failed}/{tests.Count} tests passed");
return failed == 0 ? 0 : 1;

sealed class FakeRunner(Func<string, string> result) : IScriptRunner
{
    public int Calls { get; private set; }
    public string LastScript { get; private set; } = "";
    public object? LastParameters { get; private set; }
    public Task<string> RunAsync(string script, object? parameters = null, TimeSpan? timeout = null, CancellationToken cancellationToken = default) { Calls++; LastScript = script; LastParameters = parameters; return Task.FromResult(result(script)); }
}
sealed class FakeHttp(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
}
