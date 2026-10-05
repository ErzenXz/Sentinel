namespace Sentinel.Core;

public sealed record DefenderStatus(bool AntivirusEnabled, bool RealTimeProtectionEnabled,
    bool BehaviorMonitorEnabled, bool IsTamperProtected, string AMRunningMode,
    int AntivirusSignatureAge, string AntivirusSignatureVersion, string? QuickScanEndTime);
public sealed record FirewallProfile(string Name, bool Enabled, string DefaultInboundAction, string DefaultOutboundAction);
public sealed record ThreatRecord(string ThreatID, string ThreatName, bool IsActive, int SeverityID);
public sealed record AppRecord(int Id, string Name, string Path, string Signature, string Publisher);
public sealed record ConnectionRecord(string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, string State, int OwningProcess);
public sealed record FirewallRule(string Name, string DisplayName, string Direction, string Action, string Program);
public sealed record SecuritySnapshot(DefenderStatus? Defender, IReadOnlyList<FirewallProfile> Profiles,
    IReadOnlyList<ThreatRecord> Threats, string? DefenderError, string? FirewallError, string? ThreatError)
{
    // An unavailable subsystem must never produce a reassuring green status.
    public bool IsHealthy => Defender is { AntivirusEnabled: true, RealTimeProtectionEnabled: true, BehaviorMonitorEnabled: true,
        AMRunningMode: "Normal", AntivirusSignatureAge: <= 2 and >= 0 }
        && Profiles.Count == 3 && Profiles.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 3 && Profiles.All(p => p.Enabled)
        && ThreatError is null && !Threats.Any(t => t.IsActive) && DefenderError is null && FirewallError is null;
    public string Summary => IsHealthy ? "Core protections are on" : "Your protection needs a look";
}
public enum ScanKind { Quick, Full, Custom }
public enum ProviderKind { OpenAiCompatible, Anthropic, Ollama, CodexAppServer }
public sealed record AiSettings(ProviderKind Provider = ProviderKind.Ollama,
    string Endpoint = "http://127.0.0.1:11434/", string Model = "", string CodexExecutable = "");
public sealed record AuditEvent(DateTimeOffset Time, string Action, string Result);
