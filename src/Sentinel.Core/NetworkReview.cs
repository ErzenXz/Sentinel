using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Sentinel.Core;

public sealed record NetworkProcess(int Id, string Name, string Path, string StartedAt);
public sealed record NetworkSnapshot(DateTimeOffset CapturedAt, IReadOnlyList<FirewallProfile> Profiles,
    IReadOnlyList<ConnectionRecord> Connections, IReadOnlyList<NetworkProcess> Processes, bool Truncated,
    string? ProfileError = null, string? ConnectionError = null, string? ProcessError = null);
public enum ReviewPriority { Routine, Review, Urgent }
public enum AddressScope { Unknown, Unspecified, Loopback, LocalNetwork, NonLocal }

// Only fixed categories/counts can cross the model boundary. No path, name, PID, address or publisher.
public sealed record FirewallEvidence(int EstablishedNonLocal, int EstablishedLocal, int UnknownEndpoints,
    int NonLoopbackListeners, int LoopbackListeners, bool ExecutableAvailable, string Signature,
    bool ProcessIdentified, bool ProfilesKnown, int DisabledProfiles, int AllowInboundProfiles,
    int UnknownInboundProfiles, bool ConnectionsComplete);
public sealed record LocalNetworkDecision(ReviewPriority Priority, IReadOnlyList<string> Reasons);
public sealed record NetworkAppReview(int ProcessId, string Name, string Path, string StartedAt, int Connections,
    FirewallEvidence Evidence, LocalNetworkDecision Decision)
{
    public string Priority => Decision.Priority.ToString();
    public string Summary => string.Join(" ", Decision.Reasons);
    public int NonLocal => Evidence.EstablishedNonLocal;
    public int Listeners => Evidence.NonLoopbackListeners;
}

public static class NetworkReview
{
    public const int MaxConnections = 1_000;
    public static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true, MaxDepth = 16 };
    private static readonly HashSet<string> Signatures = new(StringComparer.Ordinal) { "Unknown", "Valid", "Unsigned", "Invalid" };
    private static readonly HashSet<string> States = new(StringComparer.OrdinalIgnoreCase) { "Bound", "Closed", "CloseWait", "Closing", "DeleteTCB", "Established", "FinWait1", "FinWait2", "LastAck", "Listen", "SynReceived", "SynSent", "TimeWait" };

    public static void Validate(NetworkSnapshot snapshot)
    {
        if (snapshot.Profiles is null || snapshot.Connections is null || snapshot.Processes is null || snapshot.Profiles.Count > 3 || snapshot.Connections.Count > MaxConnections || snapshot.Processes.Count > MaxConnections || snapshot.CapturedAt == default)
            throw new InvalidDataException("Invalid or over-limit network snapshot.");
        if (snapshot.Processes.Any(x => x is null) || snapshot.Profiles.Any(x => x is null) || snapshot.Connections.Any(x => x is null)) throw new InvalidDataException("Null network record.");
        if (snapshot.Processes.Select(x => x.Id).Distinct().Count() != snapshot.Processes.Count || snapshot.Processes.Any(x => x.Id <= 0 || !Text(x.Name, 256) || !Text(x.Path, 4096) || !Text(x.StartedAt, 64) || x.StartedAt.Length > 0 && !DateTimeOffset.TryParse(x.StartedAt, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _)))
            throw new InvalidDataException("Invalid process identity in network snapshot.");
        if (snapshot.Connections.Any(x => x.OwningProcess < 0 || x.LocalPort is < 0 or > 65535 || x.RemotePort is < 0 or > 65535 || !Text(x.LocalAddress, 128) || !Text(x.RemoteAddress, 128) || !States.Contains(x.State ?? "")))
            throw new InvalidDataException("Invalid connection in network snapshot.");
        if (snapshot.Profiles.Any(x => !Text(x.Name, 32) || !Text(x.DefaultInboundAction, 32) || !Text(x.DefaultOutboundAction, 32))) throw new InvalidDataException("Invalid firewall profile.");
        if (new[] { snapshot.ProfileError, snapshot.ConnectionError, snapshot.ProcessError }.Any(x => x is not null && !Text(x, 256))) throw new InvalidDataException("Invalid network availability state.");
    }
    private static bool Text(string? value, int maximum) => value is not null && value.Length <= maximum && !value.Any(char.IsControl);
    public static bool IsFresh(NetworkSnapshot snapshot, DateTimeOffset now) => snapshot.CapturedAt <= now.AddSeconds(5) && snapshot.CapturedAt >= now.AddMinutes(-2);
    public static string SignatureCategory(string? status) => status switch { "Valid" => "Valid", "NotSigned" => "Unsigned", "HashMismatch" or "NotTrusted" => "Invalid", _ => "Unknown" };
    public static AddressScope Scope(string? address)
    {
        if (address is null || address.Length > 128 || !IPAddress.TryParse(address, out var ip)) return AddressScope.Unknown;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return AddressScope.Loopback;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return AddressScope.Unspecified;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168 || b[0] == 169 && b[1] == 254 || b[0] == 100 && b[1] is >= 64 and <= 127)
                return AddressScope.LocalNetwork;
            if (b[0] == 0 || b[0] >= 224) return AddressScope.Unknown;
        }
        else
        {
            if (ip.IsIPv6LinkLocal || (b[0] & 0xfe) == 0xfc) return AddressScope.LocalNetwork;
            if (ip.IsIPv6Multicast) return AddressScope.Unknown;
        }
        // NonLocal describes the address category, not actual Internet reachability or reputation.
        return AddressScope.NonLocal;
    }
    public static IReadOnlyList<NetworkAppReview> Assess(NetworkSnapshot snapshot)
    {
        Validate(snapshot);
        var processes = snapshot.Processes.ToDictionary(x => x.Id);
        var result = new List<NetworkAppReview>();
        var profilesKnown = snapshot.ProfileError is null && snapshot.Profiles.Count == 3 &&
            snapshot.Profiles.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(["Domain", "Private", "Public"]);
        foreach (var group in snapshot.Connections.GroupBy(x => x.OwningProcess))
        {
            processes.TryGetValue(group.Key, out var process);
            var nonLocal = 0; var local = 0; var unknown = 0; var listeners = 0; var loopback = 0;
            foreach (var c in group)
            {
                if (c.State.Equals("Listen", StringComparison.OrdinalIgnoreCase))
                {
                    var scope = Scope(c.LocalAddress);
                    if (scope == AddressScope.Loopback) loopback++;
                    else { listeners++; if (scope == AddressScope.Unknown) unknown++; }
                }
                else if (c.State.Equals("Established", StringComparison.OrdinalIgnoreCase))
                {
                    var scope = Scope(c.RemoteAddress);
                    if (scope == AddressScope.NonLocal) nonLocal++;
                    else if (scope is AddressScope.Loopback or AddressScope.LocalNetwork) local++;
                    else unknown++;
                }
            }
            var evidence = new FirewallEvidence(nonLocal, local, unknown, listeners, loopback,
                process is { Path.Length: > 0 }, "Unknown", process is { StartedAt.Length: > 0 } && snapshot.ProcessError is null,
                profilesKnown, snapshot.Profiles.Count(x => !x.Enabled), snapshot.Profiles.Count(x => x.DefaultInboundAction.Equals("Allow", StringComparison.OrdinalIgnoreCase)),
                snapshot.Profiles.Count(x => !x.DefaultInboundAction.Equals("Allow", StringComparison.OrdinalIgnoreCase) && !x.DefaultInboundAction.Equals("Block", StringComparison.OrdinalIgnoreCase)),
                !snapshot.Truncated && snapshot.ConnectionError is null);
            result.Add(new(group.Key, process?.Name ?? "Process unavailable", process?.Path ?? "", process?.StartedAt ?? "", group.Count(), evidence, Decide(evidence)));
        }
        return result.OrderByDescending(x => x.Decision.Priority).ThenByDescending(x => x.Listeners).ThenByDescending(x => x.NonLocal).ThenBy(x => x.ProcessId).ToArray();
    }
    public static LocalNetworkDecision GlobalDecision(NetworkSnapshot snapshot)
    {
        Validate(snapshot);
        var known = snapshot.ProfileError is null && snapshot.Profiles.Count == 3 && snapshot.Profiles.Select(x=>x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(["Domain","Private","Public"]);
        return Decide(new(0,0,0,0,0,true,"Unknown",snapshot.ProcessError is null,known,
            snapshot.Profiles.Count(x=>!x.Enabled),snapshot.Profiles.Count(x=>x.DefaultInboundAction.Equals("Allow",StringComparison.OrdinalIgnoreCase)),
            snapshot.Profiles.Count(x=>!x.DefaultInboundAction.Equals("Allow",StringComparison.OrdinalIgnoreCase)&&!x.DefaultInboundAction.Equals("Block",StringComparison.OrdinalIgnoreCase)),
            !snapshot.Truncated && snapshot.ConnectionError is null));
    }
    public static void Validate(FirewallEvidence e)
    {
        if (!Signatures.Contains(e.Signature ?? "") || new[] { e.EstablishedNonLocal, e.EstablishedLocal, e.UnknownEndpoints, e.NonLoopbackListeners, e.LoopbackListeners }.Any(x => x is < 0 or > MaxConnections) ||
            e.EstablishedNonLocal + e.EstablishedLocal + e.NonLoopbackListeners + e.LoopbackListeners > MaxConnections ||
            new[] { e.DisabledProfiles, e.AllowInboundProfiles, e.UnknownInboundProfiles }.Any(x => x is < 0 or > 3) || e.AllowInboundProfiles + e.UnknownInboundProfiles > 3 || e.Signature != "Unknown" && !e.ExecutableAvailable)
            throw new InvalidDataException("Invalid firewall evidence.");
    }
    public static LocalNetworkDecision Decide(FirewallEvidence e)
    {
        Validate(e);
        var reasons = new List<string>(); var priority = ReviewPriority.Routine;
        void Add(ReviewPriority p, string reason) { if (p > priority) priority = p; reasons.Add(reason); }
        if (e.DisabledProfiles > 0) Add(ReviewPriority.Urgent, "A Windows Firewall profile is disabled. Review Windows protection settings.");
        if (!e.ProfilesKnown || e.UnknownInboundProfiles > 0) Add(ReviewPriority.Review, "Firewall policy could not be fully established.");
        if (e.AllowInboundProfiles > 0) Add(ReviewPriority.Review, "A profile defaults to allowing inbound traffic; review its effective policy.");
        if (!e.ConnectionsComplete) Add(ReviewPriority.Review, "The TCP snapshot is incomplete; refresh or inspect Windows networking.");
        if (!e.ProcessIdentified || !e.ExecutableAvailable) Add(ReviewPriority.Review, "The owning process or executable could not be fully identified.");
        if (e.UnknownEndpoints > 0) Add(ReviewPriority.Review, "Some endpoint addresses could not be categorized.");
        if (e.NonLoopbackListeners > 0) Add(ReviewPriority.Review, "This process listens beyond loopback. Firewall and routing determine who can reach it.");
        if (e.Signature == "Invalid") Add(ReviewPriority.Review, "Windows reported a signature problem. Check the file with the independent scanner.");
        if (e.EstablishedNonLocal > 0 && e.Signature is "Unknown" or "Unsigned") Add(ReviewPriority.Review, "Non-local connections have no verified publisher evidence. Inspect the selected app; this is not a malware verdict.");
        if (reasons.Count == 0) reasons.Add("No specific issue in these limited checks. Address and signature metadata do not prove safety.");
        return new(priority, reasons);
    }
}
