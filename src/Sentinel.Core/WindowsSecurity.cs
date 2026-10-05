using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core;

public sealed class WindowsSecurity(IScriptRunner runner)
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
    public const string RuleGroup = "Sentinel application blocks";
    public async Task<SecuritySnapshot> SnapshotAsync(CancellationToken token = default)
    {
        var defender = Capture(async () => JsonSerializer.Deserialize<DefenderStatus>(await runner.RunAsync("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,AMRunningMode,AntivirusSignatureAge,AntivirusSignatureVersion,@{n='QuickScanEndTime';e={if($_.QuickScanEndTime){$_.QuickScanEndTime.ToString('o')}}} | ConvertTo-Json -Compress", cancellationToken: token), Json) ?? throw new InvalidOperationException("No Defender status returned."));
        var firewall = Capture(async () => await ReadList<FirewallProfile>("ConvertTo-Json -InputObject @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,@{n='Enabled';e={$_.Enabled -eq 'True'}},@{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}},@{n='DefaultOutboundAction';e={$_.DefaultOutboundAction.ToString()}}) -Compress", token));
        var threats = Capture(async () => await ReadList<ThreatRecord>("ConvertTo-Json -InputObject @(Get-MpThreat | Select-Object @{n='ThreatID';e={$_.ThreatID.ToString()}},ThreatName,IsActive,SeverityID) -Compress", token));
        await Task.WhenAll(defender, firewall, threats);
        return new(defender.Result.Value, firewall.Result.Value ?? [], threats.Result.Value ?? [], defender.Result.Error, firewall.Result.Error, threats.Result.Error);
    }
    private static async Task<(T? Value, string? Error)> Capture<T>(Func<Task<T>> action)
    {
        try { return (await action(), null); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return (default, ex.Message); }
    }
    private async Task<List<T>> ReadList<T>(string script, CancellationToken token) =>
        JsonSerializer.Deserialize<List<T>>(await runner.RunAsync(script, cancellationToken: token), Json) ?? throw new InvalidOperationException("Windows returned no data.");
    public Task ScanAsync(ScanKind kind, string? path = null, CancellationToken token = default)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        if (kind == ScanKind.Custom && (string.IsNullOrWhiteSpace(path) || (!File.Exists(path) && !Directory.Exists(path)))) throw new ArgumentException("Choose an existing file or folder.");
        return runner.RunAsync(kind == ScanKind.Custom ? "Start-MpScan -ScanType CustomScan -ScanPath $p.Path" : "Start-MpScan -ScanType $p.Type",
            new { Path = path, Type = kind == ScanKind.Full ? "FullScan" : "QuickScan" }, TimeSpan.FromHours(12), token);
    }
    public Task UpdateSignaturesAsync(CancellationToken token = default) => runner.RunAsync("Update-MpSignature", timeout: TimeSpan.FromMinutes(10), cancellationToken: token);
    public Task<List<AppRecord>> AppsAsync(CancellationToken token = default) => ReadList<AppRecord>("""
        $seen=@{};$items=@();foreach($proc in Get-Process){try{$path=$proc.Path;if(!$path -or $seen.ContainsKey($path)){continue};$seen[$path]=$true;$s=Get-AuthenticodeSignature -LiteralPath $path;$items += [pscustomobject]@{Id=$proc.Id;Name=$proc.ProcessName;Path=$path;Signature=$s.Status.ToString();Publisher=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{'Unknown'}}}catch{}}
        ConvertTo-Json -InputObject @($items | Sort-Object Name) -Compress
        """, token);
    public Task<List<ConnectionRecord>> ConnectionsAsync(CancellationToken token = default) => ReadList<ConnectionRecord>("ConvertTo-Json -InputObject @(Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}},OwningProcess) -Compress", token);
    public Task<List<FirewallRule>> RulesAsync(CancellationToken token = default) => ReadList<FirewallRule>("""
        $items=@();foreach($r in @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {$_.Group -eq 'Sentinel application blocks'})){$a=$r|Get-NetFirewallApplicationFilter;$items += [pscustomobject]@{Name=$r.Name;DisplayName=$r.DisplayName;Direction=$r.Direction.ToString();Action=$r.Action.ToString();Program=$a.Program}}
        ConvertTo-Json -InputObject @($items) -Compress
        """, token);
    public static string BlockRuleName(string path) => "Sentinel-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path.ToUpperInvariant())))[..24];
    public Task BlockAppAsync(string path, CancellationToken token = default)
    {
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path) || !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Choose an existing executable with an absolute path.");
        return runner.RunAsync("""
            $existing=Get-NetFirewallRule -Name $p.Name -ErrorAction SilentlyContinue
            if($existing){if($existing.Group -ne 'Sentinel application blocks'){throw 'Rule name collision.'};$filter=$existing|Get-NetFirewallApplicationFilter;if($filter.Program -ne $p.Path){throw 'Rule path collision.'};if($existing.Enabled -ne 'True' -or $existing.Action -ne 'Block' -or $existing.Direction -ne 'Outbound'){throw 'Existing rule does not match an enabled outbound block.'}}
            else{New-NetFirewallRule -Name $p.Name -DisplayName $p.DisplayName -Group 'Sentinel application blocks' -Direction Outbound -Action Block -Program $p.Path -Profile Any -Enabled True | Out-Null}
            """, new { Path = path, Name = BlockRuleName(path), DisplayName = "Sentinel · " + Path.GetFileName(path) }, cancellationToken: token);
    }
    public Task RemoveBlockAsync(string name, CancellationToken token = default)
    {
        if (!name.StartsWith("Sentinel-", StringComparison.Ordinal) || name.Length != 33 || name[9..].Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Invalid Sentinel rule name.");
        return runner.RunAsync("$r=Get-NetFirewallRule -Name $p.Name;if($r.Group -ne 'Sentinel application blocks'){throw 'This rule is not owned by Sentinel.'};$r | Remove-NetFirewallRule", new { Name = name }, cancellationToken: token);
    }
}
