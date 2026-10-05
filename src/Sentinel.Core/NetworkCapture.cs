using System.Text.Json;

namespace Sentinel.Core;

public static class NetworkCapture
{
    // One fixed PowerShell process; no per-process signatures, DNS, whois or repeated polling.
    public static async Task<NetworkSnapshot> ReadAsync(IScriptRunner runner, CancellationToken token = default)
    {
        var captured = DateTimeOffset.UtcNow;
        var raw = await runner.RunAsync("""
            $profiles=@();$tcp=@();$processes=[System.Collections.Generic.List[object]]::new();$profileError=$null;$connectionError=$null;$processError=$null;$truncated=$false
            try{$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,@{n='Enabled';e={$_.Enabled -eq 'True'}},@{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}},@{n='DefaultOutboundAction';e={$_.DefaultOutboundAction.ToString()}})}catch{$profileError='Firewall profiles unavailable.'}
            try{$tcp=@(Get-NetTCPConnection | Select-Object -First 1001);$truncated=$tcp.Count -gt 1000;$tcp=@($tcp | Select-Object -First 1000)}catch{$connectionError='TCP connections unavailable.'}
            try{foreach($processId in @($tcp.OwningProcess | Sort-Object -Unique)){if($processId -le 0){continue};$name='Process unavailable';$path='';$started='';try{$proc=Get-Process -Id $processId;$name=$proc.ProcessName;try{$path=$proc.Path;if(!$path){$path=''}}catch{};try{$started=$proc.StartTime.ToUniversalTime().ToString('o')}catch{}}catch{};$processes.Add([pscustomobject]@{Id=$processId;Name=$name;Path=$path;StartedAt=$started})}}catch{$processError='Process identities incomplete.'}
            [pscustomobject]@{Profiles=@($profiles);Connections=@($tcp | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}},OwningProcess);Processes=@($processes.ToArray());Truncated=$truncated;ProfileError=$profileError;ConnectionError=$connectionError;ProcessError=$processError}|ConvertTo-Json -Depth 5 -Compress
            """, timeout: TimeSpan.FromSeconds(30), cancellationToken: token);
        if (raw.Length > 4 * 1024 * 1024) throw new InvalidDataException("Network snapshot exceeded its size limit.");
        try
        {
            var snapshot = JsonSerializer.Deserialize<NetworkSnapshot>(raw, NetworkReview.Json) ?? throw new InvalidDataException("Windows returned no network snapshot.");
            snapshot = snapshot with { CapturedAt = captured };
            NetworkReview.Validate(snapshot); return snapshot;
        }
        catch (JsonException) { throw new InvalidDataException("Windows returned an invalid network snapshot."); }
    }
    public static async Task<AppRecord> InspectAsync(IScriptRunner runner, NetworkAppReview selected, CancellationToken token = default)
    {
        if (selected.ProcessId <= 0 || string.IsNullOrWhiteSpace(selected.Path) || !DateTimeOffset.TryParse(selected.StartedAt, out _)) throw new ArgumentException("Process identity is unavailable. Refresh or choose the executable manually.");
        var raw = await runner.RunAsync("""
            $proc=Get-Process -Id $p.Id
            if(!$proc.Path -or $proc.Path -ne $p.Path -or $proc.StartTime.ToUniversalTime().ToString('o') -ne $p.StartedAt){throw 'The selected process changed. Refresh the network snapshot.'}
            $s=Get-AuthenticodeSignature -LiteralPath $proc.Path
            [pscustomobject]@{Id=$proc.Id;Name=$proc.ProcessName;Path=$proc.Path;Signature=$s.Status.ToString();Publisher=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{'Unknown'}}|ConvertTo-Json -Compress
            """, new { Id = selected.ProcessId, selected.Path, selected.StartedAt }, TimeSpan.FromSeconds(20), token);
        if (raw.Length > 32 * 1024) throw new InvalidDataException("Signature inspection exceeded its size limit.");
        var app = JsonSerializer.Deserialize<AppRecord>(raw, NetworkReview.Json) ?? throw new InvalidDataException("Windows returned no application identity.");
        if (app.Id != selected.ProcessId || !string.Equals(app.Path, selected.Path, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("The selected application identity changed.");
        return app;
    }
}
