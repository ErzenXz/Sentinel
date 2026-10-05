using System.Text;
using System.Text.Json;

namespace Sentinel.Core.Protection;

public static class WindowsArgument
{
    public static string Quote(string value)
    {
        var text = new StringBuilder("\""); var slashes=0;
        foreach(var ch in value)
        {
            if(ch=='\\') { slashes++;continue; }
            if(ch=='"') { text.Append('\\',slashes*2+1);text.Append(ch);slashes=0;continue; }
            text.Append('\\',slashes);slashes=0;text.Append(ch);
        }
        text.Append('\\',slashes*2);text.Append('"');return text.ToString();
    }
}
public sealed record ScheduleStatus(bool Exists, string? State, string? NextRun, string? LastRun, long? LastResult);
public sealed class ScanScheduler(IScriptRunner runner)
{
    public Task RegisterAsync(string executable,string folder,string profile,int hour,int minute,CancellationToken token=default)
    {
        if (hour is <0 or >23 || minute is <0 or >59) throw new ArgumentException("Use a valid daily time.");
        if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable) || !executable.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("The portable Sentinel.Scanner.exe is missing. Extract the full Windows package.");
        folder=FileSafety.NormalizeRegularPath(folder);if(!Directory.Exists(folder))throw new ArgumentException("Choose a scan folder.");
        var arguments = string.Join(" ",new[]{"scan",folder,"--profile",profile,"--report",Path.Combine(profile,"reports","scheduled-scan.json")}.Select(WindowsArgument.Quote));
        return runner.RunAsync("""
            $id=[Security.Principal.WindowsIdentity]::GetCurrent();$name='Sentinel-OwnScan-'+$id.User.Value
            $a=New-ScheduledTaskAction -Execute $p.Executable -Argument $p.Arguments
            $t=New-ScheduledTaskTrigger -Daily -At ([DateTime]::Today.AddHours($p.Hour).AddMinutes($p.Minute))
            $principal=New-ScheduledTaskPrincipal -UserId $id.Name -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $name -Action $a -Trigger $t -Principal $principal -Settings $settings -Description 'Sentinel independent daily folder scan. Runs only for the current logged-in user; no automatic deletion.' -Force | Out-Null
            """,new {Executable=executable,Arguments=arguments,Hour=hour,Minute=minute},cancellationToken:token);
    }
    public async Task<ScheduleStatus> StatusAsync(CancellationToken token = default)
    {
        var json = await runner.RunAsync("""
            $name='Sentinel-OwnScan-'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $task=Get-ScheduledTask | Where-Object {$_.TaskName -eq $name -and $_.TaskPath -eq '\'} | Select-Object -First 1
            if($null -eq $task){@{Exists=$false}|ConvertTo-Json -Compress;return}
            $info=$task|Get-ScheduledTaskInfo
            @{Exists=$true;State=[string]$task.State;NextRun=$info.NextRunTime.ToString('o');LastRun=$info.LastRunTime.ToString('o');LastResult=[long]$info.LastTaskResult}|ConvertTo-Json -Compress
            """, cancellationToken: token);
        return JsonSerializer.Deserialize<ScheduleStatus>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new InvalidDataException("Windows returned an invalid schedule status.");
    }
    public Task RemoveAsync(CancellationToken token=default) => runner.RunAsync("$name='Sentinel-OwnScan-'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Unregister-ScheduledTask -TaskName $name -Confirm:$false",cancellationToken:token);
}
