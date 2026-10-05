using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core;

public interface IScriptRunner
{
    Task<string> RunAsync(string script, object? parameters = null, TimeSpan? timeout = null, CancellationToken cancellationToken = default);
}

public sealed class PowerShellRunner : IScriptRunner
{
    public static string Encode(string script, object? parameters)
    {
        var data = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parameters ?? new { })));
        // Arguments are serialized data, never executable PowerShell fragments.
        var prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" +
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);" +
            "$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data + "'))|ConvertFrom-Json;";
        return Convert.ToBase64String(Encoding.Unicode.GetBytes(prefix + script));
    }

    public async Task<string> RunAsync(string script, object? parameters = null, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Live protection requires Windows.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout ?? TimeSpan.FromSeconds(45));
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        using var process = new Process { StartInfo = new ProcessStartInfo(executable) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 } };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Encode(script, parameters) }) process.StartInfo.ArgumentList.Add(arg);
        process.Start();
        // Drain both streams before waiting to prevent pipe deadlocks.
        var output = process.StandardOutput.ReadToEndAsync(deadline.Token);
        var error = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            var result = await output;
            var problem = await error;
            if (process.ExitCode != 0) throw new InvalidOperationException(string.IsNullOrWhiteSpace(problem) ? "Windows rejected the operation." : problem.Trim());
            return result.Trim();
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await Task.WhenAll(output, error); } catch (OperationCanceledException) { }
            if (!cancellationToken.IsCancellationRequested) throw new TimeoutException("Windows did not respond within the time limit. A native scan may still be running.");
            throw;
        }
    }
}
