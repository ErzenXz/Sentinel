using System.Text.Json;

namespace Sentinel.Core.Protection;

public sealed record ProtectionPreferences(bool KeepInTray = false, bool NotifyDetections = false, bool AutoUpdateFeeds = false,
    bool RememberMonitor = false, string MonitorFolder = "");

public static class ProtectionPreferencesStore
{
    public static ProtectionPreferences Load(string path)
    {
        if (!File.Exists(path)) return new();
        path = FileSafety.NormalizeRegularPath(Path.GetFullPath(path));
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > 16 * 1024) throw new InvalidDataException("Protection preferences exceed the size limit.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        var preferences = JsonSerializer.Deserialize<ProtectionPreferences>(bytes, FeedVerifier.Json) ?? throw new InvalidDataException("Invalid protection preferences.");
        Validate(preferences); return preferences;
    }
    public static void Validate(ProtectionPreferences preferences)
    {
        if (preferences.MonitorFolder is null || preferences.MonitorFolder.Length > 4096 || preferences.MonitorFolder.Any(char.IsControl)) throw new InvalidDataException("Invalid saved monitoring folder.");
        if (preferences.RememberMonitor && string.IsNullOrWhiteSpace(preferences.MonitorFolder)) throw new InvalidDataException("Choose a monitoring folder before enabling resume.");
        if (!string.IsNullOrEmpty(preferences.MonitorFolder)) _ = FileSafety.NormalizeLocalPath(preferences.MonitorFolder);
    }
    public static void Save(string path, ProtectionPreferences preferences)
    {
        Validate(preferences); path = FileSafety.NormalizeLocalPath(Path.GetFullPath(path));
        var parent = Path.GetDirectoryName(path)!; FileSafety.EnsureDirectory(parent);
        if (File.Exists(path)) _ = FileSafety.NormalizeRegularPath(path);
        var staged = Path.Combine(parent, ".sentinel-preferences-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(JsonSerializer.SerializeToUtf8Bytes(preferences, FeedVerifier.Json)); stream.Flush(flushToDisk: true); }
            File.Move(staged, path, overwrite: true);
        }
        finally { if (File.Exists(staged)) File.Delete(staged); }
    }
}

public sealed record FeedUpdateStatus(bool Running, DateTimeOffset? LastAttempt = null, DateTimeOffset? LastSuccess = null,
    DateTimeOffset? NextAttempt = null, bool Failed = false);

// One opt-in worker, no catch-up bursts, and no retries until the next interval after a failure.
public sealed class FeedUpdateLoop : IAsyncDisposable
{
    private readonly CancellationTokenSource stop = new();
    private readonly Func<CancellationToken, Task> update;
    private readonly Action<FeedUpdateStatus> changed;
    private readonly TimeSpan interval;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    private readonly TimeProvider time;
    private readonly Task worker;
    private readonly object gate = new();
    private Task? disposal;
    private FeedUpdateStatus status = new(true);
    public FeedUpdateStatus Status => Volatile.Read(ref status);
    public FeedUpdateLoop(Func<CancellationToken, Task> update, Action<FeedUpdateStatus>? changed = null, TimeSpan? interval = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null, TimeProvider? time = null)
    {
        this.update = update; this.changed = changed ?? (_ => {}); this.interval = interval ?? TimeSpan.FromHours(6);
        if (this.interval < TimeSpan.FromMinutes(5) || this.interval > TimeSpan.FromDays(7)) throw new ArgumentOutOfRangeException(nameof(interval));
        this.delay = delay ?? ((duration, token) => Task.Delay(duration, token)); this.time = time ?? TimeProvider.System;
        worker = Task.Run(Work);
    }
    private void Publish(FeedUpdateStatus value)
    {
        Volatile.Write(ref status, value);
        try { changed(value); } catch { /* Observers cannot stop signed-feed checking. */ }
    }
    private async Task Work()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                Publish(Status with { Running = true, LastAttempt = time.GetUtcNow(), NextAttempt = null });
                try
                {
                    await update(stop.Token); stop.Token.ThrowIfCancellationRequested();
                    Publish(Status with { LastSuccess = time.GetUtcNow(), Failed = false });
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
                catch (Exception) { Publish(Status with { Failed = true }); }
                Publish(Status with { NextAttempt = time.GetUtcNow() + interval });
                await delay(interval, stop.Token);
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        finally { Publish(Status with { Running = false, NextAttempt = null }); }
    }
    public ValueTask DisposeAsync() { lock (gate) return new(disposal ??= DisposeCore()); }
    private async Task DisposeCore() { stop.Cancel(); await worker; stop.Dispose(); }
}

public enum FindingScope { All, Detections, Review, Incomplete }
public static class FindingSearch
{
    public static bool Matches(FileFinding finding, string search, FindingScope scope)
    {
        var selected = scope switch {
            FindingScope.All => true,
            FindingScope.Detections => finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile,
            FindingScope.Review => finding.Verdict == FileVerdict.NeedsReview,
            FindingScope.Incomplete => finding.Verdict is FileVerdict.Skipped or FileVerdict.Error,
            _ => throw new ArgumentOutOfRangeException(nameof(scope))
        };
        search = search.Trim();
        return selected && (search.Length == 0 || finding.DisplayPath.Contains(search, StringComparison.OrdinalIgnoreCase)
            || finding.Reason.Contains(search, StringComparison.OrdinalIgnoreCase) || finding.Sha256?.Contains(search, StringComparison.OrdinalIgnoreCase) == true);
    }
}

// Alerts contain counts only; no file paths, hashes, provider names, or file contents enter the OS notification.
public sealed class DetectionAlerts(TimeProvider? time = null)
{
    private readonly TimeProvider time = time ?? TimeProvider.System;
    private DateTimeOffset? last;
    private int pending;
    public string? Record(int detections, bool enabled)
    {
        if (!enabled) { pending = 0; return null; }
        if (detections > 0) pending = (int)Math.Min(int.MaxValue, (long)pending + detections);
        return Flush(enabled);
    }
    public string? Flush(bool enabled)
    {
        if (!enabled) { pending = 0; return null; }
        if (pending == 0) return null;
        var now = time.GetUtcNow();
        if (last is not null && now - last < TimeSpan.FromSeconds(30)) return null;
        var count = pending; pending = 0; last = now;
        return $"{count} exact detection{(count == 1 ? "" : "s")} need review. Open Sentinel to see the evidence. No file was removed automatically.";
    }
}
