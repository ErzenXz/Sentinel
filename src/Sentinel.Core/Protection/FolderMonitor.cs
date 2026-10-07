using System.Threading.Channels;

namespace Sentinel.Core.Protection;

public sealed record MonitorRecoveryStatus(bool Scanning = false, bool Pending = false, int Completed = 0,
    DateTimeOffset? LastCompleted = null, int Scanned = 0, int Detected = 0, int Review = 0, int Skipped = 0, int Errors = 0,
    bool LimitReached = false, bool FindingsTruncated = false, bool Canceled = false)
{
    public bool Incomplete => Skipped > 0 || Errors > 0 || LimitReached || FindingsTruncated || Canceled;
}

// One worker handles both settled file changes and bounded recovery scans. This observes
// writes after they happen; it is not a pre-execution gate or a protected service.
public sealed class FolderMonitor : IAsyncDisposable
{
    private sealed class Pending { public long Version; public long ChangedAt; }
    private readonly record struct WorkItem(string? Path);
    private readonly object gate = new();
    private readonly FileSystemWatcher watcher;
    private readonly Channel<WorkItem> queue = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(512) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly Dictionary<string, Pending> pending = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private readonly string directory;
    private readonly string[] excluded;
    private readonly CancellationTokenSource stop = new();
    private readonly Func<FileScanner> scanner;
    private readonly Action<FileFinding> finding;
    private readonly Action<string> problem;
    private readonly TimeProvider time;
    private readonly TimeSpan recoveryTimeout;
    private readonly Task worker;
    private Task? disposal;
    private int dropped, running = 1, scans;
    private long changed;
    private bool recoveryRequested = true;
    private bool wakeQueued;
    private long? recoveryFinished;
    private MonitorRecoveryStatus recovery = new();
    public bool IsRunning => Volatile.Read(ref running) == 1;
    public int DroppedEvents => Volatile.Read(ref dropped);
    public int CompletedScans => Volatile.Read(ref scans);
    public long ObservedChanges => Interlocked.Read(ref changed);
    public int PendingFiles { get { lock (gate) return pending.Count; } }
    public MonitorRecoveryStatus RecoveryStatus { get { lock (gate) return recovery.Pending == recoveryRequested ? recovery : recovery with { Pending = recoveryRequested }; } }

    public FolderMonitor(string directory, Func<FileScanner> scanner, Action<FileFinding> finding, Action<string> problem,
        IEnumerable<string>? excludedDirectories = null, TimeProvider? time = null, TimeSpan? recoveryTimeout = null)
    {
        this.directory = FileSafety.NormalizeRegularPath(directory);
        if (!Directory.Exists(this.directory)) throw new ArgumentException("Choose a folder to monitor.");
        this.scanner = scanner; this.finding = finding; this.problem = problem; this.time = time ?? TimeProvider.System;
        this.recoveryTimeout = recoveryTimeout ?? TimeSpan.FromMinutes(5);
        if (this.recoveryTimeout < TimeSpan.FromSeconds(1) || this.recoveryTimeout > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(recoveryTimeout));
        excluded = FileSafety.NormalizeExclusions(excludedDirectories);
        if (FileSafety.IsExcluded(this.directory, excluded)) throw new ArgumentException("The monitoring folder cannot be excluded.");
        watcher = new(this.directory) { IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size, InternalBufferSize = 16 * 1024 };
        watcher.Created += (_, e) => Enqueue(e.FullPath);
        watcher.Changed += (_, e) => Enqueue(e.FullPath);
        watcher.Renamed += (_, e) => Enqueue(e.FullPath);
        watcher.Error += (_, e) => {
            if (!IsRunning) return;
            if (e.GetException() is InternalBufferOverflowException)
                Lost("The folder watcher lost events. A bounded recovery scan is queued.");
            else
            {
                Volatile.Write(ref running, 0);
                try { stop.Cancel(); } catch (ObjectDisposedException) { }
                ReportProblem("The folder watcher stopped. Restart monitoring and run a manual folder scan.");
            }
        };
        // Start observing before the initial scan, so changes during that scan stay queued.
        try { watcher.EnableRaisingEvents = true; worker = Task.Run(Work); }
        catch { Volatile.Write(ref running, 0); watcher.Dispose(); stop.Dispose(); throw; }
    }
    public static bool IsWithin(string path, string directory)
    {
        directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)); path = Path.GetFullPath(path);
        return FileSafety.IsWithinNormalized(path, directory);
    }
    // Requests coalesce into one bit. Scans begin at least 30 seconds after the previous
    // recovery completes; file-change work can continue throughout that cooldown.
    public bool RequestRecovery()
    {
        lock (gate)
        {
            if (!IsRunning) return false;
            recoveryRequested = true;
            if (!wakeQueued) wakeQueued = queue.Writer.TryWrite(default); // A full queue already guarantees the worker wakes.
            return true;
        }
    }
    private void ReportProblem(string message) { try { problem(message); } catch { /* Observer failures cannot crash native watcher callbacks. */ } }
    private void Lost(string message) { Interlocked.Increment(ref dropped); RequestRecovery(); ReportProblem(message); }
    private void Enqueue(string path)
    {
        if (!IsRunning || FileSafety.IsExcluded(path, excluded)) return;
        Interlocked.Increment(ref changed);
        var lost = false;
        lock (gate)
        {
            if (!IsRunning) return;
            if (pending.TryGetValue(path, out var current)) { current.Version++; current.ChangedAt = Environment.TickCount64; return; }
            if (pending.Count >= 512) lost = true;
            else
            {
                pending.Add(path, new() { Version = 1, ChangedAt = Environment.TickCount64 });
                if (!queue.Writer.TryWrite(new(path))) { pending.Remove(path); lost = true; }
            }
        }
        if (lost) Lost("The folder scan queue is full. Some changes were missed; a bounded recovery scan is queued.");
    }
    private void Requeue(string path)
    {
        if (IsRunning && queue.Writer.TryWrite(new(path))) return;
        pending.Remove(path);
        if (IsRunning) Lost("A rewritten file could not be queued; a bounded recovery scan is queued.");
    }
    private void Deliver(FileFinding value)
    {
        if (value.Verdict == FileVerdict.NoKnownMatch) return;
        try { finding(value); }
        catch { ReportProblem("A monitoring finding could not be delivered. Run and save a manual scan."); }
    }
    private async Task DeliverFindings(IReadOnlyList<FileFinding> values)
    {
        for (var i = 0; i < values.Count; i++)
        {
            stop.Token.ThrowIfCancellationRequested();
            // Give the native inbox time to drain large recovery/archive batches.
            // An unresponsive observer can still lose bounded display evidence.
            if (i > 0 && i % 128 == 0) await Task.Delay(200, stop.Token);
            Deliver(values[i]);
        }
    }
    private async Task Recover()
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
        deadline.CancelAfter(recoveryTimeout);
        try
        {
            var report = await scanner().ScanPathAsync(directory, token: deadline.Token, excludedDirectories: excluded);
            await DeliverFindings(report.Findings);
            stop.Token.ThrowIfCancellationRequested();
            lock (gate) recovery = new(Completed: recovery.Completed + 1, LastCompleted: time.GetUtcNow(), Scanned: report.Scanned,
                Detected: report.Detected, Review: report.Review, Skipped: report.Skipped, Errors: report.Errors,
                LimitReached: report.LimitReached, FindingsTruncated: report.FindingsTruncated, Canceled: report.Canceled);
            if (report.Incomplete) ReportProblem("Recovery scan finished with exclusions or coverage gaps. Review the findings; run and save a manual scan for a report.");
        }
        catch (OperationCanceledException) when (!stop.IsCancellationRequested && deadline.IsCancellationRequested)
        {
            lock (gate) recovery = new(Completed: recovery.Completed + 1, LastCompleted: time.GetUtcNow(), Canceled: true);
            ReportProblem("Recovery reached its time budget. Changed files will still be checked; run and save a manual scan for full coverage.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
            lock (gate) recovery = new(Completed: recovery.Completed + 1, LastCompleted: time.GetUtcNow(), Errors: 1);
            ReportProblem("The watched folder could not be fully rechecked. Review its location and run a manual scan.");
        }
        finally { lock (gate) { recovery = recovery with { Scanning = false }; recoveryFinished = time.GetTimestamp(); } }
    }
    private async Task ProcessFile(string path)
    {
        long version, wait;
        lock (gate)
        {
            if (!pending.TryGetValue(path, out var item)) return;
            version = item.Version; wait = Math.Max(0, 500 - (Environment.TickCount64 - item.ChangedAt));
        }
        if (wait > 0) await Task.Delay((int)wait, stop.Token);
        lock (gate)
        {
            if (!pending.TryGetValue(path, out var item)) return;
            if (Environment.TickCount64 - item.ChangedAt < 500) { Requeue(path); return; }
            version = item.Version;
        }
        try
        {
            if (Directory.Exists(path)) { RequestRecovery(); return; }
            if (!File.Exists(path)) return;
            var result = await scanner().ScanFileDetailedAsync(path, stop.Token);
            if (result.File.Verdict == FileVerdict.Error)
            {
                await Task.Delay(1_000, stop.Token);
                result = await scanner().ScanFileDetailedAsync(path, stop.Token);
            }
            stop.Token.ThrowIfCancellationRequested();
            var completed = Interlocked.Increment(ref scans);
            Deliver(result.File); await DeliverFindings(result.ArchiveFindings);
            if (completed % 32 == 0) await Task.Delay(20, stop.Token);
        }
        finally
        {
            lock (gate)
            {
                if (pending.TryGetValue(path, out var item))
                {
                    if (item.Version != version) Requeue(path); else pending.Remove(path);
                }
            }
        }
    }
    private async Task Work()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var recover = false; TimeSpan? wait = null;
                lock (gate)
                {
                    if (recoveryRequested)
                    {
                        wait = recoveryFinished is { } finished ? TimeSpan.FromSeconds(30) - time.GetElapsedTime(finished) : TimeSpan.Zero;
                        if (wait <= TimeSpan.Zero) { recoveryRequested = false; recovery = recovery with { Scanning = true }; recover = true; }
                    }
                }
                if (recover) { await Recover(); continue; }
                if (queue.Reader.TryRead(out var item))
                {
                    if (item.Path is not null) await ProcessFile(item.Path);
                    else { lock (gate) wakeQueued = false; }
                    continue;
                }
                // A single cancellable wait replaces polling and does not leave orphaned
                // channel readers when a cooldown expires or the monitor is disposed.
                using var wake = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
                if (wait is { } duration) wake.CancelAfter(duration);
                try { if (!await queue.Reader.WaitToReadAsync(wake.Token)) break; }
                catch (OperationCanceledException) when (!stop.IsCancellationRequested && wake.IsCancellationRequested) { }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception) { ReportProblem("Folder monitoring stopped unexpectedly. Restart monitoring and run a manual scan."); }
        finally { Volatile.Write(ref running, 0); lock (gate) { recoveryRequested = false; recovery = recovery with { Scanning = false }; } }
    }
    public ValueTask DisposeAsync() { lock (gate) return new(disposal ??= DisposeCore()); }
    private async Task DisposeCore()
    {
        Volatile.Write(ref running, 0); watcher.EnableRaisingEvents = false; watcher.Dispose(); queue.Writer.TryComplete(); stop.Cancel();
        await worker; lock (gate) { pending.Clear(); while (queue.Reader.TryRead(out _)) { } } stop.Dispose();
    }
}
