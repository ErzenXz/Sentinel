using System.Threading.Channels;

namespace Sentinel.Core.Protection;

// Best-effort user-mode monitoring after writes; this is not a pre-execution gate.
public sealed class FolderMonitor : IAsyncDisposable
{
    private sealed class Pending { public long Version; public long ChangedAt; }
    private readonly object gate = new();
    private readonly FileSystemWatcher watcher;
    private readonly Channel<string> queue = Channel.CreateBounded<string>(new BoundedChannelOptions(512) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly Dictionary<string, Pending> pending = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    private readonly string[] excluded;
    private readonly CancellationTokenSource stop = new();
    private readonly Func<FileScanner> scanner;
    private readonly Action<FileFinding> finding;
    private readonly Action<string> problem;
    private readonly Task worker;
    private Task? disposal;
    private int dropped, running = 1, scans;
    private long changed;
    public bool IsRunning => Volatile.Read(ref running) == 1;
    public int DroppedEvents => Volatile.Read(ref dropped);
    public int CompletedScans => Volatile.Read(ref scans);
    public long ObservedChanges => Interlocked.Read(ref changed);
    public int PendingFiles { get { lock (gate) return pending.Count; } }
    public FolderMonitor(string directory, Func<FileScanner> scanner, Action<FileFinding> finding, Action<string> problem, IEnumerable<string>? excludedDirectories = null)
    {
        directory = FileSafety.NormalizeRegularPath(directory);
        if (!Directory.Exists(directory)) throw new ArgumentException("Choose a folder to monitor.");
        this.scanner = scanner; this.finding = finding; this.problem = problem;
        excluded = (excludedDirectories ?? []).Select(Path.GetFullPath).ToArray();
        watcher = new(directory) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size, InternalBufferSize = 16 * 1024 };
        watcher.Created += (_, e) => Enqueue(e.FullPath);
        watcher.Changed += (_, e) => Enqueue(e.FullPath);
        watcher.Renamed += (_, e) => Enqueue(e.FullPath);
        watcher.Error += (_, _) => Lost("The folder watcher lost events. Run a full Sentinel scan of this folder.");
        worker = Task.Run(Work);
        watcher.EnableRaisingEvents = true;
    }
    public static bool IsWithin(string path, string directory)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)); path = Path.GetFullPath(path);
        return path.Equals(directory, comparison) || path.StartsWith(Path.EndsInDirectorySeparator(directory) ? directory : directory + Path.DirectorySeparatorChar, comparison);
    }
    private void Lost(string message) { Interlocked.Increment(ref dropped); try { problem(message); } catch { /* A notification must not crash watcher callbacks. */ } }
    private void Enqueue(string path)
    {
        if (!IsRunning || excluded.Any(root => IsWithin(path, root))) return;
        Interlocked.Increment(ref changed);
        var lost = false;
        lock (gate)
        {
            if (!IsRunning) return;
            if (pending.TryGetValue(path, out var current)) { current.Version++; current.ChangedAt = Environment.TickCount64; return; }
            // The in-flight path and queued paths share one bounded dictionary.
            if (pending.Count >= 512) lost = true;
            else
            {
                pending.Add(path, new() { Version = 1, ChangedAt = Environment.TickCount64 });
                if (!queue.Writer.TryWrite(path)) { pending.Remove(path); lost = true; }
            }
        }
        if (lost) Lost("The folder scan queue is full. Some changes were missed; scan this folder manually.");
    }
    private bool Requeue(string path)
    {
        if (IsRunning && queue.Writer.TryWrite(path)) return true;
        pending.Remove(path); return false;
    }
    private async Task Work()
    {
        try
        {
            await foreach (var path in queue.Reader.ReadAllAsync(stop.Token))
            {
                long version, wait;
                lock (gate)
                {
                    if (!pending.TryGetValue(path, out var item)) continue;
                    version = item.Version; wait = Math.Max(0, 500 - (Environment.TickCount64 - item.ChangedAt));
                }
                if (wait > 0) await Task.Delay((int)wait, stop.Token);
                lock (gate)
                {
                    if (!pending.TryGetValue(path, out var item)) continue;
                    if (Environment.TickCount64 - item.ChangedAt < 500) { Requeue(path); continue; }
                    version = item.Version;
                }
                try
                {
                    if (Directory.Exists(path)) { Lost("A folder was created or renamed. Scan it manually to cover files already inside it."); continue; }
                    if (!File.Exists(path)) continue;
                    var result = await scanner().ScanFileDetailedAsync(path, stop.Token);
                    if (result.File.Verdict == FileVerdict.Error)
                    {
                        await Task.Delay(1_000, stop.Token);
                        result = await scanner().ScanFileDetailedAsync(path, stop.Token);
                    }
                    stop.Token.ThrowIfCancellationRequested();
                    Interlocked.Increment(ref scans);
                    foreach (var item in result.ArchiveFindings.Prepend(result.File)) if (item.Verdict != FileVerdict.NoKnownMatch) finding(item);
                }
                finally
                {
                    lock (gate)
                    {
                        if (pending.TryGetValue(path, out var item))
                        {
                            // A rewrite during the scan is queued again, never erased by completion of an older generation.
                            if (item.Version != version) Requeue(path); else pending.Remove(path);
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception ex) { Volatile.Write(ref running, 0); Lost("Folder monitoring stopped: " + ex.Message); }
        finally { Volatile.Write(ref running, 0); }
    }
    public ValueTask DisposeAsync()
    {
        lock (gate) return new(disposal ??= DisposeCore());
    }
    private async Task DisposeCore()
    {
        Volatile.Write(ref running, 0); watcher.EnableRaisingEvents = false; watcher.Dispose(); queue.Writer.TryComplete(); stop.Cancel();
        await worker; lock (gate) pending.Clear(); stop.Dispose();
    }
}
