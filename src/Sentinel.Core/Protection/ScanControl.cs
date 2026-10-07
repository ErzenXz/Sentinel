namespace Sentinel.Core.Protection;

public enum ScanMode { Balanced, LowImpact }

// One control per scan worker. Pausing waits on a signal rather than polling or spinning.
// A pause is cooperative: an in-flight filesystem read can finish before the next checkpoint.
public sealed class ScanControl
{
    private TaskCompletionSource? paused;
    private long pacedBytes;
    private int pacedFiles;
    public ScanMode Mode { get; }
    public bool IsPaused => Volatile.Read(ref paused) is not null;
    public ScanControl(ScanMode mode = ScanMode.Balanced)
    {
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        Mode = mode;
    }
    public bool Pause() => Interlocked.CompareExchange(ref paused, new(TaskCreationOptions.RunContinuationsAsynchronously), null) is null;
    public bool Resume()
    {
        var wait = Interlocked.Exchange(ref paused, null);
        if (wait is null) return false;
        wait.TrySetResult(); return true;
    }
    internal ValueTask CheckpointAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var wait = Volatile.Read(ref paused);
        return wait is null ? ValueTask.CompletedTask : new(wait.Task.WaitAsync(token));
    }
    internal ValueTask ReadCompletedAsync(int bytes, CancellationToken token)
    {
        if (Mode != ScanMode.LowImpact) return ValueTask.CompletedTask;
        pacedBytes += bytes;
        if (pacedBytes < 4 * 1024 * 1024) return ValueTask.CompletedTask;
        pacedBytes %= 4 * 1024 * 1024;
        return new(Task.Delay(20, token));
    }
    internal ValueTask FileCompletedAsync(CancellationToken token)
    {
        if (Mode != ScanMode.LowImpact || ++pacedFiles < 32) return ValueTask.CompletedTask;
        pacedFiles = 0; return new(Task.Delay(20, token));
    }
}
