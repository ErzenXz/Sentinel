using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sentinel.App;

// One interactive instance per profile/session. The only IPC message is "show the window".
internal sealed class ProfileInstance : IDisposable
{
    private readonly Mutex mutex = new(false, @"Local\Sentinel-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(LocalStore.Root)))[..24]);
    private bool acquired;
    public static uint ActivationMessage { get; } = RegisterWindowMessage("Sentinel.ShowWindow.v1");
    public bool Acquire(bool waitForPrevious)
    {
        try { acquired = mutex.WaitOne(waitForPrevious ? TimeSpan.FromSeconds(8) : TimeSpan.Zero); }
        catch (AbandonedMutexException) { acquired = true; }
        return acquired;
    }
    public static bool ActivateExisting()
    {
        if (ActivationMessage == 0) return false;
        using var current = Process.GetCurrentProcess();
        var targets = new HashSet<int>();
        foreach (var candidate in Process.GetProcessesByName(current.ProcessName))
        {
            using (candidate)
            {
                try { if (candidate.Id != current.Id && candidate.SessionId == current.SessionId && string.Equals(candidate.MainModule?.FileName, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)) targets.Add(candidate.Id); }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
        var found = false; var attempts = 0;
        EnumWindows((window, _) => {
            GetWindowThreadProcessId(window, out var id);
            if (targets.Contains((int)id)) { attempts++; if (SendMessageTimeout(window, ActivationMessage, IntPtr.Zero, IntPtr.Zero, 2, 200, out _) != IntPtr.Zero) found = true; }
            return !found && attempts < 8;
        }, IntPtr.Zero);
        return found;
    }
    public void Dispose() { if (acquired) { mutex.ReleaseMutex(); acquired = false; } mutex.Dispose(); }
    private delegate bool EnumWindowsCallback(IntPtr window, IntPtr parameter);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegisterWindowMessageW")] private static extern uint RegisterWindowMessage(string message);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr parameter);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint id);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "SendMessageTimeoutW")] private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr wParam, IntPtr lParam, uint flags, uint timeout, out IntPtr result);
}
