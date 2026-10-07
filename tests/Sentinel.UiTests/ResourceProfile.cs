using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Sentinel.App;

internal static partial class Program
{
    private static async Task ProfileResources(MainWindow window)
    {
        Stage("Profiling visible fixture before additional bitmap captures");
        await Navigate(window, "Home"); await SetSize(window, 1200, 820);
        await SampleResources(window, "visible-before-capture-burst");
        for (var i = 0; i < 27; i++) Capture(window, "profile-capture-" + i, false);
        await SampleResources(window, "visible-after-27-bitmap-captures");
        window.Hide();
        await SampleResources(window, "hidden-after-captures");
        window.Show(); await Until(() => !Field<bool>(window, "busy"), "Fixture refresh after showing did not settle");
        await SampleResources(window, "visible-after-showing");
    }

    private static async Task SampleResources(MainWindow window, string phase)
    {
        await Task.Delay(2000); await Drain();
        using var process = Process.GetCurrentProcess();
        var modules = process.Modules.Cast<ProcessModule>().Select(m => new ModuleRange(m.ModuleName, (ulong)m.BaseAddress.ToInt64(), m.ModuleMemorySize)).ToArray();
        var beforeThreads = Threads(process, modules);
        process.Refresh(); var beforeCpu = process.TotalProcessorTime; var start = Stopwatch.GetTimestamp();
        var dispatches = new long[16];
        DispatcherHookEventHandler dispatch = (_, e) => { var p = (int)e.Operation.Priority; if (p >= 0 && p < dispatches.Length) dispatches[p]++; };
        window.Dispatcher.Hooks.OperationStarted += dispatch;
        try { await Task.Delay(5000); }
        finally { window.Dispatcher.Hooks.OperationStarted -= dispatch; }
        process.Refresh(); var seconds = Stopwatch.GetElapsedTime(start).TotalSeconds; var cpu = (process.TotalProcessorTime - beforeCpu).TotalMilliseconds;
        var afterThreads = Threads(process, modules);
        var top = afterThreads.Values.Where(t => beforeThreads.ContainsKey(t.Id))
            .Select(t => new { t.Id, t.Name, t.StartModule, cpuMilliseconds = Math.Max(0, t.CpuMilliseconds - beforeThreads[t.Id].CpuMilliseconds) })
            .OrderByDescending(t => t.cpuMilliseconds).Take(12).ToArray();
        var sample = new { phase, seconds, cpuMilliseconds = cpu, windowVisible = window.IsVisible,
            description = "Five-second fixture process/thread CPU sample after two seconds settling. Injected status reads; no monitoring, Defender work, AI, driver or real-user workload. Forced software/default rendering preference is recorded separately.",
            processId = process.Id, renderingTier = RenderCapability.Tier >> 16, softwarePreference = RenderOptions.ProcessRenderMode.ToString(),
            workingSetBytes = process.WorkingSet64, privateBytes = process.PrivateMemorySize64, managedBytes = GC.GetTotalMemory(false),
            trackedThreadCpuMilliseconds = top.Sum(t => t.cpuMilliseconds), topThreads = top,
            dispatcherOperations = dispatches.Select((count, p) => new { priority = ((DispatcherPriority)p).ToString(), count }).Where(x => x.count > 0).ToArray() };
        resourceSamples.Add(sample);
        Stage($"Resource phase {phase}: {cpu:F1} ms process CPU / {seconds:F2}s; hottest thread {top.FirstOrDefault()?.Name}");
    }

    private sealed record ModuleRange(string Name, ulong Start, int Bytes);
    private sealed record ThreadSample(int Id, string Name, string StartModule, double CpuMilliseconds);
    private static Dictionary<int, ThreadSample> Threads(Process process, ModuleRange[] modules)
    {
        var result = new Dictionary<int, ThreadSample>();
        foreach (ProcessThread thread in process.Threads.Cast<ProcessThread>().Take(512))
        {
            using (thread)
            {
                try
                {
                    var handle = OpenThread(0x0840, false, (uint)thread.Id); // Read-only query rights on this fixture process's threads.
                    string name = "unavailable", module = "unavailable";
                    if (handle != IntPtr.Zero)
                    {
                        try
                        {
                            if (GetThreadDescription(handle, out var description) == 0 && description != IntPtr.Zero)
                            {
                                try { name = Marshal.PtrToStringUni(description) ?? "unnamed"; if (name.Length == 0) name = "unnamed"; }
                                finally { LocalFree(description); }
                            }
                            if (NtQueryInformationThread(handle, 9, out var address, IntPtr.Size, IntPtr.Zero) == 0)
                            {
                                var value = (ulong)address.ToInt64();
                                module = modules.FirstOrDefault(m => value >= m.Start && value - m.Start < (ulong)m.Bytes)?.Name ?? "unmapped";
                            }
                        }
                        finally { CloseHandle(handle); }
                    }
                    result[thread.Id] = new(thread.Id, name, module, thread.TotalProcessorTime.TotalMilliseconds);
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
        return result;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenThread(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint id);
    [DllImport("kernel32.dll")] private static extern int GetThreadDescription(IntPtr thread, out IntPtr description);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationThread(IntPtr thread, int informationClass, out IntPtr value, int length, IntPtr returnLength);
}
