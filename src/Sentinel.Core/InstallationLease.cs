using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core;

// Cooperative install/remove guard, not tamper protection. The process keeps its
// marker until exit; no worker, polling, or elevated service is added.
public static class InstallationLease
{
    private static readonly object Gate = new();
    private static Mutex? running;
    public static string CurrentProfile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel");
    public static string ProfileKey(string profile) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(profile))).ToLowerInvariant();
    public static string RunningName(string profile) => @"Global\Sentinel.Run.v1." + ProfileKey(profile);
    public static string SetupName(string profile) => @"Global\Sentinel.Setup.v1." + ProfileKey(profile);
    public static void EnsureHeld()
    {
        if (!OperatingSystem.IsWindows()) return;
        lock (Gate)
        {
            if (running is not null) return;
            // Presence serializes startup against SetupMutex. Create the running
            // marker before releasing this short startup guard.
            using var transition = new Mutex(false, SetupName(CurrentProfile), out var created);
            if (!created) throw new InvalidOperationException("Sentinel is being installed or removed. Wait for that operation to finish, then open it again.");
            running = new Mutex(false, RunningName(CurrentProfile));
        }
    }
}
