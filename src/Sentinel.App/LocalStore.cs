using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Core.Protection;

namespace Sentinel.App;

internal static class LocalStore
{
    private static string? temporaryRoot;
    private static string DefaultRoot => InstallationLease.CurrentProfile;
    public static string Root => temporaryRoot ?? DefaultRoot;
    // Only the friend test assembly uses this before creating a window. There is no
    // environment variable or product command-line option that redirects a profile.
    internal static IDisposable UseTemporaryProfile(string directory)
    {
        if (temporaryRoot is not null || System.Windows.Application.Current?.Windows.Count > 0)
            throw new InvalidOperationException("Choose the temporary profile before creating a window.");
        directory = FileSafety.NormalizeRegularPath(directory);
        if (!Directory.Exists(directory) || FolderMonitor.IsWithin(directory, DefaultRoot) || FolderMonitor.IsWithin(DefaultRoot, directory))
            throw new ArgumentException("Use a separate temporary folder for UI verification.");
        temporaryRoot = directory;
        return new TemporaryProfile();
    }
    private sealed class TemporaryProfile : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            if (disposed) return;
            if (System.Windows.Application.Current?.Windows.Count > 0) throw new InvalidOperationException("Close the verification window before releasing its profile.");
            temporaryRoot = null; disposed = true;
        }
    }
    public static ProtectionPreferences LoadPreferences() => ProtectionPreferencesStore.Load(Path.Combine(Root, "protection-preferences.json"));
    public static void SavePreferences(ProtectionPreferences preferences) => ProtectionPreferencesStore.Save(Path.Combine(Root, "protection-preferences.json"), preferences);
    public static ProtectionSettings LoadProtection() { var path = Path.Combine(Root, "protection.json"); return File.Exists(path) ? JsonSerializer.Deserialize<ProtectionSettings>(File.ReadAllText(path)) ?? new() : new(); }
    public static void SaveProtection(ProtectionSettings settings) { Directory.CreateDirectory(Root); AtomicWrite(Path.Combine(Root, "protection.json"), JsonSerializer.SerializeToUtf8Bytes(settings)); }
    internal static byte[] ProtectKey(byte[] key) => Protect(key, true);
    internal static byte[] UnprotectKey(byte[] key) => Protect(key, false);
    private static string SettingsFile => Path.Combine(Root, "settings.json");
    private static string KeyFile => Path.Combine(Root, "provider.dpapi");
    public static AiSettings LoadSettings() => File.Exists(SettingsFile) ? JsonSerializer.Deserialize<AiSettings>(File.ReadAllText(SettingsFile)) ?? new() : new();
    public static void Save(AiSettings settings, string key)
    {
        Directory.CreateDirectory(Root);
        // Protect first: failure must not result in plaintext credentials.
        var protectedKey = string.IsNullOrEmpty(key) ? null : Protect(Encoding.UTF8.GetBytes(key), encrypt: true);
        if (protectedKey is not null) AtomicWrite(KeyFile, protectedKey);
        else if (File.Exists(KeyFile)) File.Delete(KeyFile);
        AtomicWrite(SettingsFile, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true })));
    }
    public static string LoadKey() => File.Exists(KeyFile) ? Encoding.UTF8.GetString(Protect(File.ReadAllBytes(KeyFile), encrypt: false)) : "";
    public sealed record DecisionConnection(DecisionSettings Settings, string Key);
    private static string DecisionFile => Path.Combine(Root, "decision-connection.dpapi");
    public static DecisionConnection LoadDecision()
    {
        if (!File.Exists(DecisionFile)) return new(new(), "");
        var path = FileSafety.NormalizeRegularPath(DecisionFile);
        if (new FileInfo(path).Length > 64 * 1024) throw new InvalidDataException("Saved Jev connection exceeded its size limit.");
        var bytes = Protect(File.ReadAllBytes(path), false);
        try
        {
            var value = JsonSerializer.Deserialize<DecisionConnection>(bytes) ?? throw new InvalidDataException("Invalid Jev connection.");
            if (value.Settings is null || value.Key is null || value.Key.Length > 8192 || value.Key.Any(char.IsWhiteSpace) || value.Key.Any(char.IsControl)) throw new InvalidDataException("Invalid Jev connection.");
            value.Settings.Validate(); return value;
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
    public static void SaveDecision(DecisionSettings settings, string key)
    {
        settings.Validate();
        if (key.Length > 8192 || key.Any(char.IsWhiteSpace) || key.Any(char.IsControl)) throw new ArgumentException("Paste only the decision provider key.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new DecisionConnection(settings, key));
        try { AtomicWrite(DecisionFile, Protect(bytes, true)); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void AtomicWrite(string path, byte[] bytes)
    {
        FileSafety.EnsureDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path)) _ = FileSafety.NormalizeRegularPath(path);
        var temporary = Path.Combine(Path.GetDirectoryName(path)!, ".sentinel-state-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { stream.Write(bytes); stream.Flush(flushToDisk: true); }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public static void Audit(AuditEvent entry)
    {
        Directory.CreateDirectory(Root);
        var path = Path.Combine(Root, "activity.jsonl");
        if (File.Exists(path) && new FileInfo(path).Length > 512 * 1024) File.Move(path, path + ".previous", overwrite: true);
        File.AppendAllText(path, JsonSerializer.Serialize(entry) + Environment.NewLine);
    }
    public static IReadOnlyList<AuditEvent> ReadAudit()
    {
        var path = Path.Combine(Root, "activity.jsonl");
        if (!File.Exists(path)) return [];
        return File.ReadLines(path).Reverse().Take(200).Select(line => { try { return JsonSerializer.Deserialize<AuditEvent>(line); } catch (JsonException) { return null; } }).OfType<AuditEvent>().ToList();
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    private static byte[] Protect(byte[] bytes, bool encrypt)
    {
        var input = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            Blob output;
            var ok = encrypt ? CryptProtectData(ref input, "Sentinel provider credential", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output) : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Windows could not protect or unlock the API key.");
            try { var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { LocalFree(output.Data); }
        }
        finally { for (var i = 0; i < bytes.Length; i++) Marshal.WriteByte(input.Data, i, 0); Marshal.FreeHGlobal(input.Data); }
    }
}

internal sealed class WindowsVaultKeyProtector : IKeyProtector
{
    public byte[] Protect(byte[] key) => LocalStore.ProtectKey(key);
    public byte[] Unprotect(byte[] wrapped) => LocalStore.UnprotectKey(wrapped);
}
