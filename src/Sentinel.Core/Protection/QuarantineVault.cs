using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Core.Protection;

public interface IKeyProtector { byte[] Protect(byte[] key); byte[] Unprotect(byte[] wrapped); }
public sealed record QuarantineEntry(string Id, string OriginalPath, string Reason, string Sha256, long Bytes, DateTimeOffset Time, bool SourceRemoved);
internal sealed record VaultMetadata(string OriginalPath, string Reason, string Sha256, long Bytes, DateTimeOffset Time);

// Chunked authenticated encryption keeps working memory bounded independently of file size.
// On Windows removal is requested against the still-open, exclusively locked source handle.
public sealed class QuarantineVault(string directory, IKeyProtector protector)
{
    private const int ChunkSize = 64 * 1024;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SNTLVLT2");
    private readonly SemaphoreSlim gate = new(1, 1);
    private string EntryPath(string id, string extension)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("Invalid quarantine item.");
        return Path.Combine(directory, id + extension);
    }
    private void Prepare()
    {
        Directory.CreateDirectory(directory);
        _ = FileSafety.NormalizeRegularPath(Path.GetFullPath(directory));
    }
    public IReadOnlyList<QuarantineEntry> List()
    {
        Prepare(); var result = new List<QuarantineEntry>();
        foreach (var path in Directory.EnumerateFiles(directory, "*.json").Take(2_000))
        {
            try
            {
                _ = FileSafety.NormalizeRegularPath(path);
                var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllBytes(path));
                if (entry is not null && Path.GetFileNameWithoutExtension(path) == entry.Id && File.Exists(EntryPath(entry.Id, ".vault"))) result.Add(entry);
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException or ArgumentException) { }
        }
        return result.OrderByDescending(x => x.Time).ToList();
    }
    public async Task<QuarantineEntry> QuarantineAsync(FileFinding finding, CancellationToken token = default)
    {
        if (finding.ArchiveEntry is not null) throw new ArgumentException("Archive detections require explicit container confirmation and a fresh container hash.");
        if (finding.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile) || !FeedVerifier.IsHash(finding.Sha256)) throw new ArgumentException("Only an exact threat/test detection can be quarantined. Review-only findings cannot be removed.");
        await gate.WaitAsync(token);
        try
        {
            Prepare();
            var path = FileSafety.NormalizeRegularPath(finding.Path);
            var id = Guid.NewGuid().ToString("N"); var temporary = EntryPath(id, ".pending"); var vaultPath = EntryPath(id, ".vault");
            var key = RandomNumberGenerator.GetBytes(32); var committed = false;
            try
            {
                // FileShare.None blocks new opens, writes and renames on Windows while we create the backup.
                using var input = OpenSource(path);
                var length = input.Length;
                if (length != finding.Bytes || length > 256L * 1024 * 1024) throw new IOException("The file changed or is too large. Scan it again before quarantine.");
                var metadata = new VaultMetadata(path, finding.Reason, finding.Sha256!, length, DateTimeOffset.UtcNow);
                await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, ChunkSize, FileOptions.Asynchronous))
                {
                    await output.WriteAsync(Magic, token);
                    using var aes = new AesGcm(key, 16);
                    await WriteRecord(output, aes, id, 0, JsonSerializer.SerializeToUtf8Bytes(metadata), token);
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[ChunkSize]; ulong index = 1; long total = 0; int count;
                    while ((count = await input.ReadAsync(buffer, token)) > 0)
                    {
                        total += count; if (total > length) throw new IOException("File changed during quarantine.");
                        hash.AppendData(buffer, 0, count);
                        await WriteRecord(output, aes, id, index++, buffer.AsMemory(0, count), token);
                    }
                    if (total != length || !Convert.ToHexString(hash.GetHashAndReset()).Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)) throw new IOException("File content changed after detection. The original was retained.");
                    await WriteRecord(output, aes, id, index, ReadOnlyMemory<byte>.Empty, token);
                    await output.FlushAsync(token); output.Flush(flushToDisk: true);
                    CryptographicOperations.ZeroMemory(buffer);
                }
                token.ThrowIfCancellationRequested();
                WriteDurable(EntryPath(id, ".key"), protector.Protect(key));
                File.Move(temporary, vaultPath);
                var entry = new QuarantineEntry(id, path, finding.Reason, finding.Sha256!, length, metadata.Time, false);
                WriteIndex(entry); committed = true;
                // The recoverable authenticated backup is on disk before removal. Cancellation is no longer honored during this commit.
                if (OperatingSystem.IsWindows())
                {
                    var disposition = new Disposition { Delete = true };
                    if (!SetFileInformationByHandle(input.SafeFileHandle, 4, ref disposition, 1)) throw new IOException("Encrypted backup saved, but Windows refused to remove the original. The source is still present.", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
                }
                else File.Delete(path); // Portable tests only; Windows is the supported quarantine platform.
                input.Dispose();
                entry = entry with { SourceRemoved = true };
                WriteIndex(entry);
                return entry;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                if (File.Exists(temporary)) File.Delete(temporary);
                if (!committed) { if (File.Exists(EntryPath(id, ".key"))) File.Delete(EntryPath(id, ".key")); if (File.Exists(vaultPath)) File.Delete(vaultPath); }
            }
        }
        finally { gate.Release(); }
    }
    private static void WriteDurable(string path, byte[] bytes)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        file.Write(bytes); file.Flush(flushToDisk: true);
    }
    private void WriteIndex(QuarantineEntry entry)
    {
        var path = EntryPath(entry.Id, ".json"); WriteDurable(path + ".tmp", JsonSerializer.SerializeToUtf8Bytes(entry)); File.Move(path + ".tmp", path, overwrite: true);
    }
    public async Task RestoreAsync(string id, string destination, CancellationToken token = default)
    {
        await gate.WaitAsync(token);
        try
        {
            Prepare();
            if (!Path.IsPathFullyQualified(destination) || File.Exists(destination) || Directory.Exists(destination)) throw new IOException("Choose a new absolute file path. Existing files are never overwritten.");
            destination = FileSafety.NormalizeLocalPath(destination);
            var parent = Path.GetDirectoryName(destination) ?? throw new ArgumentException("Missing destination directory.");
            _ = FileSafety.NormalizeRegularPath(parent);
            var staged = Path.Combine(parent, ".sentinel-restore-" + Guid.NewGuid().ToString("N") + ".tmp");
            var key = protector.Unprotect(File.ReadAllBytes(FileSafety.NormalizeRegularPath(EntryPath(id, ".key"))));
            try
            {
                await using var input = new FileStream(FileSafety.NormalizeRegularPath(EntryPath(id, ".vault")), FileMode.Open, FileAccess.Read, FileShare.Read, ChunkSize, FileOptions.Asynchronous);
                var magic = new byte[8]; await input.ReadExactlyAsync(magic, token); if (!magic.AsSpan().SequenceEqual(Magic)) throw new InvalidDataException("Invalid quarantine format.");
                using var aes = new AesGcm(key, 16);
                var metadataBytes = await ReadRecord(input, aes, id, 0, token);
                var metadata = JsonSerializer.Deserialize<VaultMetadata>(metadataBytes) ?? throw new InvalidDataException("Invalid quarantine metadata.");
                if (!FeedVerifier.IsHash(metadata.Sha256) || metadata.Bytes < 0 || metadata.Bytes > 256L * 1024 * 1024) throw new InvalidDataException("Invalid quarantine file size or hash.");
                await using (var output = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, ChunkSize, FileOptions.Asynchronous))
                {
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); long total = 0; ulong index = 1;
                    while (true)
                    {
                        var data = await ReadRecord(input, aes, id, index++, token);
                        if (data.Length == 0) break;
                        total += data.Length; if (total > metadata.Bytes) throw new InvalidDataException("Quarantine data exceeds its authenticated size.");
                        hash.AppendData(data); await output.WriteAsync(data, token); CryptographicOperations.ZeroMemory(data);
                    }
                    if (input.Position != input.Length || total != metadata.Bytes || !Convert.ToHexString(hash.GetHashAndReset()).Equals(metadata.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Quarantine integrity check failed.");
                    await output.FlushAsync(token); output.Flush(flushToDisk: true);
                }
                token.ThrowIfCancellationRequested();
                File.Move(staged, destination, overwrite: false);
                // Retain the encrypted backup until the user explicitly deletes it.
            }
            finally { CryptographicOperations.ZeroMemory(key); if (File.Exists(staged)) File.Delete(staged); }
        }
        finally { gate.Release(); }
    }
    public void Delete(string id)
    {
        Prepare();
        foreach (var extension in new[] { ".vault", ".key", ".json" }) { var path = EntryPath(id, extension); if (File.Exists(path)) { _ = FileSafety.NormalizeRegularPath(path); File.Delete(path); } }
    }
    private static byte[] Aad(string id, ulong index, int length)
    {
        var aad = new byte[28]; Guid.ParseExact(id, "N").TryWriteBytes(aad); BinaryPrimitives.WriteUInt64LittleEndian(aad.AsSpan(16), index); BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(24), length); return aad;
    }
    private static async Task WriteRecord(Stream output, AesGcm aes, string id, ulong index, ReadOnlyMemory<byte> plaintext, CancellationToken token)
    {
        if (plaintext.Length > ChunkSize) throw new InvalidDataException("Quarantine record too large.");
        var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16]; var encrypted = new byte[plaintext.Length];
        aes.Encrypt(nonce, plaintext.Span, encrypted, tag, Aad(id, index, plaintext.Length));
        var size = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(size, plaintext.Length);
        await output.WriteAsync(size, token); await output.WriteAsync(nonce, token); await output.WriteAsync(tag, token); await output.WriteAsync(encrypted, token);
    }
    private static async Task<byte[]> ReadRecord(Stream input, AesGcm aes, string id, ulong index, CancellationToken token)
    {
        var size = new byte[4]; await input.ReadExactlyAsync(size, token); var length = BinaryPrimitives.ReadInt32LittleEndian(size);
        if (length < 0 || length > ChunkSize) throw new InvalidDataException("Invalid quarantine record size.");
        var nonce = new byte[12]; var tag = new byte[16]; var encrypted = new byte[length]; var plaintext = new byte[length];
        await input.ReadExactlyAsync(nonce, token); await input.ReadExactlyAsync(tag, token); await input.ReadExactlyAsync(encrypted, token);
        aes.Decrypt(nonce, encrypted, tag, plaintext, Aad(id, index, length)); return plaintext;
    }
    private static FileStream OpenSource(string path)
    {
        if (!OperatingSystem.IsWindows()) return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, ChunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        // DELETE access is needed for disposition by handle; plain FileAccess.Read is insufficient.
        var handle = CreateFile(path, 0x80010000, 0, IntPtr.Zero, 3, 0x48200080, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Windows could not lock this file for quarantine."); }
        if (!GetFileInformationByHandleEx(handle, 9, out var attributes, 8) || (attributes.Attributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
        { handle.Dispose(); throw new IOException("The source is not a regular file."); }
        try { return new FileStream(handle, FileAccess.Read, ChunkSize, isAsync: true); }
        catch { handle.Dispose(); throw; }
    }
    [StructLayout(LayoutKind.Sequential)] private struct AttributeTag { public uint Attributes; public uint Tag; }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, out AttributeTag info, uint size);
    [StructLayout(LayoutKind.Sequential)] private struct Disposition { [MarshalAs(UnmanagedType.U1)] public bool Delete; }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, ref Disposition info, uint size);
}
