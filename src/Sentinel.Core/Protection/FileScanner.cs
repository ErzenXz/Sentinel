using System.Security.Cryptography;
using System.Buffers;
using System.Text;
using System.Text.Json.Serialization;
using System.IO.Enumeration;

namespace Sentinel.Core.Protection;

public enum FileVerdict { NoKnownMatch, KnownThreat, TestFile, NeedsReview, Skipped, Error }
public sealed record FileFinding(string Path, FileVerdict Verdict, string Reason, string? Sha256 = null, long Bytes = 0,
    string? ArchiveEntry = null, string? ContainerSha256 = null)
{
    // Path always names the actual filesystem file. ArchiveEntry is display-only, never an extraction destination.
    [JsonIgnore] public string DisplayPath => ArchiveEntry is null ? Path : $"{Path} → {ArchiveEntry}";
}
public sealed record FileScanResult(FileFinding File, IReadOnlyList<FileFinding> ArchiveFindings, int ArchiveEntries, long ArchiveBytesRead, bool Canceled = false);
public sealed record ScanProgress(int Scanned, int Detected, int Review, int Skipped, int Errors, string CurrentFile);
public sealed record ScanReport(DateTimeOffset StartedAt, TimeSpan Duration, int Scanned, int Detected, int Review, int Skipped, int Errors,
    bool LimitReached, bool FindingsTruncated, long BytesRead, long? FeedSequence, bool FeedStale, IReadOnlyList<FileFinding> Findings,
    bool Canceled = false, int ArchiveEntries = 0, long ArchiveBytesRead = 0, ScanMode Mode = ScanMode.Balanced, int PeakPendingDirectories = 0)
{
    [JsonIgnore] public bool Incomplete => Canceled || LimitReached || FindingsTruncated || Skipped > 0 || Errors > 0;
}
public sealed record ScanLimits(long MaxFileBytes = 256L * 1024 * 1024, int MaxFiles = 50_000, int MaxFindings = 2_000, int MaxArchiveEntries = 2_048,
    long MaxArchiveEntryBytes = 32L * 1024 * 1024, long MaxArchiveExpandedBytes = 128L * 1024 * 1024,
    long MaxNestedArchiveBytes = 16L * 1024 * 1024, int MaxArchiveDepth = 2, int MaxCompressionRatio = 200);

public static class FileSafety
{
    internal static string[] NormalizeExclusions(IEnumerable<string>? directories)
    {
        var result = (directories ?? []).Take(33).Select(path => Path.TrimEndingDirectorySeparator(NormalizeLocalPath(path))).ToArray();
        if (result.Length > 32) throw new ArgumentException("At most 32 excluded folders are supported.");
        return result;
    }
    internal static bool IsWithinNormalized(string path, string directory)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return path.Equals(directory, comparison) || path.Length > directory.Length && path.StartsWith(directory, comparison)
            && (Path.EndsInDirectorySeparator(directory) || path[directory.Length] == Path.DirectorySeparatorChar);
    }
    internal static bool IsExcluded(string path, string[] directories)
    {
        foreach (var directory in directories) if (IsWithinNormalized(path, directory)) return true;
        return false;
    }
    public static string NormalizeLocalPath(string path)
    {
        if (!System.IO.Path.IsPathFullyQualified(path)) throw new ArgumentException("Choose an absolute local path.");
        var full = System.IO.Path.GetFullPath(path);
        // Avoid UNC/device namespaces and ADS paths. The scanner is limited to local regular files.
        if (OperatingSystem.IsWindows() && (full.StartsWith(@"\\", StringComparison.Ordinal) || full.AsSpan(2).Contains(':'))) throw new IOException("Network, device, and alternate stream paths are not supported.");
        return full;
    }
    public static void EnsureDirectory(string directory)
    {
        directory = NormalizeLocalPath(Path.GetFullPath(directory)); var existing = directory;
        while (!Directory.Exists(existing) && !File.Exists(existing)) existing = Path.GetDirectoryName(existing) ?? throw new IOException("Folder has no local parent.");
        _ = NormalizeRegularPath(existing); Directory.CreateDirectory(directory); _ = NormalizeRegularPath(directory);
    }
    public static string NormalizeRegularPath(string path)
    {
        var full = NormalizeLocalPath(path);
        var root = System.IO.Path.GetPathRoot(full);
        for (var current = full; !string.IsNullOrEmpty(current); current = System.IO.Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Symbolic links and reparse points are not scanned or modified.");
            if (current == root) break;
        }
        return full;
    }
}

public sealed class FileScanner(VerifiedFeed? feed = null, ScanLimits? limits = null, ScanControl? control = null)
{
    private readonly ScanLimits limits = ValidateLimits(limits ?? new());
    private static ScanLimits ValidateLimits(ScanLimits value)
    {
        if (value.MaxFileBytes is < 1 or > 1024L * 1024 * 1024 || value.MaxFiles is < 1 or > 1_000_000 || value.MaxFindings is < 1 or > 2_000
            || value.MaxArchiveEntries is < 1 or > 2_048 || value.MaxArchiveEntryBytes is < 1 or > 32L * 1024 * 1024
            || value.MaxArchiveExpandedBytes is < 1 or > 128L * 1024 * 1024 || value.MaxNestedArchiveBytes is < 1 or > 16L * 1024 * 1024
            || value.MaxArchiveDepth is < 0 or > 2 || value.MaxCompressionRatio is < 1 or > 200) throw new ArgumentException("Scan budgets must be positive and within the supported maximums.");
        return value;
    }
    private readonly VerifiedFeed catalog = feed ?? BuiltInCatalog.Current;
    // Harmless standardized test marker. It is never treated as a live malware family.
    internal static readonly byte[] TestMarker = Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    public static bool IsStandardTestFile(ReadOnlySpan<byte> prefix, long bytes)
    {
        if (bytes < TestMarker.Length || bytes > 128 || prefix.Length < bytes || !prefix[..TestMarker.Length].SequenceEqual(TestMarker)) return false;
        foreach (var value in prefix.Slice(TestMarker.Length, (int)bytes - TestMarker.Length)) if (value is not (9 or 10 or 13 or 32)) return false;
        return true;
    }
    public async Task<FileFinding> ScanFileAsync(string path, CancellationToken token = default)
    {
        var result = await ScanFileDetailedAsync(path, token);
        if (result.Canceled) token.ThrowIfCancellationRequested();
        return result.ArchiveFindings.Prepend(result.File).OrderByDescending(x => Priority(x.Verdict)).First();
    }
    // Call only after the user explicitly confirms removal of the file (the whole container for archive findings).
    public async Task<FileFinding> ConfirmQuarantineAsync(FileFinding finding, CancellationToken token = default)
    {
        if (finding.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile)) throw new ArgumentException("Only exact detections can be confirmed for quarantine.");
        var fresh = await ScanFileDetailedAsync(finding.Path, token);
        if (fresh.Canceled) token.ThrowIfCancellationRequested();
        var current = fresh.ArchiveFindings.Prepend(fresh.File).FirstOrDefault(x => x.ArchiveEntry == finding.ArchiveEntry && x.Sha256 == finding.Sha256 && x.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile);
        if (current is null || finding.ArchiveEntry is not null && fresh.File.Sha256 != finding.ContainerSha256)
            throw new IOException("This detection is no longer confirmed by the current file and catalog. Run a new scan.");
        return current.ArchiveEntry is null ? current : new(current.Path, current.Verdict,
            "Archive contains an exact detection: " + current.ArchiveEntry + " · " + current.Reason, fresh.File.Sha256, fresh.File.Bytes);
    }
    private static int Priority(FileVerdict verdict) => verdict switch { FileVerdict.KnownThreat => 6, FileVerdict.TestFile => 5, FileVerdict.Error => 4, FileVerdict.Skipped => 3, FileVerdict.NeedsReview => 2, _ => 1 };
    public async Task<FileScanResult> ScanFileDetailedAsync(string path, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            var full = FileSafety.NormalizeRegularPath(path);
            await using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, IsZipName(full) ? 64 * 1024 : 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var size = stream.Length;
            if (size > limits.MaxFileBytes) return new(new(full, FileVerdict.Skipped, "File exceeds the configured scan size limit."), [], 0, 0);
            var content = await InspectStreamAsync(stream, full, size, limits.MaxFileBytes, token);
            using (content.ArchiveBytes)
            {
                if (content.Finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile or FileVerdict.Error or FileVerdict.Skipped)
                    return new(content.Finding, [], 0, 0);
                if (content.Format != ArchiveFormat.None)
                {
                    stream.Position = 0;
                    var archive = new ArchiveScanner(this, limits);
                    var canceled = false;
                    try { await archive.ScanAsync(stream, full, content.Finding.Sha256!, content.Format, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) { canceled = true; }
                    return new(content.Finding, archive.Findings, archive.ScannedEntries, archive.BytesRead, canceled);
                }
                if (content.UnsupportedArchive)
                    return new(content.Finding, [new(full, FileVerdict.Skipped, "Archive contents use an unsupported format; only the container hash was checked.", content.Finding.Sha256, size)], 0, 0);
                return new(content.Finding, [], 0, 0);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        { return new(new(path, FileVerdict.Error, ex.Message), [], 0, 0); }
    }
    internal enum ArchiveFormat { None, Zip, Tar, Gzip }
    internal sealed record ContentScan(FileFinding Finding, ArchiveFormat Format, MemoryStream? ArchiveBytes, bool UnsupportedArchive);
    internal ValueTask CheckpointAsync(CancellationToken token) => control?.CheckpointAsync(token) ?? ValueTask.CompletedTask;
    internal ValueTask ReadCompletedAsync(int bytes, CancellationToken token) => control?.ReadCompletedAsync(bytes, token) ?? ValueTask.CompletedTask;
    internal async Task<ContentScan> InspectStreamAsync(Stream stream, string name, long size, long ceiling, CancellationToken token, bool captureArchive = false, Action<int>? consumed = null)
    {
        // Only scripts need a 32 KiB review prefix. Other files retain at most one
        // 512-byte TAR header in the existing read buffer; all bytes are still hashed.
        var script = IsScript(name);
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024); var headCapacity = (int)Math.Min(script ? 32 * 1024 : 512, size);
        var scriptHead = script ? ArrayPool<byte>.Shared.Rent(Math.Max(1, headCapacity)) : null;
        // Non-script prefixes share the end of the read buffer, outside subsequent reads.
        var head = (scriptHead ?? buffer).AsMemory(script ? 0 : buffer.Length - headCapacity, headCapacity);
        var readCapacity = script ? buffer.Length : buffer.Length - headCapacity;
        var headCount = 0; long total = 0; MemoryStream? nested = null; var format = ArchiveName(name);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            while (true)
            {
                await CheckpointAsync(token);
                var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(readCapacity, Math.Max(1, ceiling - total + 1))), token);
                if (read == 0) break;
                consumed?.Invoke(read); total += read;
                if (total > ceiling) { nested?.Dispose(); return new(new(name, FileVerdict.Skipped, "Content exceeds its scan/expansion limit.", Bytes: total), ArchiveFormat.None, null, false); }
                hash.AppendData(buffer, 0, read);
                var copy = Math.Min(read, headCapacity - headCount);
                if (copy > 0) { buffer.AsSpan(0, copy).CopyTo(head.Span[headCount..]); headCount += copy; }
                var magic = ArchiveMagic(head.Span[..headCount]);
                if (magic != ArchiveFormat.None) format = magic;
                if (captureArchive && format != ArchiveFormat.None && size <= limits.MaxNestedArchiveBytes)
                {
                    if (nested is null)
                    {
                        nested = new MemoryStream((int)size);
                        if (total > read) nested.Write(head.Span[..(int)(total - read)]);
                    }
                    await nested.WriteAsync(buffer.AsMemory(0, read), token);
                }
                if (control is not null) await control.ReadCompletedAsync(read, token);
            }
            if (total != size) { nested?.Dispose(); return new(new(name, FileVerdict.Error, "Content size changed or does not match its declared size. Rescan it.", Bytes: total), ArchiveFormat.None, null, false); }
            var digest = Convert.ToHexString(hash.GetHashAndReset());
            var reason = ReviewSignals(name, head.Span[..headCount], script);
            var finding = IsStandardTestFile(head.Span[..headCount], total) ? new FileFinding(name, FileVerdict.TestFile, "Standard harmless antivirus test file.", digest, total)
                : catalog.Hashes.TryGetValue(digest, out var indicator) ? new(name, FileVerdict.KnownThreat, $"SHA-256 match: {indicator.Label} · {indicator.Source}", digest, total)
                : new(name, reason is null ? FileVerdict.NoKnownMatch : FileVerdict.NeedsReview, reason ?? "No known hash match. This does not establish that the file is safe.", digest, total);
            if (nested is not null) nested.Position = 0;
            if (control is not null) await control.FileCompletedAsync(token);
            return new(finding, format, nested, format == ArchiveFormat.None && IsUnsupportedArchive(name, head.Span[..Math.Min(8, headCount)]));
        }
        catch { nested?.Dispose(); throw; }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); if (scriptHead is not null) ArrayPool<byte>.Shared.Return(scriptHead, clearArray: true); }
    }
    internal static bool IsZipMagic(ReadOnlySpan<byte> bytes) => bytes.Length >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4b && (bytes[2] == 3 && bytes[3] == 4 || bytes[2] == 5 && bytes[3] == 6);
    internal static ArchiveFormat ArchiveMagic(ReadOnlySpan<byte> head) => IsZipMagic(head) ? ArchiveFormat.Zip
        : head.Length >= 2 && head[0] == 0x1f && head[1] == 0x8b ? ArchiveFormat.Gzip
        : head.Length >= 262 && head.Slice(257, 5).SequenceEqual("ustar"u8) ? ArchiveFormat.Tar : ArchiveFormat.None;
    private static ArchiveFormat ArchiveName(string name)
    {
        if (IsZipName(name)) return ArchiveFormat.Zip;
        var extension = Path.GetExtension(name.AsSpan());
        return extension.Equals(".tar", StringComparison.OrdinalIgnoreCase) ? ArchiveFormat.Tar
            : extension.Equals(".gz", StringComparison.OrdinalIgnoreCase) || extension.Equals(".tgz", StringComparison.OrdinalIgnoreCase) ? ArchiveFormat.Gzip : ArchiveFormat.None;
    }
    private static bool IsZipName(string name)
    {
        var extension = Path.GetExtension(name.AsSpan());
        return extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) || extension.Equals(".jar", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".apk", StringComparison.OrdinalIgnoreCase) || extension.Equals(".nupkg", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".odt", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".ods", StringComparison.OrdinalIgnoreCase) || extension.Equals(".epub", StringComparison.OrdinalIgnoreCase);
    }
    private static ReadOnlySpan<byte> SevenZipMagic => [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
    internal static bool IsUnsupportedArchive(string name, ReadOnlySpan<byte> head)
    {
        var extension = Path.GetExtension(name.AsSpan());
        return extension.Equals(".7z", StringComparison.OrdinalIgnoreCase) || extension.Equals(".rar", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".bz2", StringComparison.OrdinalIgnoreCase) || extension.Equals(".xz", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".cab", StringComparison.OrdinalIgnoreCase) || extension.Equals(".iso", StringComparison.OrdinalIgnoreCase)
            || head.StartsWith(SevenZipMagic) || head.StartsWith("Rar!"u8) || head.Length >= 2 && head[0] == 0x1f && head[1] == 0x8b;
    }
    private static bool IsScript(string path)
    {
        var extension = Path.GetExtension(path.AsSpan());
        return extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".vbs", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".js", StringComparison.OrdinalIgnoreCase);
    }
    private static string? ReviewSignals(string path, ReadOnlySpan<byte> head, bool script)
    {
        var name = Path.GetFileName(path.AsSpan());
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            (name.EndsWith(".pdf.exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".doc.exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".docx.exe", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".jpg.exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".png.exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".txt.exe", StringComparison.OrdinalIgnoreCase))) return "Executable with a document/image-style double extension. Review manually; this is not a malware verdict.";
        if (script)
        {
            var text = Encoding.UTF8.GetString(head);
            if (text.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) && (text.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) || text.Contains("DownloadString", StringComparison.OrdinalIgnoreCase))) return "Script combines encoded content with execution or download primitives. Review manually; legitimate scripts can contain these patterns.";
        }
        return null;
    }
    public async Task<ScanReport> ScanPathAsync(string path, IProgress<ScanProgress>? progress = null, CancellationToken token = default,
        IEnumerable<string>? excludedDirectories = null)
    {
        var started = DateTimeOffset.UtcNow; var clock = System.Diagnostics.Stopwatch.StartNew();
        var findings = new List<FileFinding>(); var scanned = 0; var detected = 0; var review = 0; var skipped = 0; var errors = 0; long bytes = 0; var limit = false; var attempted = 0;
        token.ThrowIfCancellationRequested();
        var root = FileSafety.NormalizeRegularPath(path);
        var exclusions = FileSafety.NormalizeExclusions(excludedDirectories);
        // Streaming depth-first traversal keeps one enumerator per directory level,
        // rather than retaining every child path in a wide folder.
        var pending = new Stack<(IEnumerator<(string Path, FileAttributes Attributes)> Children, string Parent, int Depth)>();
        (string Path, int Depth, FileAttributes? Attributes)? next = (root, 0, null); var peakPending = 0;
        var lastProgress = TimeSpan.Zero;
        var findingCount = 0; var archiveEntries = 0; long archiveBytes = 0; var canceled = false;
        void Add(FileFinding finding)
        {
            findingCount++;
            if (findings.Count < limits.MaxFindings) { findings.Add(finding); return; }
            if (finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile)
            {
                var replace = findings.FindLastIndex(x => x.Verdict is not (FileVerdict.KnownThreat or FileVerdict.TestFile));
                if (replace >= 0) findings[replace] = finding;
            }
        }
        try
        {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            await CheckpointAsync(token);
            while (next is null && pending.TryPeek(out var folder))
            {
                try { if (folder.Children.MoveNext()) { var child = folder.Children.Current; next = (child.Path, folder.Depth, child.Attributes); break; } }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                { errors++; Add(new(folder.Parent, FileVerdict.Error, ex.Message)); }
                pending.Pop().Children.Dispose();
            }
            if (next is null) break;
            var entry = next.Value; next = null;
            if (++attempted > limits.MaxFiles) { limit = true; break; }
            if (FileSafety.IsExcluded(entry.Path, exclusions))
            {
                skipped++; Add(new(entry.Path, FileVerdict.Skipped, "Excluded from this scan by the monitoring storage policy.")); continue;
            }
            try
            {
                // Windows supplies these attributes with native directory enumeration.
                // FileSafety still freshly revalidates the leaf and every parent before reads.
                var attributes = entry.Attributes ?? File.GetAttributes(entry.Path);
                if ((attributes & FileAttributes.ReparsePoint) != 0) { skipped++; Add(new(entry.Path, FileVerdict.Skipped, "Reparse point skipped.")); continue; }
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (entry.Depth >= 64) { skipped++; Add(new(entry.Path, FileVerdict.Skipped, "Directory depth limit reached.")); continue; }
                    var children = new FileSystemEnumerable<(string Path, FileAttributes Attributes)>(entry.Path,
                        static (ref FileSystemEntry child) => (child.ToFullPath(), child.Attributes),
                        new EnumerationOptions { AttributesToSkip = 0, IgnoreInaccessible = false });
                    pending.Push((children.GetEnumerator(), entry.Path, entry.Depth + 1));
                    peakPending = Math.Max(peakPending, pending.Count);
                    continue;
                }
                var result = await ScanFileDetailedAsync(entry.Path, token);
                var finding = result.File;
                if (finding.Verdict is not (FileVerdict.Skipped or FileVerdict.Error)) scanned++;
                foreach (var item in result.ArchiveFindings.Prepend(finding))
                {
                    switch (item.Verdict)
                    {
                        case FileVerdict.KnownThreat: case FileVerdict.TestFile: detected++; Add(item); break;
                        case FileVerdict.NeedsReview: review++; Add(item); break;
                        case FileVerdict.Skipped: skipped++; Add(item); break;
                        case FileVerdict.Error: errors++; Add(item); break;
                    }
                }
                bytes += finding.Bytes; archiveEntries += result.ArchiveEntries; archiveBytes += result.ArchiveBytesRead;
                if (result.Canceled) token.ThrowIfCancellationRequested();
                if (lastProgress == TimeSpan.Zero || clock.Elapsed - lastProgress >= TimeSpan.FromMilliseconds(200)) { lastProgress = clock.Elapsed; progress?.Report(new(scanned, detected, review, skipped, errors, entry.Path)); }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { errors++; Add(new(entry.Path, FileVerdict.Error, ex.Message)); }
        }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { canceled = true; }
        finally { while (pending.TryPop(out var folder)) folder.Children.Dispose(); }
        canceled |= token.IsCancellationRequested;
        progress?.Report(new(scanned, detected, review, skipped, errors, canceled ? "Canceled" : "Finished"));
        return new(started, clock.Elapsed, scanned, detected, review, skipped, errors, limit, findingCount > limits.MaxFindings, bytes, catalog.Payload.Sequence, catalog.IsExpired(DateTimeOffset.UtcNow), findings, canceled, archiveEntries, archiveBytes, control?.Mode ?? ScanMode.Balanced, peakPending);
    }
}
