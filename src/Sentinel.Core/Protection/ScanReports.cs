using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Protection;

public sealed record ReportSummary(string Path, DateTimeOffset StartedAt, int Scanned, int Detected, int Review, bool Incomplete);

public static class ScanReports
{
    public const int MaxReportBytes = 16 * 1024 * 1024;
    public static JsonSerializerOptions Json { get; } = new(FeedVerifier.Json)
    {
        WriteIndented = true, MaxDepth = 16, DefaultBufferSize = 64 * 1024,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };
    public static ScanReport Load(string path)
    {
        path = FileSafety.NormalizeRegularPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxReportBytes) throw new InvalidDataException("Scan report exceeds the size limit.");
        using var bounded = new ReportStream(stream);
        var report = JsonSerializer.Deserialize<ScanReport>(bounded, Json) ?? throw new InvalidDataException("Invalid scan report.");
        Validate(report); return report;
    }
    public static void Validate(ScanReport report)
    {
        if (report.Findings is null || report.Findings.Count > 2_000 || report.Duration < TimeSpan.Zero || report.Duration > TimeSpan.FromDays(7)
            || report.StartedAt == default || report.FeedSequence < 0 || report.BytesRead < 0 || report.ArchiveBytesRead < 0
            || !Enum.IsDefined(report.Mode) || report.PeakPendingDirectories is < 0 or > 64
            || new[] { report.Scanned, report.Detected, report.Review, report.Skipped, report.Errors, report.ArchiveEntries }.Any(x => x < 0))
            throw new InvalidDataException("Invalid scan report totals or limits.");
        foreach (var finding in report.Findings)
        {
            if (finding is null || !Enum.IsDefined(finding.Verdict) || string.IsNullOrEmpty(finding.Path) || finding.Path.Length > 32768
                || !Path.IsPathFullyQualified(finding.Path) || finding.Reason is null || finding.Reason.Length > 8192 || finding.Bytes < 0
                || finding.ArchiveEntry?.Length > 2048 || finding.ArchiveEntry?.Any(char.IsControl) == true
                || finding.Sha256 is not null && !FeedVerifier.IsHash(finding.Sha256)
                || finding.ContainerSha256 is not null && !FeedVerifier.IsHash(finding.ContainerSha256)
                || finding.ArchiveEntry is not null && finding.ContainerSha256 is null
                || finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile && finding.Sha256 is null)
                throw new InvalidDataException("Invalid finding in scan report.");
        }
        if (report.Findings.Count(x => x.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile) > report.Detected
            || report.Findings.Count(x => x.Verdict == FileVerdict.NeedsReview) > report.Review
            || report.Findings.Count(x => x.Verdict == FileVerdict.Skipped) > report.Skipped
            || report.Findings.Count(x => x.Verdict == FileVerdict.Error) > report.Errors)
            throw new InvalidDataException("Scan report counts contradict its findings.");
    }
    public static async Task SaveAsync(ScanReport report, string path, CancellationToken token = default)
    {
        Validate(report); path = FileSafety.NormalizeLocalPath(Path.GetFullPath(path));
        var parent = Path.GetDirectoryName(path) ?? throw new ArgumentException("Choose a report folder.");
        Prepare(parent);
        if (File.Exists(path) || Directory.Exists(path)) _ = FileSafety.NormalizeRegularPath(path);
        var staged = Path.Combine(parent, ".sentinel-report-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous))
            {
                using var bounded = new ReportStream(stream);
                await JsonSerializer.SerializeAsync(bounded, report, Json, token);
                await stream.FlushAsync(token); stream.Flush(flushToDisk: true);
            }
            token.ThrowIfCancellationRequested(); File.Move(staged, path, overwrite: true);
        }
        finally { if (File.Exists(staged)) File.Delete(staged); }
    }
    public static async Task<string> SaveHistoryAsync(ScanReport report, string directory)
    {
        Prepare(directory);
        var path = Path.Combine(directory, $"sentinel-run-{DateTime.UtcNow:yyyyMMdd-HHmmss-fffffff}-{Guid.NewGuid():N}.json");
        // Completed work is saved even when the scan's cancellation token has been canceled.
        await SaveAsync(report, path);
        foreach (var old in HistoryPaths(directory).Skip(30)) File.Delete(FileSafety.NormalizeRegularPath(old));
        return path;
    }
    public static ScanReport? Latest(string directory)
    {
        if (!Directory.Exists(directory)) return null;
        _ = FileSafety.NormalizeRegularPath(directory);
        foreach (var path in HistoryPaths(directory).Take(30))
        {
            try { return Load(path); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or ArgumentException or UnauthorizedAccessException) { }
        }
        return null;
    }
    public static IReadOnlyList<ReportSummary> List(string directory)
    {
        if (!Directory.Exists(directory)) return [];
        _ = FileSafety.NormalizeRegularPath(directory);
        var summaries = new List<ReportSummary>();
        foreach (var path in HistoryPaths(directory).Take(30))
        {
            try { var report = Load(path); summaries.Add(new(path, report.StartedAt, report.Scanned, report.Detected, report.Review, report.Incomplete)); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or ArgumentException or UnauthorizedAccessException) { }
        }
        return summaries;
    }
    private static IEnumerable<string> HistoryPaths(string directory) => Directory.EnumerateFiles(directory, "sentinel-run-*.json").Take(1_000).OrderByDescending(Path.GetFileName, StringComparer.Ordinal);
    private static void Prepare(string directory)
    {
        directory = Path.GetFullPath(directory);
        var existing = directory;
        while (!Directory.Exists(existing) && !File.Exists(existing)) existing = Path.GetDirectoryName(existing) ?? throw new IOException("Report folder has no local parent.");
        _ = FileSafety.NormalizeRegularPath(existing);
        Directory.CreateDirectory(directory); _ = FileSafety.NormalizeRegularPath(directory);
    }

    // The wrapper leaves the file open for its owner and checks every read/write, even
    // if an untrusted file grows after the initial length check. No full JSON byte copy.
    private sealed class ReportStream(Stream inner) : Stream
    {
        private long processed;
        private void Check(int count)
        {
            if (count > MaxReportBytes - processed) throw new InvalidDataException("Scan report exceeds the size limit.");
        }
        public override int Read(Span<byte> buffer)
        {
            var count = inner.Read(buffer[..(int)Math.Min(buffer.Length, MaxReportBytes - processed + 1)]);
            Check(count); processed += count; return count;
        }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        { Check(buffer.Length); inner.Write(buffer); processed += buffer.Length; }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        { Check(buffer.Length); await inner.WriteAsync(buffer, cancellationToken); processed += buffer.Length; }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
