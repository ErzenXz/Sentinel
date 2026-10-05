using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Protection;

public sealed record ReportSummary(string Path, DateTimeOffset StartedAt, int Scanned, int Detected, int Review, bool Incomplete);

public static class ScanReports
{
    public const int MaxReportBytes = 16 * 1024 * 1024;
    public static JsonSerializerOptions Json { get; } = new(FeedVerifier.Json)
    {
        WriteIndented = true, MaxDepth = 16,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };
    public static ScanReport Load(string path)
    {
        path = FileSafety.NormalizeRegularPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxReportBytes) throw new InvalidDataException("Scan report exceeds the size limit.");
        var bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
        var report = JsonSerializer.Deserialize<ScanReport>(bytes, Json) ?? throw new InvalidDataException("Invalid scan report.");
        Validate(report); return report;
    }
    public static void Validate(ScanReport report)
    {
        if (report.Findings is null || report.Findings.Count > 2_000 || report.Duration < TimeSpan.Zero || report.Duration > TimeSpan.FromDays(7)
            || report.StartedAt == default || report.FeedSequence < 0 || report.BytesRead < 0 || report.ArchiveBytesRead < 0
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
        var bytes = JsonSerializer.SerializeToUtf8Bytes(report, Json);
        if (bytes.Length > MaxReportBytes) throw new InvalidDataException("Scan report exceeds the size limit.");
        var staged = Path.Combine(parent, ".sentinel-report-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous))
            { await stream.WriteAsync(bytes, token); await stream.FlushAsync(token); stream.Flush(flushToDisk: true); }
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
}
