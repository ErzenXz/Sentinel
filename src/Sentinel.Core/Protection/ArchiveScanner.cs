using System.Buffers.Binary;
using System.IO.Compression;

namespace Sentinel.Core.Protection;

// ZIP content is read from streams only. No archive name is ever used to create a file.
// Preflight bounds the central directory before ZipArchive allocates its entry collection.
internal sealed class ArchiveScanner(FileScanner scanner, ScanLimits limits)
{
    public List<FileFinding> Findings { get; } = [];
    public int ScannedEntries { get; private set; }
    public long BytesRead { get; private set; }
    private int visited;
    private string container = "";
    private string containerHash = "";
    private sealed record Header(ushort Flags, ushort Method, uint Crc, uint Compressed, uint Expanded, uint Attributes);
    public async Task ScanAsync(Stream stream, string path, string hash, CancellationToken token)
    {
        container = path; containerHash = hash;
        await ReadZip(stream, "", 0, token);
    }
    private void Notice(string? entry, FileVerdict verdict, string reason) => Findings.Add(new(container, verdict, reason, ArchiveEntry: string.IsNullOrEmpty(entry) ? null : entry, ContainerSha256: containerHash));
    private async Task ReadZip(Stream stream, string prefix, int depth, CancellationToken token)
    {
        try
        {
            var headers = await Preflight(stream, token);
            stream.Position = 0;
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            if (zip.Entries.Count != headers.Count) throw new InvalidDataException("ZIP entry count is inconsistent.");
            for (var i = 0; i < zip.Entries.Count; i++)
            {
                token.ThrowIfCancellationRequested();
                if (++visited > limits.MaxArchiveEntries) { Notice(prefix, FileVerdict.Skipped, "Archive-tree entry budget reached; remaining contents were not scanned."); break; }
                var entry = zip.Entries[i]; var header = headers[i];
                var name = prefix + entry.FullName;
                if (!SafeName(entry.FullName) || name.Length > 2048)
                { Notice(prefix, FileVerdict.Skipped, "Archive has an unsafe, ambiguous, or overlong entry name; that entry was not scanned."); continue; }
                var unixType = (header.Attributes >> 16) & 0xf000;
                if (unixType is not (0 or 0x8000 or 0x4000)) { Notice(name, FileVerdict.Skipped, "Archive links and special files are not inspected."); continue; }
                if ((header.Flags & 0x41) != 0) { Notice(name, FileVerdict.Skipped, "Encrypted archive entry cannot be inspected without a password."); continue; }
                if (header.Method is not (0 or 8)) { Notice(name, FileVerdict.Skipped, "Unsupported ZIP compression method."); continue; }
                if (entry.Length != header.Expanded || entry.CompressedLength != header.Compressed) throw new InvalidDataException("ZIP entry size is inconsistent.");
                if (entry.FullName.EndsWith('/') && entry.Length == 0) continue;
                if (entry.Length > limits.MaxArchiveEntryBytes || entry.Length > limits.MaxArchiveExpandedBytes - BytesRead)
                { Notice(name, FileVerdict.Skipped, "Archive entry or cumulative expansion exceeds the scan budget."); continue; }
                if (entry.Length > (long)Math.Max(1u, header.Compressed) * limits.MaxCompressionRatio)
                { Notice(name, FileVerdict.Skipped, "Archive compression ratio exceeds the scan budget."); continue; }
                try
                {
                    using var input = entry.Open();
                    using var checkedInput = new CrcStream(input);
                    var result = await scanner.InspectStreamAsync(checkedInput, entry.FullName, entry.Length,
                        Math.Min(limits.MaxArchiveEntryBytes, limits.MaxArchiveExpandedBytes - BytesRead), token,
                        captureZip: true, consumed: n => BytesRead += n);
                    using (result.ZipBytes)
                    {
                        if (result.Finding.Sha256 is not null && checkedInput.Crc != header.Crc)
                        { Notice(name, FileVerdict.Error, "ZIP entry integrity check failed (CRC-32)."); continue; }
                        if (result.Finding.Sha256 is not null) ScannedEntries++;
                        if (result.Finding.Verdict != FileVerdict.NoKnownMatch)
                            Findings.Add(result.Finding with { Path = container, ArchiveEntry = name, ContainerSha256 = containerHash });
                        if (result.Finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile or FileVerdict.Error or FileVerdict.Skipped) continue;
                        if (result.IsZip)
                        {
                            if (depth >= limits.MaxArchiveDepth) Notice(name, FileVerdict.Skipped, "Nested archive depth budget reached; its hash was checked, contents were not.");
                            else if (result.ZipBytes is null) Notice(name, FileVerdict.Skipped, "Nested archive exceeds the in-memory archive budget; only its hash was checked.");
                            else await ReadZip(result.ZipBytes, name + " → ", depth + 1, token);
                        }
                        else if (FileScanner.IsUnsupportedArchive(entry.FullName, result.Head))
                            Notice(name, FileVerdict.Skipped, "Nested archive format is unsupported; only its hash was checked.");
                    }
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or NotSupportedException)
                { Notice(name, FileVerdict.Error, "Archive entry could not be read: " + ex.Message); }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or NotSupportedException or ArgumentException)
        { Notice(prefix, FileVerdict.Skipped, "Archive contents were not fully inspected: " + ex.Message); }
    }
    private static bool SafeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 2048 || name.StartsWith('/') || name.Contains('\\') || name.Contains(':') || name.Any(char.IsControl)) return false;
        return !name.Split('/').Any(part => part is "." or "..");
    }
    private async Task<List<Header>> Preflight(Stream stream, CancellationToken token)
    {
        if (!stream.CanSeek || stream.Length < 22) throw new InvalidDataException("Invalid ZIP container.");
        var tail = new byte[(int)Math.Min(stream.Length, 65557)];
        stream.Position = stream.Length - tail.Length; await stream.ReadExactlyAsync(tail, token);
        var end = -1;
        for (var i = tail.Length - 22; i >= 0; i--)
            if (U32(tail, i) == 0x06054b50 && i + 22 + U16(tail, i + 20) == tail.Length) { end = i; break; }
        if (end < 0) throw new InvalidDataException("ZIP end record is missing or has trailing data.");
        var count = U16(tail, end + 10); var length = U32(tail, end + 12); var offset = U32(tail, end + 16);
        if (U16(tail, end + 4) != 0 || U16(tail, end + 6) != 0 || U16(tail, end + 8) != count) throw new InvalidDataException("Multipart ZIP files are unsupported.");
        if (count == ushort.MaxValue || length == uint.MaxValue || offset == uint.MaxValue) throw new InvalidDataException("ZIP64 files are outside the supported scan limits.");
        if (count > limits.MaxArchiveEntries || length > 4 * 1024 * 1024) throw new InvalidDataException("ZIP central directory exceeds the entry/metadata budget.");
        var endPosition = stream.Length - tail.Length + end;
        if ((long)offset + length != endPosition) throw new InvalidDataException("ZIP central directory boundaries are inconsistent.");
        stream.Position = offset; var headers = new List<Header>(count); var fixedHeader = new byte[46];
        for (var i = 0; i < count; i++)
        {
            token.ThrowIfCancellationRequested();
            if (stream.Position + fixedHeader.Length > endPosition) throw new InvalidDataException("Truncated ZIP central directory.");
            await stream.ReadExactlyAsync(fixedHeader, token);
            if (U32(fixedHeader, 0) != 0x02014b50 || U16(fixedHeader, 34) != 0) throw new InvalidDataException("Invalid ZIP directory entry.");
            var compressed = U32(fixedHeader, 20); var expanded = U32(fixedHeader, 24); var local = U32(fixedHeader, 42);
            if (compressed == uint.MaxValue || expanded == uint.MaxValue || local == uint.MaxValue) throw new InvalidDataException("ZIP64 entries are unsupported.");
            if ((long)local + 30 > offset || (long)local + 30 + compressed > offset) throw new InvalidDataException("ZIP local entry boundaries are inconsistent.");
            var variable = U16(fixedHeader, 28) + U16(fixedHeader, 30) + U16(fixedHeader, 32);
            if (stream.Position + variable > endPosition) throw new InvalidDataException("Truncated ZIP entry metadata.");
            var metadata = new byte[variable]; await stream.ReadExactlyAsync(metadata, token);
            var next = stream.Position; var localHeader = new byte[30]; stream.Position = local;
            await stream.ReadExactlyAsync(localHeader, token);
            var localNameLength = U16(localHeader, 26); var dataStart = (long)local + 30 + localNameLength + U16(localHeader, 28);
            if (U32(localHeader, 0) != 0x04034b50 || U16(localHeader, 6) != U16(fixedHeader, 8) || U16(localHeader, 8) != U16(fixedHeader, 10)
                || localNameLength != U16(fixedHeader, 28) || dataStart + compressed > offset) throw new InvalidDataException("ZIP local header is inconsistent.");
            var localName = new byte[localNameLength]; await stream.ReadExactlyAsync(localName, token);
            if (!localName.AsSpan().SequenceEqual(metadata.AsSpan(0, localNameLength))) throw new InvalidDataException("ZIP local and central entry names differ.");
            if ((U16(fixedHeader, 8) & 8) == 0 && (U32(localHeader, 14) != U32(fixedHeader, 16) || U32(localHeader, 18) != compressed || U32(localHeader, 22) != expanded))
                throw new InvalidDataException("ZIP local and central sizes or checksums differ.");
            headers.Add(new(U16(fixedHeader, 8), U16(fixedHeader, 10), U32(fixedHeader, 16), compressed, expanded, U32(fixedHeader, 38)));
            stream.Position = next;
        }
        if (stream.Position != endPosition) throw new InvalidDataException("ZIP central directory count does not match its size.");
        return headers;
    }
    private static ushort U16(byte[] data, int at) => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(at, 2));
    private static uint U32(byte[] data, int at) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at, 4));
    private sealed class CrcStream(Stream inner) : Stream
    {
        private static readonly uint[] Table = MakeTable();
        private static uint[] MakeTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < table.Length; i++)
            {
                var value = i;
                for (var bit = 0; bit < 8; bit++) value = (value >> 1) ^ (0xedb88320u & (uint)-(int)(value & 1));
                table[i] = value;
            }
            return table;
        }
        private uint crc = uint.MaxValue;
        public uint Crc => ~crc;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var count = await inner.ReadAsync(buffer, cancellationToken);
            foreach (var value in buffer.Span[..count])
            {
                crc = Table[(crc ^ value) & 0xff] ^ (crc >> 8);
            }
            return count;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
