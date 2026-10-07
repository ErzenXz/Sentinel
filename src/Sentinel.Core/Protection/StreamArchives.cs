using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Sentinel.Core.Protection;

internal sealed partial class ArchiveScanner
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const int MaxTarMetadataBytes = 4 * 1024 * 1024;

    // Strict V7/ustar subset: bounded fixed headers and regular files. Extensions
    // that can change names, sizes or sparse layouts stop inspection explicitly.
    private async Task ReadTar(Stream stream, string prefix, int depth, CancellationToken token)
    {
        var block = new byte[512]; var metadata = 0;
        try
        {
            async Task<int> ReadBlock()
            {
                await scanner.CheckpointAsync(token);
                var count = await stream.ReadAtLeastAsync(block, 512, throwOnEndOfStream: false, token);
                metadata += count;
                if (metadata > MaxTarMetadataBytes) throw new InvalidDataException("TAR metadata/padding exceeds its budget.");
                if (count is not (0 or 512)) throw new InvalidDataException("Truncated TAR block.");
                return count;
            }
            while (true)
            {
                if (await ReadBlock() == 0) throw new InvalidDataException("TAR end markers are missing.");
                if (IsZero(block))
                {
                    if (await ReadBlock() != 512 || !IsZero(block)) throw new InvalidDataException("TAR requires two zero end blocks.");
                    while (await ReadBlock() != 0)
                        if (!IsZero(block)) throw new InvalidDataException("TAR has nonzero trailing data or another concatenated archive.");
                    return;
                }
                if (++visited > limits.MaxArchiveEntries) { Notice(prefix, FileVerdict.Skipped, "Archive-tree entry budget reached; remaining contents were not scanned."); return; }
                var sum = 0;
                for (var i = 0; i < block.Length; i++) sum += i is >= 148 and < 156 ? 32 : block[i];
                if (Octal(block.AsSpan(148, 8)) != sum) throw new InvalidDataException("TAR header checksum is invalid.");
                var ustar = block.AsSpan(257, 6).SequenceEqual("ustar\0"u8) && block.AsSpan(263, 2).SequenceEqual("00"u8);
                if (!ustar && !IsZero(block.AsSpan(257, 8))) throw new NotSupportedException("Only V7 and POSIX ustar TAR headers are supported.");
                var type = block[156];
                if (type is (byte)'x' or (byte)'g' or (byte)'L' or (byte)'K' or (byte)'S')
                    throw new NotSupportedException("PAX, GNU long-name and sparse TAR extensions are outside the supported subset.");
                var entryName = Text(block.AsSpan(0, 100));
                var directoryPrefix = ustar ? Text(block.AsSpan(345, 155)) : "";
                if (directoryPrefix.Length > 0) entryName = directoryPrefix + "/" + entryName;
                var name = prefix + entryName; var size = Octal(block.AsSpan(124, 12));
                if (size > limits.MaxArchiveEntryBytes || size > limits.MaxArchiveExpandedBytes - BytesRead)
                { Notice(name, FileVerdict.Skipped, "TAR entry or cumulative expansion exceeds the scan budget; remaining contents were not scanned."); return; }
                if (type == (byte)'5' && size == 0 && SafeName(entryName)) continue;
                using var input = new EntryReadStream(stream, size);
                if (!SafeName(entryName) || name.Length > 2048 || type is not (0 or (byte)'0'))
                {
                    Notice(SafeName(entryName) ? name : prefix, FileVerdict.Skipped, "TAR entry has an unsafe name, link, special file or unsupported type.");
                    await Drain(input, token);
                }
                else
                {
                    var result = await scanner.InspectStreamAsync(input, entryName, size,
                        Math.Min(limits.MaxArchiveEntryBytes, limits.MaxArchiveExpandedBytes - BytesRead), token,
                        captureArchive: depth < limits.MaxArchiveDepth, consumed: n => BytesRead += n);
                    using (result.ArchiveBytes)
                    {
                        if (result.Finding.Sha256 is not null) ScannedEntries++;
                        if (result.Finding.Verdict != FileVerdict.NoKnownMatch)
                            Findings.Add(result.Finding with { Path = container, ArchiveEntry = name, ContainerSha256 = containerHash });
                        if (input.Remaining != 0) throw new InvalidDataException("TAR entry is truncated.");
                        await ReadNested(result, entryName, name, depth, token);
                    }
                }
                var padding = (int)((512 - size % 512) % 512);
                if (padding > 0)
                {
                    await stream.ReadExactlyAsync(block.AsMemory(0, padding), token); metadata += padding;
                    if (metadata > MaxTarMetadataBytes || !IsZero(block.AsSpan(0, padding))) throw new InvalidDataException("TAR padding is invalid or over budget.");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or NotSupportedException or ArgumentException)
        { Notice(prefix, FileVerdict.Skipped, "TAR contents were not fully inspected: " + ex.Message); }
    }
    private async Task Drain(EntryReadStream stream, CancellationToken token)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            while (stream.Remaining > 0)
            {
                await scanner.CheckpointAsync(token);
                var count = await stream.ReadAsync(buffer, token);
                if (count == 0) throw new InvalidDataException("TAR entry is truncated.");
                BytesRead += count;
                await scanner.ReadCompletedAsync(count, token);
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }
    private async Task ReadNested(FileScanner.ContentScan result, string sourceName, string name, int depth, CancellationToken token)
    {
        if (result.Finding.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile or FileVerdict.Error or FileVerdict.Skipped) return;
        if (result.Format != FileScanner.ArchiveFormat.None)
        {
            if (depth >= limits.MaxArchiveDepth) Notice(name, FileVerdict.Skipped, "Nested archive depth budget reached; its hash was checked, contents were not.");
            else if (result.ArchiveBytes is null) Notice(name, FileVerdict.Skipped, "Nested archive exceeds the in-memory archive budget; only its hash was checked.");
            else await ReadArchive(result.ArchiveBytes, result.Format, sourceName, name + " → ", depth + 1, token);
        }
        else if (result.UnsupportedArchive) Notice(name, FileVerdict.Skipped, "Nested archive format is unsupported; only its hash was checked.");
    }
    private async Task ReadGzip(Stream stream, string sourceName, string prefix, int depth, CancellationToken token)
    {
        try
        {
            if (!AppContext.TryGetSwitch("System.IO.Compression.UseStrictValidation", out var strict) || !strict)
                throw new NotSupportedException("The host must enable strict compression validation before inspecting GZIP.");
            if (!stream.CanSeek || stream.Length < 18) throw new InvalidDataException("Truncated GZIP container.");
            stream.Position = 0; var header = new byte[10]; await stream.ReadExactlyAsync(header, token);
            if (header[0] != 0x1f || header[1] != 0x8b || header[2] != 8 || (header[3] & 0xe0) != 0) throw new InvalidDataException("Invalid GZIP header.");
            // Read at most 4 KiB of optional fields, never trusting an arbitrary name/length.
            var metadata = new byte[(int)Math.Min(4096, stream.Length - 18)];
            var metadataCount = await stream.ReadAtLeastAsync(metadata, metadata.Length, throwOnEndOfStream: false, token);
            var at = 0; string? originalName = null;
            if ((header[3] & 4) != 0)
            {
                if (metadataCount < 2) throw new InvalidDataException("Truncated GZIP extra field.");
                at = 2 + BinaryPrimitives.ReadUInt16LittleEndian(metadata);
                if (at > metadataCount) throw new NotSupportedException("GZIP optional metadata exceeds its budget.");
            }
            string? Field(bool name)
            {
                var end = metadata.AsSpan(at, metadataCount - at).IndexOf((byte)0);
                if (end < 0) throw new NotSupportedException("GZIP optional metadata exceeds its budget.");
                var value = name ? Encoding.Latin1.GetString(metadata.AsSpan(at, end)) : null;
                at += end + 1; return value;
            }
            if ((header[3] & 8) != 0) originalName = Field(true);
            if ((header[3] & 16) != 0) _ = Field(false);
            if ((header[3] & 2) != 0) at += 2; // GZipStream validates FHCRC as well as payload CRC.
            if (at > metadataCount || 10 + at > stream.Length - 8) throw new InvalidDataException("Truncated GZIP optional metadata.");
            var compressedSize = stream.Length - 10 - at - 8;
            stream.Position = stream.Length - 8; var trailer = new byte[8]; await stream.ReadExactlyAsync(trailer, token);
            var size = (long)BinaryPrimitives.ReadUInt32LittleEndian(trailer.AsSpan(4));
            var payloadName = originalName ?? Path.GetFileName(sourceName);
            if (originalName is null)
            {
                if (payloadName.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase)) payloadName = payloadName[..^4] + ".tar";
                else if (payloadName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) payloadName = payloadName[..^3];
                else payloadName = "GZIP payload";
            }
            var name = prefix + payloadName;
            if (!SafeName(payloadName) || name.Length > 2048) throw new NotSupportedException("GZIP contains an unsafe or ambiguous original name.");
            if (++visited > limits.MaxArchiveEntries || size > limits.MaxArchiveEntryBytes || size > limits.MaxArchiveExpandedBytes - BytesRead
                || size > Math.Max(1, compressedSize) * limits.MaxCompressionRatio)
            { Notice(name, FileVerdict.Skipped, "GZIP entry, expansion, count or compression ratio exceeds the scan budget."); return; }
            stream.Position = 0;
            using var observed = new EndObservedStream(stream);
            using var gzip = new GZipStream(observed, CompressionMode.Decompress, leaveOpen: true);
            using var checkedInput = new CrcStream(gzip);
            var result = await scanner.InspectStreamAsync(checkedInput, payloadName, size,
                Math.Min(limits.MaxArchiveEntryBytes, limits.MaxArchiveExpandedBytes - BytesRead), token,
                captureArchive: depth < limits.MaxArchiveDepth, consumed: n => BytesRead += n);
            using (result.ArchiveBytes)
            {
                if (result.Finding.Sha256 is not null && (!observed.EndObserved || checkedInput.Crc != BinaryPrimitives.ReadUInt32LittleEndian(trailer)))
                    throw new InvalidDataException("GZIP integrity check failed or trailing data was not consumed.");
                if (result.Finding.Sha256 is not null) ScannedEntries++;
                if (result.Finding.Verdict != FileVerdict.NoKnownMatch)
                    Findings.Add(result.Finding with { Path = container, ArchiveEntry = name, ContainerSha256 = containerHash });
                await ReadNested(result, payloadName, name, depth, token);
            }
        }
        catch (NotSupportedException ex) { Notice(prefix, FileVerdict.Skipped, "GZIP contents were not fully inspected: " + ex.Message); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException)
        { Notice(prefix, FileVerdict.Error, "GZIP integrity/read failure: " + ex.Message); }
    }
    private static bool IsZero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    private static string Text(ReadOnlySpan<byte> bytes)
    {
        var end = bytes.IndexOf((byte)0);
        if (end >= 0)
        {
            if (!IsZero(bytes[end..])) throw new InvalidDataException("TAR text has ambiguous bytes after its terminator.");
            bytes = bytes[..end];
        }
        return StrictUtf8.GetString(bytes);
    }
    private static long Octal(ReadOnlySpan<byte> bytes)
    {
        long value = 0; var terminated = false; var digit = false;
        foreach (var b in bytes)
        {
            if (b is 0 or 32) { if (digit || b == 0) terminated = true; continue; }
            if (terminated || b is < (byte)'0' or > (byte)'7') throw new InvalidDataException("Unsupported or invalid TAR numeric field.");
            value = checked(value * 8 + b - (byte)'0');
            digit = true;
        }
        return value;
    }
    private sealed class EntryReadStream(Stream inner, long size) : EndObservedStream(inner)
    {
        public long Remaining { get; private set; } = size;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (Remaining == 0) return 0;
            var count = await base.ReadAsync(buffer[..(int)Math.Min(buffer.Length, Remaining)], cancellationToken);
            Remaining -= count; return count;
        }
    }
    // GZipStream can stop at trailing garbage without consuming its entire input.
    // A clean input EOF, strict runtime validation, CRC and size are all required.
    private class EndObservedStream(Stream inner) : Stream
    {
        public bool EndObserved { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var count = await inner.ReadAsync(buffer, cancellationToken);
            if (count == 0 && buffer.Length > 0) EndObserved = true;
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
