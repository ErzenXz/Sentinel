using System.Security.Cryptography;
using System.Text.Json;
using System.Buffers;

namespace Sentinel.Core.Protection;

public sealed record HashIndicator(string Sha256, string Label, string Source);
public sealed record FeedPayload(int Schema, long Sequence, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, IReadOnlyList<HashIndicator> Hashes);
public sealed record SignedFeed(int Schema, string Algorithm, string Payload, string Signature);
public sealed record ProtectionSettings(string Endpoint = "http://127.0.0.1:8787/", string PublicKeyPem = "");
public sealed record FeedRefreshResult(VerifiedFeed Feed, bool HashSetChanged);

public sealed class VerifiedFeed
{
    public FeedPayload Payload { get; }
    public IReadOnlyDictionary<string, HashIndicator> Hashes { get; }
    private readonly byte[]? signedPayloadDigest;
    internal VerifiedFeed(FeedPayload payload, Dictionary<string, HashIndicator>? validatedHashes = null, byte[]? signedPayloadDigest = null)
    {
        // Labels and source names repeat thousands of times in public IOC lists.
        // Share identical text inside this catalog only; never globally intern feed data.
        var text = new Dictionary<string, string>(StringComparer.Ordinal);
        string Share(string value)
        {
            if (text.TryGetValue(value, out var existing)) return existing;
            text.Add(value, value); return value;
        }
        var rules = new HashIndicator[payload.Hashes.Count];
        var hashes = validatedHashes ?? new Dictionary<string, HashIndicator>(rules.Length, StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < rules.Length; i++)
        {
            var rule = payload.Hashes[i]; var label = Share(rule.Label); var source = Share(rule.Source);
            rules[i] = ReferenceEquals(label, rule.Label) && ReferenceEquals(source, rule.Source) ? rule : rule with { Label = label, Source = source };
            if (validatedHashes is null) hashes.Add(rule.Sha256, rules[i]);
            else hashes[rule.Sha256] = rules[i];
        }
        Payload = payload with { Hashes = rules };
        Hashes = hashes;
        this.signedPayloadDigest = signedPayloadDigest;
    }
    internal bool MatchesSignedPayload(VerifiedFeed other) => signedPayloadDigest is not null && other.signedPayloadDigest is not null
        && CryptographicOperations.FixedTimeEquals(signedPayloadDigest, other.signedPayloadDigest);
    public bool IsExpired(DateTimeOffset now) => Payload.ExpiresAt <= now;
}

public static class FeedVerifier
{
    // The byte-array JSON converter decodes base64 directly from UTF-8, avoiding
    // a second, large UTF-16 representation of the envelope's payload/signature.
    private sealed record DecodedSignedFeed(int Schema, string Algorithm, byte[]? Payload, byte[]? Signature);
    public const int MaxEnvelopeBytes = 24 * 1024 * 1024;
    public const int MaxIndicators = 100_000;
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };
    public static string Fingerprint(string pem)
    {
        if (pem.Length > 16 * 1024 || !pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) || pem.Contains("PRIVATE KEY", StringComparison.Ordinal)) throw new CryptographicException("Import only the server public.pem file, never a private key.");
        using var rsa = RSA.Create(); rsa.ImportFromPem(pem);
        if (rsa.KeySize < 3072) throw new CryptographicException("Feed keys must be RSA 3072 bits or stronger.");
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }
    public static VerifiedFeed Verify(ReadOnlySpan<byte> envelope, string pinnedPem, DateTimeOffset now, long minimumSequence = 0, bool allowExpired = false)
    {
        if (envelope.Length > MaxEnvelopeBytes) throw new InvalidDataException("Threat feed exceeds its size limit.");
        DecodedSignedFeed signed;
        try { signed = JsonSerializer.Deserialize<DecodedSignedFeed>(envelope, Json) ?? throw new InvalidDataException("Missing feed envelope."); }
        catch (JsonException ex) { throw new InvalidDataException("Malformed feed envelope or base64 encoding.", ex); }
        if (signed.Schema != 1 || signed.Algorithm != "RSA-SHA256") throw new InvalidDataException("Unsupported feed format.");
        var data = signed.Payload ?? throw new InvalidDataException("Missing feed payload encoding.");
        var signature = signed.Signature ?? throw new InvalidDataException("Missing feed signature encoding.");
        _ = Fingerprint(pinnedPem);
        using var rsa = RSA.Create(); rsa.ImportFromPem(pinnedPem);
        var payloadDigest = SHA256.HashData(data);
        if (rsa.KeySize < 3072 || !rsa.VerifyHash(payloadDigest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) throw new CryptographicException("Threat feed signature is invalid. The previous feed was retained.");
        var payload = JsonSerializer.Deserialize<FeedPayload>(data, Json) ?? throw new InvalidDataException("Missing feed payload.");
        if (payload.Schema != 1 || payload.Sequence < 1 || payload.Sequence < minimumSequence) throw new InvalidDataException("Old or unsupported feed rejected.");
        if (payload.IssuedAt > now.AddMinutes(5) || payload.ExpiresAt <= payload.IssuedAt || payload.ExpiresAt - payload.IssuedAt > TimeSpan.FromDays(8)) throw new InvalidDataException("Invalid feed validity period.");
        if (!allowExpired && payload.ExpiresAt <= now) throw new InvalidDataException("The threat feed has expired. Ask the server operator to publish an update.");
        if (payload.Hashes is null || payload.Hashes.Count > MaxIndicators) throw new InvalidDataException("Invalid indicator count.");
        var hashes = new Dictionary<string, HashIndicator>(payload.Hashes.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var rule in payload.Hashes)
        {
            if (rule is null || !IsHash(rule.Sha256) || !SafeLabel(rule.Label) || !SafeLabel(rule.Source) || !hashes.TryAdd(rule.Sha256, rule)) throw new InvalidDataException("Malformed or duplicate threat indicator.");
        }
        return new(payload, hashes, payloadDigest);
    }
    public static bool IsHash(string? hash) => hash is { Length: 64 } && hash.All(Uri.IsHexDigit);
    private static bool SafeLabel(string? text) => text is { Length: > 0 and <= 160 } && !text.Any(char.IsControl);
}

// Only signed indicator lists are downloaded; neither hashes of local files nor file contents are sent.
public sealed class FeedRepository(string directory)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private string CachePath => Path.Combine(directory, "feed.json");
    private string SequencePath => Path.Combine(directory, "sequence.txt");
    private VerifiedFeed? current;
    public VerifiedFeed? Current => Volatile.Read(ref current);
    public void Load(string publicKeyPem)
    {
        Volatile.Write(ref current, null);
        if (!File.Exists(CachePath))
        {
            if (ReadSequence() > 0) throw new InvalidDataException("Signed feed cache is missing. Ask the server operator to publish a newer sequence.");
            return;
        }
        if (new FileInfo(CachePath).Length > FeedVerifier.MaxEnvelopeBytes) throw new InvalidDataException("Cached feed exceeds its size limit.");
        Volatile.Write(ref current, FeedVerifier.Verify(File.ReadAllBytes(FileSafety.NormalizeRegularPath(Path.GetFullPath(CachePath))), publicKeyPem, DateTimeOffset.UtcNow, ReadSequence(), allowExpired: true));
    }
    private long ReadSequence()
    {
        if (!File.Exists(SequencePath)) return 0;
        if (new FileInfo(SequencePath).Length > 128) throw new InvalidDataException("Threat feed sequence state exceeds its size limit.");
        if (!long.TryParse(File.ReadAllText(FileSafety.NormalizeRegularPath(Path.GetFullPath(SequencePath))), out var sequence) || sequence < 0) throw new InvalidDataException("Threat feed sequence state is corrupt. Recovery requires a deliberate trust reset.");
        return sequence;
    }
    public async Task ResetTrustAsync(CancellationToken token = default)
    {
        await gate.WaitAsync(token);
        try
        {
            if (File.Exists(CachePath)) File.Delete(FileSafety.NormalizeRegularPath(Path.GetFullPath(CachePath)));
            if (File.Exists(SequencePath)) File.Delete(FileSafety.NormalizeRegularPath(Path.GetFullPath(SequencePath)));
            Volatile.Write(ref current, null);
        }
        finally { gate.Release(); }
    }
    public async Task<VerifiedFeed> UpdateAsync(HttpClient http, ProtectionSettings settings, CancellationToken token = default)
        => (await RefreshAsync(http, settings, token)).Feed;

    // Compare the committed hash set while holding the update gate. Renewed expiry,
    // sequence, labels or provenance alone do not require reading watched files again.
    public async Task<FeedRefreshResult> RefreshAsync(HttpClient http, ProtectionSettings settings, CancellationToken token = default)
    {
        var endpoint = AiClient.ValidateEndpoint(settings.Endpoint);
        _ = FeedVerifier.Fingerprint(settings.PublicKeyPem);
        await gate.WaitAsync(token);
        try
        {
            using var response = await http.GetAsync(new Uri(endpoint, "v1/feed"), HttpCompletionOption.ResponseHeadersRead, token);
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Threat server returned HTTP {(int)response.StatusCode}. The previous feed was retained.");
            var declaredLength = response.Content.Headers.ContentLength;
            if (declaredLength > FeedVerifier.MaxEnvelopeBytes) throw new InvalidDataException("Threat feed exceeds its size limit.");
            await using var stream = await response.Content.ReadAsStreamAsync(token);
            using var bytes = declaredLength is > 0 ? new MemoryStream((int)declaredLength.Value) : new MemoryStream();
            var buffer = new byte[64 * 1024]; int count;
            while ((count = await stream.ReadAsync(buffer, token)) > 0)
            {
                if (bytes.Length + count > FeedVerifier.MaxEnvelopeBytes) throw new InvalidDataException("Threat feed exceeds its size limit.");
                await bytes.WriteAsync(buffer.AsMemory(0, count), token);
            }
            // Keep the received envelope in its existing buffer through verification and staging.
            var raw = bytes.GetBuffer().AsMemory(0, (int)bytes.Length);
            var previous = Current;
            var committedSequence = ReadSequence();
            var verified = FeedVerifier.Verify(raw.Span, settings.PublicKeyPem, DateTimeOffset.UtcNow, Math.Max(committedSequence, previous?.Payload.Sequence ?? 0));
            if (previous is null && committedSequence > 0 && verified.Payload.Sequence == committedSequence && !File.Exists(CachePath))
                throw new InvalidDataException("Signed feed cache is missing. Ask the server operator to publish a newer sequence.");
            if (previous is not null && verified.Payload.Sequence == previous.Payload.Sequence
                && !previous.MatchesSignedPayload(verified))
                throw new InvalidDataException("Feed content changed without a sequence increase.");
            var activeHashes = (previous ?? BuiltInCatalog.Current).Hashes;
            var hashSetChanged = activeHashes.Count != verified.Hashes.Count
                || verified.Hashes.Keys.Any(hash => !activeHashes.ContainsKey(hash));
            // An equal sequence must contain the exact same signed payload, not a different rule set.
            if (File.Exists(CachePath) && verified.Payload.Sequence == ReadSequence())
            {
                if (!await MatchesCacheAsync(raw, token)) throw new InvalidDataException("Feed content changed without a sequence increase.");
                // Signature, validity, rollback state and all cache bytes were checked again.
                // An identical signed envelope needs no replacement or disk flush.
                token.ThrowIfCancellationRequested();
                Volatile.Write(ref current, verified);
                return new(verified, hashSetChanged);
            }
            FileSafety.EnsureDirectory(directory);
            if (File.Exists(CachePath)) _ = FileSafety.NormalizeRegularPath(Path.GetFullPath(CachePath));
            var suffix = "." + Guid.NewGuid().ToString("N") + ".tmp";
            var temporary = CachePath + suffix; var sequenceTemp = SequencePath + suffix;
            async Task Stage(string path, ReadOnlyMemory<byte> data)
            {
                await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous);
                await file.WriteAsync(data, token); await file.FlushAsync(token); file.Flush(flushToDisk: true);
            }
            try
            {
                await Stage(temporary, raw);
                await Stage(sequenceTemp, System.Text.Encoding.ASCII.GetBytes(verified.Payload.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                token.ThrowIfCancellationRequested();
                // Commit anti-rollback state first; cancellation cannot split the small replacement transaction.
                File.Move(sequenceTemp, SequencePath, overwrite: true); File.Move(temporary, CachePath, overwrite: true);
                Volatile.Write(ref current, verified);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
                if (File.Exists(sequenceTemp)) File.Delete(sequenceTemp);
            }
            return new(verified, hashSetChanged);
        }
        finally { gate.Release(); }
    }
    private async Task<bool> MatchesCacheAsync(ReadOnlyMemory<byte> envelope, CancellationToken token)
    {
        await using var cache = new FileStream(FileSafety.NormalizeRegularPath(Path.GetFullPath(CachePath)), FileMode.Open,
            FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (cache.Length != envelope.Length) return false;
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            var offset = 0;
            while (offset < envelope.Length)
            {
                var count = await cache.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, envelope.Length - offset)), token);
                if (count == 0 || !buffer.AsSpan(0, count).SequenceEqual(envelope.Span.Slice(offset, count))) return false;
                offset += count;
            }
            token.ThrowIfCancellationRequested();
            return cache.Length == envelope.Length;
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }
}
