using System.Reflection;
using System.Text.Json;

namespace Sentinel.Core.Protection;

// Snapshot is embedded in the application's assembly; it follows the same release-trust
// boundary as executable code. Online replacements must pass FeedVerifier with a pinned key.
public static class BuiltInCatalog
{
    private static readonly Lazy<VerifiedFeed> Catalog = new(Load);
    public static VerifiedFeed Current => Catalog.Value;
    private static VerifiedFeed Load()
    {
        var assembly=typeof(BuiltInCatalog).Assembly;
        using var list=assembly.GetManifestResourceStream("Sentinel.BuiltinIndicators.json") ?? throw new InvalidDataException("Built-in indicator snapshot is missing.");
        using var provenance=assembly.GetManifestResourceStream("Sentinel.BuiltinProvenance.json") ?? throw new InvalidDataException("Built-in provenance is missing.");
        var hashes=JsonSerializer.Deserialize<List<HashIndicator>>(list,FeedVerifier.Json) ?? throw new InvalidDataException("Invalid built-in indicators.");
        using var metadata=JsonDocument.Parse(provenance);
        var issued=metadata.RootElement.GetProperty("downloadedAt").GetDateTimeOffset();
        if(hashes.Count>FeedVerifier.MaxIndicators||hashes.Any(x=>!FeedVerifier.IsHash(x.Sha256)))throw new InvalidDataException("Malformed built-in indicators.");
        return new(new FeedPayload(1,0,issued,issued.AddDays(7),hashes));
    }
}
