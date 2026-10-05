using System.Net.Http.Headers;
using System.Text.Json;

namespace Sentinel.Core;

public sealed record ModelDiscoveryResult(IReadOnlyList<string> Models, bool Truncated);
public sealed class AiModelDiscovery(HttpClient http)
{
    public const int MaxBytes = 1024 * 1024;
    public async Task<ModelDiscoveryResult> ListAsync(ProviderKind provider, string endpointText, string key, CancellationToken token = default)
    {
        if (provider == ProviderKind.CodexAppServer) throw new NotSupportedException("Codex uses its account/runtime model configuration; it does not use API model discovery.");
        if (!Enum.IsDefined(provider)) throw new ArgumentOutOfRangeException(nameof(provider));
        var endpoint = AiClient.ValidateEndpoint(endpointText);
        if (key.Any(char.IsWhiteSpace) || key.Any(char.IsControl)) throw new ArgumentException("The API key contains whitespace or control characters.");
        if (!endpoint.IsLoopback && string.IsNullOrWhiteSpace(key)) throw new ArgumentException("Add your provider API key before listing remote models.");
        var route = provider switch { ProviderKind.Ollama => "api/tags", ProviderKind.Anthropic => "v1/models?limit=1000", _ => "models" };
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(endpoint, route));
        if (provider == ProviderKind.Anthropic) { request.Headers.Add("x-api-key", key); request.Headers.Add("anthropic-version", "2023-06-01"); }
        else if (!string.IsNullOrEmpty(key)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Model provider returned HTTP {(int)response.StatusCode}. Check the endpoint and credentials.");
        if (response.RequestMessage?.RequestUri is { } actual && actual != request.RequestUri) throw new InvalidOperationException("Model discovery redirects are not accepted.");
        if (response.Content.Headers.ContentLength > MaxBytes) throw new InvalidDataException("Model list exceeds the 1 MB limit.");
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var buffer = new MemoryStream(); var chunk = new byte[8192]; int read;
        while ((read = await input.ReadAsync(chunk, token)) > 0)
        {
            if (buffer.Length + read > MaxBytes) throw new InvalidDataException("Model list exceeds the 1 MB limit.");
            await buffer.WriteAsync(chunk.AsMemory(0, read), token);
        }
        try
        {
            using var doc = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 16 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Malformed model metadata.");
            if (!root.TryGetProperty(provider == ProviderKind.Ollama ? "models" : "data", out var rows) || rows.ValueKind != JsonValueKind.Array) throw new InvalidDataException("The provider did not return a model list.");
            if (rows.GetArrayLength() > 2_000) throw new InvalidDataException("The provider returned too many model entries.");
            var models = new HashSet<string>(StringComparer.Ordinal);
            foreach (var row in rows.EnumerateArray())
            {
                if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty(provider == ProviderKind.Ollama ? "name" : "id", out var id) || id.ValueKind != JsonValueKind.String) throw new InvalidDataException("Malformed model entry.");
                var value = id.GetString()!;
                if (value.Length is < 1 or > 256 || value.Any(char.IsControl) || value.Any(char.IsWhiteSpace)) throw new InvalidDataException("Invalid model identifier.");
                models.Add(value);
            }
            return new(models.Order(StringComparer.Ordinal).Take(1_000).ToArray(), models.Count > 1_000 || root.TryGetProperty("has_more", out var more) && more.ValueKind == JsonValueKind.True);
        }
        catch (JsonException) { throw new InvalidDataException("The provider returned malformed model metadata."); }
    }
}
