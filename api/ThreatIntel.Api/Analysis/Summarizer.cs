using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using ThreatIntel.Api.Data;

namespace ThreatIntel.Api.Analysis;

public sealed class LlmOptions
{
    /// <summary>OpenAI-kompatibler Endpunkt, z. B. https://api.openai.com/v1 oder Ollama http://localhost:11434/v1.</summary>
    public string? BaseUrl { get; set; }
    public string? ApiKey { get; set; }
    public string Model { get; set; } = "gpt-4o-mini";
}

public interface ISummarizer
{
    Task<string> SummarizeAsync(Severity severity, IReadOnlyList<string> products, string description, CancellationToken ct);
}

/// <summary>
/// Erstellt eine deutsche Kurzfassung für die Lageübersicht. Ohne konfiguriertes Sprachmodell
/// oder bei Fehlern wird die regelbasierte Kurzfassung verwendet.
/// </summary>
public sealed class Summarizer : ISummarizer
{
    private readonly HttpClient _http;
    private readonly LlmOptions _options;
    private readonly ILogger<Summarizer> _logger;

    public Summarizer(HttpClient http, LlmOptions options, ILogger<Summarizer> logger)
    {
        _http = http;
        _options = options;
        _logger = logger;
    }

    public async Task<string> SummarizeAsync(Severity severity, IReadOnlyList<string> products, string description, CancellationToken ct)
    {
        var fallback = ThreatAnalyzer.RuleBasedSummary(severity, products, description);
        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            return fallback;
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_options.BaseUrl.TrimEnd('/')}/chat/completions");
            if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            }

            var prompt = $"Schweregrad: {severity}\nProdukte: {string.Join(", ", products)}\nBeschreibung: {description}";
            request.Content = JsonContent.Create(new ChatRequest(_options.Model, new[]
            {
                new ChatMessage("system", "Fasse Sicherheitsmeldungen für ein Lagebild in höchstens zwei deutschen Sätzen zusammen. " +
                                          "Nenne betroffenes Produkt, Art des Angriffs und mögliche Auswirkung. Erfinde nichts."),
                new ChatMessage("user", prompt)
            }, 0.1));

            using var response = await _http.SendAsync(request, ct);
            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadFromJsonAsync<ChatResponse>(cancellationToken: ct);
            var text = body?.Choices.FirstOrDefault()?.Message.Content?.Trim();
            return string.IsNullOrWhiteSpace(text) ? fallback : text;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            _logger.LogWarning(ex, "Sprachmodell nicht erreichbar, regelbasierte Kurzfassung wird genutzt.");
            return fallback;
        }
    }

    private sealed record ChatMessage(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("content")] string? Content);

    private sealed record ChatRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("messages")] IReadOnlyList<ChatMessage> Messages,
        [property: JsonPropertyName("temperature")] double Temperature);

    private sealed record ChatChoice([property: JsonPropertyName("message")] ChatMessage Message);

    private sealed record ChatResponse([property: JsonPropertyName("choices")] IReadOnlyList<ChatChoice> Choices);
}
