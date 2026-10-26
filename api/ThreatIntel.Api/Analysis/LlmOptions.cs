namespace ThreatIntel.Api.Analysis;

public sealed class LlmOptions
{
    /// <summary>OpenAI-kompatibler Endpunkt, z. B. https://api.openai.com/v1 oder Ollama http://localhost:11434/v1.</summary>
    public string? BaseUrl { get; set; }
    public string? ApiKey { get; set; }
    public string Model { get; set; } = "gpt-4o-mini";
}