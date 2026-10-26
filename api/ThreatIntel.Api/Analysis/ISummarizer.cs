using ThreatIntel.Api.Data;

namespace ThreatIntel.Api.Analysis;

public interface ISummarizer
{
    Task<string> SummarizeAsync(Severity severity, IReadOnlyList<string> products, string description, CancellationToken ct);
}
