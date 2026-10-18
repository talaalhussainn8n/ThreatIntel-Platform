namespace ThreatIntel.Api.Contracts;

/// <summary>Eingangsformat des Python-Sammlers (eine normalisierte CVE).</summary>
public sealed record IngestVulnerability(
    string CveId,
    DateTime Published,
    double? CvssScore,
    string? CvssSeverity,
    string Description,
    IReadOnlyList<string>? Products,
    string? Source);

public sealed record IngestResult(int Created, int Updated, int Rejected);

public sealed record VulnerabilityDto(
    string CveId,
    DateTime PublishedUtc,
    double? CvssScore,
    string Severity,
    string Summary,
    string Description,
    IReadOnlyList<string> Products,
    IReadOnlyList<string> Tags,
    int Priority,
    bool OnWatchlist);

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed record StatsDto(
    int Total,
    IReadOnlyDictionary<string, int> BySeverity,
    IReadOnlyList<ProductCount> TopProducts,
    int WatchlistHits);

public sealed record ProductCount(string Product, int Count);

public sealed record WatchlistRequest(string Product);
