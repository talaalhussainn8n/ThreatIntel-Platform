using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using ThreatIntel.Api.Contracts;
using ThreatIntel.Api.Data;

namespace ThreatIntel.Api.Analysis;

/// <summary>
/// Nimmt normalisierte Schwachstellen vom Sammler entgegen, bewertet sie und speichert sie.
/// Bereits bekannte CVEs werden aktualisiert statt doppelt angelegt.
/// </summary>
public sealed partial class IngestionService
{
    private readonly ThreatDbContext _db;
    private readonly ISummarizer _summarizer;

    public IngestionService(ThreatDbContext db, ISummarizer summarizer)
    {
        _db = db;
        _summarizer = summarizer;
    }

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$")]
    private static partial Regex CveIdRegex();

    public static bool IsValid(IngestVulnerability item) =>
        !string.IsNullOrWhiteSpace(item.CveId)
        && CveIdRegex().IsMatch(item.CveId.Trim())
        && !string.IsNullOrWhiteSpace(item.Description)
        && item.CvssScore is null or (>= 0 and <= 10);

    public async Task<IngestResult> IngestAsync(IReadOnlyList<IngestVulnerability> items, CancellationToken ct)
    {
        var watchlist = await _db.Watchlist.Select(w => w.Product).ToListAsync(ct);
        var ids = items.Select(i => i.CveId?.Trim() ?? string.Empty).ToList();
        var existing = await _db.Vulnerabilities
            .Where(v => ids.Contains(v.CveId))
            .ToDictionaryAsync(v => v.CveId, ct);

        int created = 0, updated = 0, rejected = 0;
        foreach (var item in items)
        {
            if (!IsValid(item))
            {
                rejected++;
                continue;
            }

            var cveId = item.CveId.Trim();
            var products = (item.Products ?? Array.Empty<string>())
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var severity = ThreatAnalyzer.SeverityFrom(item.CvssScore, item.CvssSeverity);
            var tags = ThreatAnalyzer.DetectTags(item.Description);
            var onWatchlist = ThreatAnalyzer.MatchesWatchlist(products, watchlist);

            if (!existing.TryGetValue(cveId, out var entity))
            {
                entity = new Vulnerability { CveId = cveId };
                _db.Vulnerabilities.Add(entity);
                existing[cveId] = entity;
                created++;
            }
            else
            {
                updated++;
            }

            entity.PublishedUtc = DateTime.SpecifyKind(item.Published.ToUniversalTime(), DateTimeKind.Utc);
            entity.CvssScore = item.CvssScore;
            entity.Severity = severity;
            entity.Description = item.Description.Trim();
            entity.Products = string.Join(';', products);
            entity.Tags = string.Join(';', tags);
            entity.Priority = ThreatAnalyzer.Priority(item.CvssScore, tags, onWatchlist);
            entity.Source = string.IsNullOrWhiteSpace(item.Source) ? "NVD" : item.Source.Trim();
            entity.Summary = await _summarizer.SummarizeAsync(severity, products, entity.Description, ct);
        }

        await _db.SaveChangesAsync(ct);
        return new IngestResult(created, updated, rejected);
    }

    /// <summary>Berechnet die Priorität aller Einträge neu, z. B. nach Änderung der Beobachtungsliste.</summary>
    public async Task RecalculatePrioritiesAsync(CancellationToken ct)
    {
        var watchlist = await _db.Watchlist.Select(w => w.Product).ToListAsync(ct);
        foreach (var v in await _db.Vulnerabilities.ToListAsync(ct))
        {
            var tags = v.Tags.Split(';', StringSplitOptions.RemoveEmptyEntries);
            v.Priority = ThreatAnalyzer.Priority(v.CvssScore, tags, ThreatAnalyzer.MatchesWatchlist(v.ProductList, watchlist));
        }
        await _db.SaveChangesAsync(ct);
    }
}
