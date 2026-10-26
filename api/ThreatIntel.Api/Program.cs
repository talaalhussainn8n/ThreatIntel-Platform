using Microsoft.EntityFrameworkCore;
using ThreatIntel.Api.Analysis;
using ThreatIntel.Api.Contracts;
using ThreatIntel.Api.Data;

var builder = WebApplication.CreateBuilder(args);

// Datenbank: PostgreSQL im Betrieb, SQLite für lokale Entwicklung und Tests.
var provider = builder.Configuration["Database:Provider"] ?? "Postgres";
var connectionString = builder.Configuration.GetConnectionString("ThreatIntel")
    ?? "Host=localhost;Database=threatintel;Username=threatintel;Password=threatintel";
builder.Services.AddDbContext<ThreatDbContext>(db =>
{
    if (provider.Equals("Sqlite", StringComparison.OrdinalIgnoreCase))
    {
        db.UseSqlite(connectionString);
    }
    else
    {
        db.UseNpgsql(connectionString);
    }
});

builder.Services.AddSingleton(builder.Configuration.GetSection("Llm").Get<LlmOptions>() ?? new LlmOptions());
builder.Services.AddHttpClient<ISummarizer, Summarizer>(c => c.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddScoped<IngestionService>();

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(builder.Configuration["Cors:Origin"] ?? "http://localhost:5173")
    .AllowAnyHeader()
    .AllowAnyMethod()));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<ThreatDbContext>().Database.EnsureCreated();
}

app.UseCors();

var ingestKey = app.Configuration["Ingest:ApiKey"];
var api = app.MapGroup("/api");

// Einlieferung durch den Sammler, abgesichert über einen gemeinsamen Schlüssel.
api.MapPost("/vulnerabilities/batch", async (
    HttpRequest request,
    [Microsoft.AspNetCore.Mvc.FromBody] List<IngestVulnerability> items,
    IngestionService ingestion,
    CancellationToken ct) =>
{
    if (string.IsNullOrEmpty(ingestKey) || request.Headers["X-Api-Key"] != ingestKey)
    {
        return Results.Unauthorized();
    }

    if (items.Count > 2000)
    {
        return Results.BadRequest(new { error = "Höchstens 2000 Einträge pro Aufruf." });
    }

    return Results.Ok(await ingestion.IngestAsync(items, ct));
});

api.MapGet("/vulnerabilities", async (
    ThreatDbContext db, string? severity, string? product, string? search, bool? watchlistOnly,
    int? page, int? pageSize, CancellationToken ct) =>
{
    var size = Math.Clamp(pageSize ?? 20, 1, 100);
    var current = Math.Max(page ?? 1, 1);
    var watchlist = await db.Watchlist.Select(w => w.Product).ToListAsync(ct);

    var query = db.Vulnerabilities.AsNoTracking();
    if (Enum.TryParse<Severity>(severity, ignoreCase: true, out var sev))
    {
        query = query.Where(v => v.Severity == sev);
    }
    if (!string.IsNullOrWhiteSpace(product))
    {
        var p = product.Trim().ToLower();
        query = query.Where(v => v.Products.ToLower().Contains(p));
    }
    if (!string.IsNullOrWhiteSpace(search))
    {
        var s = search.Trim().ToLower();
        query = query.Where(v => v.CveId.ToLower().Contains(s) || v.Description.ToLower().Contains(s));
    }

    var all = await query.OrderByDescending(v => v.Priority).ThenByDescending(v => v.PublishedUtc).ToListAsync(ct);
    var filtered = watchlistOnly == true
        ? all.Where(v => ThreatAnalyzer.MatchesWatchlist(v.ProductList, watchlist)).ToList()
        : all;

    var items = filtered
        .Skip((current - 1) * size)
        .Take(size)
        .Select(v => ToDto(v, watchlist))
        .ToList();

    return Results.Ok(new PagedResult<VulnerabilityDto>(items, filtered.Count, current, size));
});

api.MapGet("/vulnerabilities/{cveId}", async (string cveId, ThreatDbContext db, CancellationToken ct) =>
{
    var watchlist = await db.Watchlist.Select(w => w.Product).ToListAsync(ct);
    var v = await db.Vulnerabilities.AsNoTracking().FirstOrDefaultAsync(x => x.CveId == cveId.ToUpper(), ct);
    return v is null ? Results.NotFound() : Results.Ok(ToDto(v, watchlist));
});

api.MapGet("/stats", async (ThreatDbContext db, CancellationToken ct) =>
{
    var watchlist = await db.Watchlist.Select(w => w.Product).ToListAsync(ct);
    var rows = await db.Vulnerabilities.AsNoTracking()
        .Select(v => new { v.Severity, v.Products })
        .ToListAsync(ct);

    var bySeverity = Enum.GetValues<Severity>()
        .ToDictionary(s => s.ToString(), s => rows.Count(r => r.Severity == s));

    var products = rows
        .SelectMany(r => r.Products.Split(';', StringSplitOptions.RemoveEmptyEntries))
        .ToList();
    var topProducts = products
        .GroupBy(p => p, StringComparer.OrdinalIgnoreCase)
        .Select(g => new ProductCount(g.Key, g.Count()))
        .OrderByDescending(p => p.Count)
        .Take(10)
        .ToList();

    var hits = rows.Count(r => ThreatAnalyzer.MatchesWatchlist(
        r.Products.Split(';', StringSplitOptions.RemoveEmptyEntries), watchlist));

    return Results.Ok(new StatsDto(rows.Count, bySeverity, topProducts, hits));
});

api.MapGet("/watchlist", async (ThreatDbContext db, CancellationToken ct) =>
    Results.Ok(await db.Watchlist.OrderBy(w => w.Product).Select(w => w.Product).ToListAsync(ct)));

api.MapPost("/watchlist", async (WatchlistRequest request, ThreatDbContext db, IngestionService ingestion, CancellationToken ct) =>
{
    var product = request.Product?.Trim();
    if (string.IsNullOrWhiteSpace(product) || product.Length > 128)
    {
        return Results.BadRequest(new { error = "Ungültiger Produktname." });
    }

    if (!await db.Watchlist.AnyAsync(w => w.Product == product, ct))
    {
        db.Watchlist.Add(new WatchlistEntry { Product = product });
        await db.SaveChangesAsync(ct);
        await ingestion.RecalculatePrioritiesAsync(ct);
    }

    return Results.NoContent();
});

api.MapDelete("/watchlist/{product}", async (string product, ThreatDbContext db, IngestionService ingestion, CancellationToken ct) =>
{
    var entry = await db.Watchlist.FirstOrDefaultAsync(w => w.Product == product, ct);
    if (entry is null)
    {
        return Results.NotFound();
    }

    db.Watchlist.Remove(entry);
    await db.SaveChangesAsync(ct);
    await ingestion.RecalculatePrioritiesAsync(ct);
    return Results.NoContent();
});

app.Run();

static VulnerabilityDto ToDto(Vulnerability v, IReadOnlyList<string> watchlist) => new(
    v.CveId,
    v.PublishedUtc,
    v.CvssScore,
    v.Severity.ToString(),
    v.Summary,
    v.Description,
    v.ProductList.ToList(),
    v.Tags.Split(';', StringSplitOptions.RemoveEmptyEntries),
    v.Priority,
    ThreatAnalyzer.MatchesWatchlist(v.ProductList, watchlist));

// Für Integrationstests mit WebApplicationFactory.
public partial class Program;

