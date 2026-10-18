using Microsoft.EntityFrameworkCore;

namespace ThreatIntel.Api.Data;

public enum Severity
{
    Unknown = 0,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Eine Schwachstelle (CVE) mit den Ergebnissen der automatischen Auswertung.
/// </summary>
public sealed class Vulnerability
{
    public int Id { get; set; }
    public string CveId { get; set; } = string.Empty;
    public DateTime PublishedUtc { get; set; }
    public double? CvssScore { get; set; }
    public Severity Severity { get; set; }
    public string Description { get; set; } = string.Empty;

    /// <summary>Kurzfassung für die Lageübersicht (vom Sprachmodell oder regelbasiert).</summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>Betroffene Produkte, getrennt durch Semikolon (datenbankunabhängig speicherbar).</summary>
    public string Products { get; set; } = string.Empty;

    /// <summary>Erkannte Angriffsmerkmale, z. B. "remote-code-execution".</summary>
    public string Tags { get; set; } = string.Empty;

    /// <summary>Priorität 0 bis 100 für die Reihenfolge der Bearbeitung.</summary>
    public int Priority { get; set; }

    public string Source { get; set; } = "NVD";
    public DateTime IngestedUtc { get; set; } = DateTime.UtcNow;

    public IEnumerable<string> ProductList =>
        Products.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>Produkte, die in der eigenen Infrastruktur eingesetzt werden und besonders beobachtet werden.</summary>
public sealed class WatchlistEntry
{
    public int Id { get; set; }
    public string Product { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class ThreatDbContext : DbContext
{
    public ThreatDbContext(DbContextOptions<ThreatDbContext> options) : base(options)
    {
    }

    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<WatchlistEntry> Watchlist => Set<WatchlistEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Vulnerability>(e =>
        {
            e.HasIndex(v => v.CveId).IsUnique();
            e.HasIndex(v => v.PublishedUtc);
            e.HasIndex(v => v.Priority);
            e.Property(v => v.CveId).HasMaxLength(32);
            e.Property(v => v.Severity).HasConversion<string>().HasMaxLength(16);
            e.Property(v => v.Source).HasMaxLength(32);
            e.Ignore(v => v.ProductList);
        });

        modelBuilder.Entity<WatchlistEntry>(e =>
        {
            e.HasIndex(w => w.Product).IsUnique();
            e.Property(w => w.Product).HasMaxLength(128);
        });
    }
}
