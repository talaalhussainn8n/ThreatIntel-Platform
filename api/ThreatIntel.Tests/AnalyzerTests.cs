using ThreatIntel.Api.Analysis;
using ThreatIntel.Api.Contracts;
using ThreatIntel.Api.Data;

namespace ThreatIntel.Tests;

public class AnalyzerTests
{
    [Theory]
    [InlineData(9.8, Severity.Critical)]
    [InlineData(7.0, Severity.High)]
    [InlineData(5.3, Severity.Medium)]
    [InlineData(2.1, Severity.Low)]
    [InlineData(0.0, Severity.Unknown)]
    public void Schweregrad_aus_CVSS(double cvss, Severity expected)
    {
        Assert.Equal(expected, ThreatAnalyzer.SeverityFrom(cvss, null));
    }

    [Fact]
    public void Schweregrad_ohne_CVSS_aus_Angabe_der_Quelle()
    {
        Assert.Equal(Severity.High, ThreatAnalyzer.SeverityFrom(null, "HIGH"));
        Assert.Equal(Severity.Unknown, ThreatAnalyzer.SeverityFrom(null, "egal"));
    }

    [Fact]
    public void Angriffsmerkmale_werden_erkannt()
    {
        var tags = ThreatAnalyzer.DetectTags(
            "A remote attacker can execute arbitrary code via a crafted request. This vulnerability is actively exploited.");

        Assert.Contains("remote-code-execution", tags);
        Assert.Contains("exploited-in-the-wild", tags);
        Assert.Contains("unauthenticated", tags);
        Assert.DoesNotContain("sql-injection", tags);
    }

    [Fact]
    public void Prioritaet_steigt_mit_Ausnutzung_und_Beobachtungsliste()
    {
        var basis = ThreatAnalyzer.Priority(7.5, Array.Empty<string>(), onWatchlist: false);
        var exploited = ThreatAnalyzer.Priority(7.5, new[] { "exploited-in-the-wild" }, onWatchlist: false);
        var watched = ThreatAnalyzer.Priority(7.5, new[] { "exploited-in-the-wild" }, onWatchlist: true);

        Assert.True(basis < exploited);
        Assert.True(exploited < watched);
        Assert.Equal(100, ThreatAnalyzer.Priority(10, new[] { "exploited-in-the-wild", "remote-code-execution" }, true));
    }

    [Fact]
    public void Beobachtungsliste_vergleicht_ohne_Gross_Kleinschreibung()
    {
        Assert.True(ThreatAnalyzer.MatchesWatchlist(new[] { "Apache HTTP Server 2.4" }, new[] { "apache http server" }));
        Assert.False(ThreatAnalyzer.MatchesWatchlist(new[] { "nginx" }, new[] { "apache" }));
    }

    [Fact]
    public void Regelbasierte_Kurzfassung_nennt_Schweregrad_und_Produkt()
    {
        var summary = ThreatAnalyzer.RuleBasedSummary(
            Severity.Critical, new[] { "Example VPN Gateway" }, "Buffer overflow in the login page. Second sentence.");

        Assert.Equal("Kritische Schwachstelle in Example VPN Gateway: Buffer overflow in the login page.", summary);
    }

    [Theory]
    [InlineData("CVE-2026-12345", "Beschreibung", 7.5, true)]
    [InlineData("cve-2026-1", "Beschreibung", 7.5, false)]
    [InlineData("CVE-2026-1234", "", 7.5, false)]
    [InlineData("CVE-2026-1234", "Beschreibung", 11.0, false)]
    public void Eingangsdaten_werden_geprueft(string cveId, string description, double cvss, bool valid)
    {
        var item = new IngestVulnerability(cveId, DateTime.UtcNow, cvss, null, description, null, null);
        Assert.Equal(valid, IngestionService.IsValid(item));
    }
}
