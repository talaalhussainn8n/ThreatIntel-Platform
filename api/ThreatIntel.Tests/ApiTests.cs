using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ThreatIntel.Tests;

/// <summary>
/// End-to-End-Tests der API mit einer temporären SQLite-Datenbank.
/// </summary>
public class ApiTests : IClassFixture<ApiTests.Factory>
{
    public const string Key = "test-schluessel";

    public sealed class Factory : WebApplicationFactory<Program>
    {
        public Factory()
        {
            var db = Path.Combine(Path.GetTempPath(), $"threatintel-test-{Guid.NewGuid():N}.db");
            Environment.SetEnvironmentVariable("Database__Provider", "Sqlite");
            Environment.SetEnvironmentVariable("ConnectionStrings__ThreatIntel", $"Data Source={db}");
            Environment.SetEnvironmentVariable("Ingest__ApiKey", Key);
            Environment.SetEnvironmentVariable("Llm__BaseUrl", "");
        }
    }

    private readonly HttpClient _client;

    public ApiTests(Factory factory)
    {
        _client = factory.CreateClient();
    }

    private static object Cve(string id, double cvss, string description, params string[] products) => new
    {
        cveId = id,
        published = "2026-10-01T10:00:00Z",
        cvssScore = cvss,
        description,
        products,
        source = "NVD"
    };

    private async Task<HttpResponseMessage> Ingest(object[] items, string key = Key)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/vulnerabilities/batch")
        {
            Content = JsonContent.Create(items)
        };
        request.Headers.Add("X-Api-Key", key);
        return await _client.SendAsync(request);
    }

    [Fact]
    public async Task Einlieferung_ohne_Schluessel_wird_abgelehnt()
    {
        var response = await Ingest(new[] { Cve("CVE-2026-0001", 5, "Test") }, key: "falsch");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Einlieferung_Bewertung_und_Abfrage()
    {
        var response = await Ingest(new[]
        {
            Cve("CVE-2026-10001", 9.8, "A remote attacker can execute arbitrary code. Actively exploited.", "Example VPN Gateway"),
            Cve("CVE-2026-10002", 4.3, "Cross-site scripting in the admin panel.", "Example CMS"),
            Cve("ungueltig", 5.0, "kaputt")
        });
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, result.GetProperty("created").GetInt32());
        Assert.Equal(1, result.GetProperty("rejected").GetInt32());

        var detail = await _client.GetFromJsonAsync<JsonElement>("/api/vulnerabilities/CVE-2026-10001");
        Assert.Equal("Critical", detail.GetProperty("severity").GetString());
        Assert.Contains("remote-code-execution", detail.GetProperty("tags").EnumerateArray().Select(t => t.GetString()));
        Assert.StartsWith("Kritische Schwachstelle in Example VPN Gateway", detail.GetProperty("summary").GetString());

        var list = await _client.GetFromJsonAsync<JsonElement>("/api/vulnerabilities?search=CVE-2026-1000");
        var items = list.GetProperty("items");
        Assert.Equal("CVE-2026-10001", items[0].GetProperty("cveId").GetString());
    }

    [Fact]
    public async Task Erneute_Einlieferung_aktualisiert_statt_zu_duplizieren()
    {
        await Ingest(new[] { Cve("CVE-2026-20001", 5.0, "Denial of service.", "Example DB") });
        var response = await Ingest(new[] { Cve("CVE-2026-20001", 7.5, "Denial of service via crafted packet.", "Example DB") });

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(0, result.GetProperty("created").GetInt32());
        Assert.Equal(1, result.GetProperty("updated").GetInt32());

        var detail = await _client.GetFromJsonAsync<JsonElement>("/api/vulnerabilities/CVE-2026-20001");
        Assert.Equal("High", detail.GetProperty("severity").GetString());
    }

    [Fact]
    public async Task Beobachtungsliste_erhoeht_Prioritaet()
    {
        await Ingest(new[] { Cve("CVE-2026-30001", 6.0, "Privilege escalation.", "Special Firewall OS") });
        var before = await _client.GetFromJsonAsync<JsonElement>("/api/vulnerabilities/CVE-2026-30001");

        var add = await _client.PostAsJsonAsync("/api/watchlist", new { product = "special firewall" });
        Assert.Equal(HttpStatusCode.NoContent, add.StatusCode);

        var after = await _client.GetFromJsonAsync<JsonElement>("/api/vulnerabilities/CVE-2026-30001");
        Assert.True(after.GetProperty("priority").GetInt32() > before.GetProperty("priority").GetInt32());
        Assert.True(after.GetProperty("onWatchlist").GetBoolean());

        var stats = await _client.GetFromJsonAsync<JsonElement>("/api/stats");
        Assert.True(stats.GetProperty("watchlistHits").GetInt32() >= 1);
    }

    [Fact]
    public async Task Unbekannte_CVE_liefert_404()
    {
        var response = await _client.GetAsync("/api/vulnerabilities/CVE-1999-0000");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
