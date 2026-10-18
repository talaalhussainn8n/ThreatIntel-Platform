using System.Text.RegularExpressions;
using ThreatIntel.Api.Data;

namespace ThreatIntel.Api.Analysis;

/// <summary>
/// Bewertet Schwachstellen: Schweregrad, Angriffsmerkmale und eine Priorität für die Bearbeitung.
/// Regelbasiert und damit nachvollziehbar; die Kurzfassung kann zusätzlich ein Sprachmodell liefern.
/// </summary>
public sealed partial class ThreatAnalyzer
{
    private static readonly (string Tag, Regex Pattern)[] TagRules =
    {
        ("remote-code-execution", RceRegex()),
        ("exploited-in-the-wild", ExploitedRegex()),
        ("unauthenticated", UnauthenticatedRegex()),
        ("privilege-escalation", PrivilegeRegex()),
        ("sql-injection", SqlInjectionRegex()),
        ("cross-site-scripting", XssRegex()),
        ("authentication-bypass", AuthBypassRegex()),
        ("denial-of-service", DosRegex())
    };

    [GeneratedRegex(@"remote code execution|execute arbitrary code|arbitrary code execution", RegexOptions.IgnoreCase)]
    private static partial Regex RceRegex();

    [GeneratedRegex(@"actively exploited|exploited in the wild|known exploited", RegexOptions.IgnoreCase)]
    private static partial Regex ExploitedRegex();

    [GeneratedRegex(@"unauthenticated|without authentication|remote attacker", RegexOptions.IgnoreCase)]
    private static partial Regex UnauthenticatedRegex();

    [GeneratedRegex(@"privilege escalation|escalate privileges|elevation of privilege", RegexOptions.IgnoreCase)]
    private static partial Regex PrivilegeRegex();

    [GeneratedRegex(@"sql injection", RegexOptions.IgnoreCase)]
    private static partial Regex SqlInjectionRegex();

    [GeneratedRegex(@"cross-site scripting|\bxss\b", RegexOptions.IgnoreCase)]
    private static partial Regex XssRegex();

    [GeneratedRegex(@"authentication bypass|bypass authentication", RegexOptions.IgnoreCase)]
    private static partial Regex AuthBypassRegex();

    [GeneratedRegex(@"denial of service|\bdos\b", RegexOptions.IgnoreCase)]
    private static partial Regex DosRegex();

    [GeneratedRegex(@"(?<=[\.\!\?])\s")]
    private static partial Regex SentenceEndRegex();

    public static Severity SeverityFrom(double? cvss, string? reported)
    {
        if (cvss is { } score)
        {
            return score switch
            {
                >= 9.0 => Severity.Critical,
                >= 7.0 => Severity.High,
                >= 4.0 => Severity.Medium,
                > 0 => Severity.Low,
                _ => Severity.Unknown
            };
        }

        return Enum.TryParse<Severity>(reported, ignoreCase: true, out var parsed) ? parsed : Severity.Unknown;
    }

    public static IReadOnlyList<string> DetectTags(string description) =>
        TagRules.Where(r => r.Pattern.IsMatch(description)).Select(r => r.Tag).ToList();

    /// <summary>
    /// Priorität 0 bis 100: CVSS als Basis, Zuschläge für ausgenutzte Lücken, Codeausführung,
    /// fehlende Authentifizierung und Produkte auf der eigenen Beobachtungsliste.
    /// </summary>
    public static int Priority(double? cvss, IReadOnlyCollection<string> tags, bool onWatchlist)
    {
        var score = (cvss ?? 5.0) * 7.0;
        if (tags.Contains("exploited-in-the-wild")) score += 15;
        if (tags.Contains("remote-code-execution")) score += 10;
        if (tags.Contains("unauthenticated")) score += 5;
        if (onWatchlist) score += 15;
        return (int)Math.Round(Math.Clamp(score, 0, 100));
    }

    public static bool MatchesWatchlist(IEnumerable<string> products, IEnumerable<string> watchlist)
    {
        var watched = watchlist.ToList();
        return products.Any(p => watched.Any(w => p.Contains(w, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>Regelbasierte Kurzfassung: Schweregrad, Produkt und erster Satz der Beschreibung.</summary>
    public static string RuleBasedSummary(Severity severity, IReadOnlyList<string> products, string description)
    {
        var firstSentence = SentenceEndRegex().Split(description.Trim()).FirstOrDefault() ?? string.Empty;
        if (firstSentence.Length > 220)
        {
            firstSentence = firstSentence[..217].TrimEnd() + "...";
        }

        var product = products.Count > 0 ? products[0] : "unbekanntem Produkt";
        return $"{GermanSeverity(severity)} Schwachstelle in {product}: {firstSentence}";
    }

    public static string GermanSeverity(Severity severity) => severity switch
    {
        Severity.Critical => "Kritische",
        Severity.High => "Hohe",
        Severity.Medium => "Mittlere",
        Severity.Low => "Niedrige",
        _ => "Nicht bewertete"
    };
}
