namespace HttpAsm.Tests;

/// <summary>
/// The tests' claims against the registry: every [Requirement] names a real row, and a report
/// shows how many rows of each document the tests prove so far.
/// </summary>
/// <param name="output">Receives the coverage report.</param>
public sealed class RegistryTests(ITestOutputHelper output)
{
    /// <summary>The documents specs/documents.json pins; the registry must hold rows of each.</summary>
    private static readonly string[] Documents =
        ["RFC9110", "RFC9111", "RFC9112", "RFC9113", "RFC7541", "RFC8446", "RFC9000", "RFC9001", "RFC9002", "RFC9114", "RFC9204"];

    /// <summary>A typo in a [Requirement] would claim a proof of nothing: every id must be a row.</summary>
    [Fact]
    public void EveryNamedRequirementExists()
    {
        string[] unknown = Registry.NamedByTests()
            .Where(n => !Registry.Rows.ContainsKey(n.Id))
            .Select(n => $"{n.Test.DeclaringType?.Name}.{n.Test.Name}: {n.Id}")
            .ToArray();
        Assert.True(unknown.Length == 0, "Not in specs/requirements.tsv:\n" + string.Join('\n', unknown));
    }

    /// <summary>
    /// How many rows of each document the tests name, by milestone. A report, not a gate yet:
    /// docs/DESIGN.md's M1 exit criteria turn it into one for the M1 documents.
    /// </summary>
    [Fact]
    public void CoverageReport()
    {
        HashSet<string> proven = Registry.NamedByTests().Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        Assert.All(Documents, d => Assert.Contains(Registry.Rows.Values, r => r.Document == d));

        output.WriteLine($"{"document",-9} {"milestone",-9} {"rows",6} {"proven",7}");
        foreach (var document in Registry.Rows.Values.GroupBy(r => r.Document))
        {
            int rows = document.Count();
            int named = document.Count(r => proven.Contains(r.Id));
            output.WriteLine($"{document.Key,-9} {document.First().Milestone,-9} {rows,6} {named,7}");
        }

        output.WriteLine($"{"total",-9} {"",-9} {Registry.Rows.Count,6} {proven.Count,7}");
    }

    /// <summary>The documents milestone 1 must account for, row by row (docs/DESIGN.md, M1's exit):
    /// the semantics, HTTP/1.1, HTTP/2, HPACK, and RFC 6585's status codes (the server sends its
    /// 431), every document specs/documents.json assigns to M1.</summary>
    private static readonly string[] M1Documents = ["RFC9110", "RFC9112", "RFC9113", "RFC7541", "RFC6585"];

    /// <summary>
    /// M1's gate: every row of RFC 9110, 9112, 9113 and 7541 is proven by a test that names it,
    /// or deferred in specs/deferred.tsv with a milestone and a reason. A row's reason is the
    /// first rule in the file that matches it, so a narrow rule placed before a broad one speaks
    /// for its rows. Two kinds of staleness fail the gate too, so the file cannot drift into
    /// claiming that done work is pending: an exact-id rule for a row a test proves, and a rule
    /// that is the first match of no unproven row at all (it defers nothing). The report gives,
    /// per document, the rows proven and the rows deferred, by milestone.
    /// </summary>
    [Fact]
    public void AccountsForEveryM1Row()
    {
        HashSet<string> proven = Registry.NamedByTests().Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        IReadOnlyList<Deferral> deferrals = Deferral.Load();
        var used = new HashSet<Deferral>();
        var unaccounted = new List<string>();
        foreach (string document in M1Documents)
        {
            var rows = Registry.Rows.Values.Where(r => r.Document == document).ToList();
            int byTest = rows.Count(r => proven.Contains(r.Id));
            var byMilestone = new SortedDictionary<string, int>(StringComparer.Ordinal);
            foreach (RegistryRow row in rows.Where(r => !proven.Contains(r.Id)))
            {
                Deferral? rule = deferrals.FirstOrDefault(d => d.Matches(row));
                if (rule is null)
                {
                    unaccounted.Add($"{row.Id} ({row.Keyword}, {row.Actor}): {row.Text[..Math.Min(100, row.Text.Length)]}");
                    continue;
                }

                used.Add(rule);
                byMilestone[rule.Milestone] = byMilestone.GetValueOrDefault(rule.Milestone) + 1;
            }

            output.WriteLine($"{document}: {rows.Count} rows, {byTest} proven by tests, {byMilestone.Values.Sum()} deferred ("
                + string.Join(", ", byMilestone.Select(m => $"{m.Key} {m.Value}")) + ")");
        }

        string[] stale = deferrals.Where(d => !d.Match.Contains('*') && proven.Contains(d.Match)).Select(d => d.Match).ToArray();
        Assert.True(stale.Length == 0, "Deferred but proven (remove the deferral):\n" + string.Join('\n', stale));
        string[] idle = deferrals.Where(d => !used.Contains(d)).Select(d => $"{d.Match} {d.Actor} {d.Keyword}".TrimEnd()).ToArray();
        Assert.True(idle.Length == 0, "Rules that defer no row (remove them, or move them before the rule that takes their rows):\n" + string.Join('\n', idle));
        Assert.True(unaccounted.Count == 0, $"{unaccounted.Count} rows neither proven nor deferred:\n" + string.Join('\n', unaccounted));
    }
}

/// <summary>
/// One rule of specs/deferred.tsv: rows it matches are not proven in milestone 1, for the reason
/// it gives. Columns: match (an id, or a glob with * over ids), actor (empty: any), keyword
/// (empty: any), milestone (where the work belongs), reason.
/// </summary>
/// <param name="Match">The id or glob.</param>
/// <param name="Actor">The actor the rows must have, or empty.</param>
/// <param name="Keyword">The keyword the rows must have, or empty.</param>
/// <param name="Milestone">Where the work belongs.</param>
/// <param name="Reason">Why it is not M1's, or why no test proves it.</param>
internal sealed record Deferral(string Match, string Actor, string Keyword, string Milestone, string Reason)
{
    /// <summary>Whether the rule covers a row.</summary>
    /// <param name="row">The row.</param>
    /// <returns>True when it matches.</returns>
    public bool Matches(RegistryRow row) =>
        System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(Match, row.Id, ignoreCase: false)
        && (Actor.Length == 0 || Actor == row.Actor)
        && (Keyword.Length == 0 || Keyword == row.Keyword);

    /// <summary>Reads specs/deferred.tsv (copied next to the tests); lines starting with # are comments.</summary>
    /// <returns>The rules.</returns>
    /// <exception cref="InvalidDataException">A rule does not have five columns, or has an empty reason.</exception>
    public static IReadOnlyList<Deferral> Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "specs", "deferred.tsv");
        var rules = new List<Deferral>();
        foreach (string line in File.ReadLines(path))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            string[] f = line.Split('\t');
            if (f.Length != 5 || f[4].Trim().Length == 0)
            {
                throw new InvalidDataException($"{path}: a rule needs match, actor, keyword, milestone and a reason: {line}");
            }

            rules.Add(new Deferral(f[0], f[1], f[2], f[3], f[4]));
        }

        return rules;
    }
}
