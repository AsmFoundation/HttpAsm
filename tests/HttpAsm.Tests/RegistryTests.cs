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
}
