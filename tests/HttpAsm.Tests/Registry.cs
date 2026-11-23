using System.Reflection;

namespace HttpAsm.Tests;

/// <summary>One row of specs/requirements.tsv (its columns, minus the section title).</summary>
/// <param name="Id">The row's id, as tests name it.</param>
/// <param name="Document">The document's id ("RFC9112").</param>
/// <param name="Section">The section number.</param>
/// <param name="Keyword">The BCP 14 keyword, or "ABNF" for a grammar block.</param>
/// <param name="Actor">The guessed subject the row binds, or empty.</param>
/// <param name="Milestone">The milestone that implements the document.</param>
/// <param name="Url">The RFC Editor's HTML at the row's paragraph or section.</param>
/// <param name="Text">The sentence, or the grammar block.</param>
internal sealed record RegistryRow(
    string Id, string Document, string Section, string Keyword, string Actor, string Milestone, string Url, string Text);

/// <summary>The requirement registry, as copied next to the test assembly, and the tests that name its rows.</summary>
internal static class Registry
{
    /// <summary>The rows by id, read once.</summary>
    private static readonly Lazy<IReadOnlyDictionary<string, RegistryRow>> LazyRows = new(Load);

    /// <summary>Every row, by id.</summary>
    /// <exception cref="FileNotFoundException">specs/requirements.tsv was not copied next to the tests.</exception>
    /// <exception cref="InvalidDataException">A line does not have the registry's nine columns.</exception>
    public static IReadOnlyDictionary<string, RegistryRow> Rows => LazyRows.Value;

    /// <summary>Every [Requirement] in this assembly: the test method and the ids it names.</summary>
    /// <returns>One pair per id per test.</returns>
    public static IEnumerable<(MethodInfo Test, string Id)> NamedByTests() =>
        typeof(Registry).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            .SelectMany(m => m.GetCustomAttributes<RequirementAttribute>().SelectMany(a => a.Ids.Select(id => (m, id))));

    /// <summary>Reads the registry.</summary>
    /// <returns>The rows by id.</returns>
    /// <exception cref="FileNotFoundException">The file is missing.</exception>
    /// <exception cref="InvalidDataException">A line has the wrong number of columns.</exception>
    private static IReadOnlyDictionary<string, RegistryRow> Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "specs", "requirements.tsv");
        var rows = new Dictionary<string, RegistryRow>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(path).Skip(1)) // the header
        {
            // id, document, section, title, keyword, actor, milestone, url, text
            string[] f = line.Split('\t');
            if (f.Length != 9)
            {
                throw new InvalidDataException($"{path}: expected 9 columns, found {f.Length}: {line}");
            }

            rows.Add(f[0], new RegistryRow(f[0], f[1], f[2], f[4], f[5], f[6], f[7], f[8]));
        }

        return rows;
    }
}
