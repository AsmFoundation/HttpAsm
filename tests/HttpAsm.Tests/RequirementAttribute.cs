namespace HttpAsm.Tests;

/// <summary>
/// Names the rows of specs/requirements.tsv that a test proves, by their ids
/// ("RFC9110-5.5-5#1"). RegistryTests fails when a named id is not in the registry, so a typo
/// cannot claim coverage that does not exist, and it reports which rows no test names yet.
/// </summary>
/// <param name="ids">The row ids, as specs/specs.cs extracts them (see its header for the forms).</param>
/// <remarks>
/// Name a row only when the test checks what the row requires. A MAY that HttpAsm chooses not to
/// do (keeping CTLs in field values, say) is proven by a test of the choice it made instead.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
internal sealed class RequirementAttribute(params string[] ids) : Attribute
{
    /// <summary>The row ids.</summary>
    public IReadOnlyList<string> Ids { get; } = ids;
}
