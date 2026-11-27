namespace HttpAsm.Tests;

/// <summary>
/// The official test vectors tests/tools.sh fetches (pinned by SHA-256) into tests/.tools/:
/// NIST's CAVP response files and, as M2 goes on, Project Wycheproof's. tests/run-linux.sh names
/// that directory in HTTPASM_VECTORS and sets HTTPASM_REQUIRE_VECTORS=1, so there a missing file
/// fails the test; elsewhere (an IDE run without the tools) the test is skipped and says why.
/// </summary>
internal static class Vectors
{
    /// <summary>
    /// The path of a vector file. A missing file ends the calling test: with Assert.Fail when
    /// HTTPASM_REQUIRE_VECTORS is 1, else with Assert.Skip (xunit's exceptions for both).
    /// </summary>
    /// <param name="relative">The file under the tools directory, as tools.sh lays it out
    /// (e.g. "cavp/shabytetestvectors/SHA256ShortMsg.rsp").</param>
    /// <returns>The file's full path; it exists.</returns>
    public static string Path(string relative)
    {
        string? root = Environment.GetEnvironmentVariable("HTTPASM_VECTORS");
        string? path = string.IsNullOrEmpty(root) ? null : System.IO.Path.Combine(root, relative);
        if (path is not null && File.Exists(path))
        {
            return path;
        }

        string reason = $"{relative} is not there (HTTPASM_VECTORS = '{root}'); tests/tools.sh fetches it, tests/run-linux.sh names it.";
        if (Environment.GetEnvironmentVariable("HTTPASM_REQUIRE_VECTORS") == "1")
        {
            Assert.Fail(reason);
        }

        Assert.Skip(reason);
        return null!;                       // Assert.Skip throws: never reached
    }

    /// <summary>
    /// The records of a CAVP response file: each a group of "Name = value" lines separated by a
    /// blank line, comments (#) left out. A bracketed line ("[L = 32]", "[L=32]") sets a section
    /// parameter that every following record carries as a field of its own ("L" = "32"), until
    /// the next section sets it again: HMAC.rsp keeps each hash's MACs in an [L=...] section. A
    /// bracketed line without "=" ("[P-256,SHA-256]", "[ENCRYPT]") becomes the field "Section"
    /// (its text between the brackets): ECDSA's files name a record's curve and hash that way.
    /// </summary>
    /// <param name="path">The .rsp file.</param>
    /// <returns>Each record's fields by name, in file order.</returns>
    public static IEnumerable<Dictionary<string, string>> CavpRecords(string path)
    {
        var section = new Dictionary<string, string>(StringComparer.Ordinal);
        var record = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in File.ReadLines(path))
        {
            string line = raw.Trim();
            if (line.Length == 0)
            {
                if (record.Count > 0)
                {
                    foreach (KeyValuePair<string, string> parameter in section)
                    {
                        record.TryAdd(parameter.Key, parameter.Value);
                    }

                    yield return record;
                    record = new Dictionary<string, string>(StringComparer.Ordinal);
                }

                continue;
            }

            if (line.StartsWith('#'))
            {
                continue;
            }

            bool bracketed = line.StartsWith('[') && line.EndsWith(']');
            string body = bracketed ? line[1..^1] : line;
            int equals = body.IndexOf('=');
            if (equals > 0)
            {
                (bracketed ? section : record)[body[..equals].Trim()] = body[(equals + 1)..].Trim();
            }
            else if (bracketed)
            {
                section["Section"] = body.Trim();
            }
        }

        if (record.Count > 0)
        {
            foreach (KeyValuePair<string, string> parameter in section)
            {
                record.TryAdd(parameter.Key, parameter.Value);
            }

            yield return record;
        }
    }

    /// <summary>
    /// The tests of a Project Wycheproof file (testvectors_v1/*.json): every test of every group,
    /// each with its group's fields (keySize, tagSize, ...) under "group".
    /// </summary>
    /// <param name="path">The JSON file.</param>
    /// <returns>(group, test) pairs in file order.</returns>
    public static IEnumerable<(System.Text.Json.JsonElement Group, System.Text.Json.JsonElement Test)> WycheproofTests(string path)
    {
        using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path));
        var pairs = new List<(System.Text.Json.JsonElement, System.Text.Json.JsonElement)>();
        foreach (System.Text.Json.JsonElement group in document.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            foreach (System.Text.Json.JsonElement test in group.GetProperty("tests").EnumerateArray())
            {
                pairs.Add((group.Clone(), test.Clone()));
            }
        }

        return pairs;
    }
}
