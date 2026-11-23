// =============================================================================
// specs.cs - HttpAsm's official documents, and the requirement registry built from them.
//
// HttpAsm follows the official documents, not other implementations (the owner's decision,
// 2026-11-21). Every MUST, SHOULD and MAY of the RFCs it implements becomes a row of
// specs/requirements.tsv, and a test names the rows it proves:
// [Requirement("RFC9112-6.3-2.1")]. The test project checks that every name exists, and
// reports which rows no test proves yet.
//
// Commands (a .NET 10 file-based app; run them from the repository root):
//   dotnet run specs/specs.cs -- fetch [--update]   download the pinned files into specs/rfc/
//   dotnet run specs/specs.cs -- extract [--check]  write requirements.tsv (--check: verify it)
//   dotnet run specs/specs.cs -- stats              rows per document and keyword
//
// fetch checks each download against its SHA-256 in documents.json. --update pins the hash
// instead: the first download, or a deliberate change of a pinned file. RFCs never change once
// published, so a mismatch means the RFC Editor re-rendered a file, and a human decides.
// extract only reads files whose hashes match the pins, so the registry always comes from the
// pinned documents. --check fails when requirements.tsv differs from what they produce (CI).
//
// Row ids:
//   XML (RFCXML v3, published from 2019 on): RFC<n>-<pn>. <pn> is the paragraph number that
//     the RFC Editor's prepped XML carries and its HTML uses as an anchor:
//     "section-6.3-2.1" gives RFC9112-6.3-2.1; "section-appendix.a-2" gives RFC9112-A-2.
//     When one paragraph holds several keywords, each gets #1, #2, ... in document order.
//   Text (older RFCs, no pn): RFC<n>-<section>-p<k>, with k counting the section's paragraphs
//     from 1. These numbers are ours: the RFC Editor's HTML has no paragraph anchors there.
// Rows whose keyword is "ABNF" are the XML documents' grammar blocks (sourcecode type abnf*),
// so a syntax test can name the rule it proves. The collected-ABNF appendix repeats those
// blocks and is skipped. Keywords in quotes (the BCP 14 boilerplate that defines them) are not
// requirements and are skipped too.
//
// Exit status: 0 success; 1 a check failed (a hash, a missing file, an out-of-date registry);
// 2 wrong usage.
// =============================================================================
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

if (args.Length == 0)
{
    return Cli.Usage();
}

string specs = Path.GetFullPath("specs");
if (!File.Exists(Path.Combine(specs, "documents.json")))
{
    Console.Error.WriteLine("specs: run this from the repository root (specs/documents.json was not found)");
    return 2;
}

try
{
    return args[0] switch
    {
        "fetch" => await Commands.FetchAsync(specs, args.Contains("--update")),
        "extract" => Commands.Extract(specs, args.Contains("--check")),
        "stats" => Commands.Stats(specs),
        _ => Cli.Usage(),
    };
}
catch (SpecsException e)
{
    // A failed check: say which, and leave every file as it was.
    Console.Error.WriteLine($"specs: {e.Message}");
    return 1;
}

/// <summary>A check that failed: a hash, a missing file, or a registry that is out of date.</summary>
/// <param name="message">What failed and how to fix it; printed as the tool's last line.</param>
internal sealed class SpecsException(string message) : Exception(message);

/// <summary>The command line's help.</summary>
internal static class Cli
{
    /// <summary>Prints the usage to standard error.</summary>
    /// <returns>2, the exit status for wrong usage.</returns>
    public static int Usage()
    {
        Console.Error.WriteLine("usage: dotnet run specs/specs.cs -- fetch [--update] | extract [--check] | stats");
        return 2;
    }
}

/// <summary>One official document, as specs/documents.json lists it.</summary>
/// <param name="Id">The registry's prefix for its rows, such as "RFC9112".</param>
/// <param name="Title">The document's title.</param>
/// <param name="Format">"xml" (prepped RFCXML v3, where every paragraph has a pn) or "txt" (an
/// older RFC's text file).</param>
/// <param name="Milestone">The docs/DESIGN.md milestone that implements it, or "open".</param>
/// <param name="Url">Where the RFC Editor publishes the file.</param>
/// <param name="Html">The RFC Editor's HTML rendering, whose anchors the rows link to.</param>
/// <param name="LocalFile">The pinned copy, relative to specs/.</param>
/// <param name="Sha256">The pinned SHA-256 in lowercase hex; empty until fetch --update.</param>
internal sealed record Document(
    string Id, string Title, string Format, string Milestone, string Url, string Html, string LocalFile, string Sha256);

/// <summary>One row of specs/requirements.tsv.</summary>
/// <param name="Id">The stable name tests use, such as "RFC9112-6.3-2.1" (see the file header).</param>
/// <param name="Document">The document's id, such as "RFC9112".</param>
/// <param name="Section">The section number ("6.3", "A.1"), or empty in front matter.</param>
/// <param name="Title">The section's title.</param>
/// <param name="Keyword">The BCP 14 keyword ("MUST NOT", "MAY", ...), or "ABNF" for a grammar block.</param>
/// <param name="Actor">Who the sentence binds, guessed from its subject ("server", "recipient", ...),
/// or empty when no subject is recognized. A guess, for sorting and filtering only.</param>
/// <param name="Milestone">The document's milestone, copied for filtering.</param>
/// <param name="Url">The RFC Editor's HTML, anchored at the paragraph (XML) or the section (text).</param>
/// <param name="Text">The sentence holding the keyword, or the grammar block, on one line.</param>
internal sealed record Requirement(
    string Id, string Document, string Section, string Title, string Keyword, string Actor, string Milestone,
    string Url, string Text);

/// <summary>Reads specs/documents.json and records new hashes in it.</summary>
internal static partial class Documents
{
    /// <summary>The "sha256" field of a document line, whatever hash it holds now.</summary>
    [GeneratedRegex("\"sha256\": \"[0-9a-f]*\"")]
    private static partial Regex ShaField();

    /// <summary>Reads every document, in the file's order.</summary>
    /// <param name="specs">The specs/ folder.</param>
    /// <returns>The documents.</returns>
    /// <exception cref="SpecsException">The file lacks the documents array or a field.</exception>
    public static IReadOnlyList<Document> Load(string specs)
    {
        JsonNode root = JsonNode.Parse(File.ReadAllText(Path.Combine(specs, "documents.json")))
            ?? throw new SpecsException("documents.json is empty");
        JsonArray list = root["documents"]?.AsArray()
            ?? throw new SpecsException("documents.json has no \"documents\" array");

        var documents = new List<Document>();
        foreach (JsonNode? node in list)
        {
            // Every field is required: a document without its milestone or hash field is a
            // mistake in the file, not a default.
            string Get(string name) => node?[name]?.GetValue<string>()
                ?? throw new SpecsException($"documents.json: a document lacks \"{name}\"");

            documents.Add(new Document(
                Get("id"), Get("title"), Get("format"), Get("milestone"), Get("url"), Get("html"), Get("file"),
                Get("sha256")));
        }

        return documents;
    }

    /// <summary>Records a document's new SHA-256 in documents.json.</summary>
    /// <param name="specs">The specs/ folder.</param>
    /// <param name="id">The document's id.</param>
    /// <param name="sha256">The hash to pin, lowercase hex.</param>
    /// <exception cref="SpecsException">No line of the file holds that document.</exception>
    /// <remarks>
    /// The file keeps one document per line, so the hash is replaced on that line alone. A
    /// JSON writer would expand every object over several lines and turn each re-pin into a
    /// diff of the whole file.
    /// </remarks>
    public static void Pin(string specs, string id, string sha256)
    {
        string path = Path.Combine(specs, "documents.json");
        string[] lines = File.ReadAllLines(path);
        int index = Array.FindIndex(lines, l => l.Contains($"\"id\": \"{id}\"", StringComparison.Ordinal));
        if (index < 0 || !ShaField().IsMatch(lines[index]))
        {
            throw new SpecsException($"documents.json: no single line holds {id} and its \"sha256\" field");
        }

        lines[index] = ShaField().Replace(lines[index], $"\"sha256\": \"{sha256}\"", 1);
        File.WriteAllText(path, string.Join('\n', lines) + "\n", new UTF8Encoding(false));
    }
}

/// <summary>The three commands.</summary>
internal static class Commands
{
    /// <summary>Downloads every document and checks it against its pinned hash.</summary>
    /// <param name="specs">The specs/ folder.</param>
    /// <param name="update">Pin new or changed hashes instead of failing on them.</param>
    /// <returns>0 when every file was written.</returns>
    /// <exception cref="SpecsException">A hash is missing or differs, and <paramref name="update"/>
    /// is false. Files fetched before that one stay written; that one and later ones are not.</exception>
    /// <exception cref="HttpRequestException">A download failed.</exception>
    public static async Task<int> FetchAsync(string specs, bool update)
    {
        using var http = new HttpClient();
        // A generic client name: the RFC Editor's servers need no contact details.
        http.DefaultRequestHeaders.UserAgent.ParseAdd("HttpAsm-specs/0.1 (+https://github.com/AsmFoundation/HttpAsm)");

        foreach (Document d in Documents.Load(specs))
        {
            byte[] bytes = await http.GetByteArrayAsync(d.Url);
            string hash = Hash(bytes);
            if (hash != d.Sha256)
            {
                if (!update)
                {
                    throw new SpecsException(d.Sha256.Length == 0
                        ? $"{d.Id}: no pinned SHA-256 yet; fetch --update pins {hash}"
                        : $"{d.Id}: {d.Url} changed: SHA-256 {hash}, pinned {d.Sha256}. Compare the files, then fetch --update re-pins it on purpose");
                }

                Documents.Pin(specs, d.Id, hash);
            }

            string path = Path.Combine(specs, d.LocalFile);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllBytesAsync(path, bytes);
            Console.WriteLine($"{d.Id}: {bytes.Length,9:N0} bytes, SHA-256 {hash}");
        }

        return 0;
    }

    /// <summary>Builds the registry from the pinned files, and writes or checks requirements.tsv.</summary>
    /// <param name="specs">The specs/ folder.</param>
    /// <param name="check">Compare with the committed requirements.tsv instead of writing it.</param>
    /// <returns>0 when the registry was written, or matches.</returns>
    /// <exception cref="SpecsException">A file is missing or does not match its pin; two rows got
    /// the same id (an extractor bug); or, with <paramref name="check"/>, the committed registry
    /// differs from the generated one.</exception>
    public static int Extract(string specs, bool check)
    {
        var rows = new List<Requirement>();
        foreach (Document d in Documents.Load(specs))
        {
            string path = Path.Combine(specs, d.LocalFile);
            if (!File.Exists(path))
            {
                throw new SpecsException($"{d.Id}: {d.LocalFile} is missing; run fetch");
            }

            // The registry must come from the pinned bytes, never from a file edited by hand.
            if (d.Sha256.Length == 0 || Hash(File.ReadAllBytes(path)) != d.Sha256)
            {
                throw new SpecsException($"{d.Id}: {d.LocalFile} does not match its pinned SHA-256; run fetch");
            }

            rows.AddRange(d.Format switch
            {
                "xml" => new XmlExtractor(d, path).Extract(),
                "txt" => TextExtractor.Extract(d, path),
                _ => throw new SpecsException($"{d.Id}: unknown format \"{d.Format}\""),
            });
        }

        string? duplicate = rows.GroupBy(r => r.Id).FirstOrDefault(g => g.Count() > 1)?.Key;
        if (duplicate is not null)
        {
            throw new SpecsException($"two rows have the id {duplicate}: the extractor is wrong");
        }

        string tsv = Tsv.Format(rows);
        string target = Path.Combine(specs, "requirements.tsv");
        if (check)
        {
            // Line endings aside (a Windows checkout may add CRs), the file must match byte for byte.
            string current = File.Exists(target) ? File.ReadAllText(target).Replace("\r\n", "\n") : "";
            if (current != tsv)
            {
                throw new SpecsException("requirements.tsv is out of date: run extract and commit it");
            }

            Console.WriteLine($"requirements.tsv is current: {rows.Count:N0} rows");
            return 0;
        }

        File.WriteAllText(target, tsv, new UTF8Encoding(false));
        Console.WriteLine($"requirements.tsv: {rows.Count:N0} rows");
        return Stats(specs);
    }

    /// <summary>Prints the rows per document and keyword.</summary>
    /// <param name="specs">The specs/ folder.</param>
    /// <returns>0.</returns>
    /// <exception cref="SpecsException">requirements.tsv is missing.</exception>
    public static int Stats(string specs)
    {
        string target = Path.Combine(specs, "requirements.tsv");
        if (!File.Exists(target))
        {
            throw new SpecsException("requirements.tsv is missing; run extract");
        }

        // Column 1 is the document, column 4 the keyword (see Tsv.Header).
        var rows = File.ReadAllLines(target).Skip(1).Select(l => l.Split('\t')).ToList();
        string[] keywords = ["MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
            "RECOMMENDED", "NOT RECOMMENDED", "MAY", "OPTIONAL"];
        Console.WriteLine($"{"document",-9} {"BCP 14",7} {"MUST",6} {"MUST NOT",9} {"SHOULD",7} {"SHOULD NOT",11} {"MAY",5} {"other",6} {"ABNF",6}");
        foreach (var byDocument in rows.GroupBy(r => r[1]))
        {
            int Count(string keyword) => byDocument.Count(r => r[4] == keyword);
            int bcp14 = byDocument.Count(r => keywords.Contains(r[4]));
            int other = bcp14 - Count("MUST") - Count("MUST NOT") - Count("SHOULD") - Count("SHOULD NOT") - Count("MAY");
            Console.WriteLine($"{byDocument.Key,-9} {bcp14,7} {Count("MUST"),6} {Count("MUST NOT"),9} {Count("SHOULD"),7} {Count("SHOULD NOT"),11} {Count("MAY"),5} {other,6} {Count("ABNF"),6}");
        }

        int total = rows.Count(r => keywords.Contains(r[4]));
        Console.WriteLine($"{"total",-9} {total,7}   ({rows.Count(r => r[4] == "ABNF")} ABNF blocks)");
        return 0;
    }

    /// <summary>The SHA-256 of some bytes.</summary>
    /// <param name="bytes">The bytes.</param>
    /// <returns>Lowercase hex, as documents.json stores it.</returns>
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}

/// <summary>Writes the registry's tab-separated format.</summary>
internal static class Tsv
{
    /// <summary>The header line: the columns of <see cref="Requirement"/>, in order.</summary>
    public const string Header = "id\tdocument\tsection\ttitle\tkeyword\tactor\tmilestone\turl\ttext";

    /// <summary>Formats the rows, one per line, after the header.</summary>
    /// <param name="rows">The rows, in registry order.</param>
    /// <returns>The file's text, with LF line endings and a final LF.</returns>
    /// <remarks>Fields hold no tabs or line breaks: every text field went through
    /// <see cref="Prose.Normalize"/>, which turns runs of whitespace into one space.</remarks>
    public static string Format(IEnumerable<Requirement> rows)
    {
        var text = new StringBuilder(Header).Append('\n');
        foreach (Requirement r in rows)
        {
            text.Append(r.Id).Append('\t').Append(r.Document).Append('\t').Append(r.Section).Append('\t')
                .Append(r.Title).Append('\t').Append(r.Keyword).Append('\t').Append(r.Actor).Append('\t')
                .Append(r.Milestone).Append('\t').Append(r.Url).Append('\t').Append(r.Text).Append('\n');
        }

        return text.ToString();
    }
}

/// <summary>Sentences, whitespace and subjects of the documents' prose.</summary>
internal static partial class Prose
{
    /// <summary>Marks where the keyword being extracted starts in rendered text (never in an RFC).</summary>
    public const char MarkStart = '\u0001';

    /// <summary>Marks where it ends.</summary>
    public const char MarkEnd = '\u0002';

    /// <summary>Any run of whitespace, NO-BREAK SPACE included (.NET's \s covers \p{Z}).</summary>
    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    /// <summary>
    /// The subjects a requirement binds, singular or plural. Longer names come first, so that
    /// "origin server" wins over "server" and "intermediaries" over "intermediary".
    /// </summary>
    [GeneratedRegex(
        @"\b(origin servers?|user agents?|intermediaries|intermediary|recipients?|senders?|servers?|clients?|proxies|proxy|gateways?|caches?|endpoints?|implementations?|peers?|decoders?|encoders?|receivers?|parsers?|tunnels?)\b",
        RegexOptions.IgnoreCase)]
    private static partial Regex Subject();

    /// <summary>Puts text on one line: runs of whitespace become one space; the ends are trimmed.</summary>
    /// <param name="text">The text.</param>
    /// <returns>The normalized text.</returns>
    public static string Normalize(string text) => Whitespace().Replace(text, " ").Trim();

    /// <summary>The sentence around a keyword.</summary>
    /// <param name="text">The paragraph, normalized.</param>
    /// <param name="at">Where the keyword starts in it.</param>
    /// <param name="length">The keyword's length.</param>
    /// <param name="keywordAt">Receives where the keyword starts in the returned sentence.</param>
    /// <returns>The sentence: from after the previous sentence's end to this one's end.</returns>
    /// <remarks>
    /// A sentence ends at ".", "?" or "!" followed by a space or the paragraph's end, unless
    /// the word before the period is an abbreviation ("e.g.", "i.e."). Section numbers at a
    /// sentence's end ("... Section 5.5.") still end it. A heuristic: the row's URL leads
    /// to the whole paragraph.
    /// </remarks>
    public static string Sentence(string text, int at, int length, out int keywordAt)
    {
        int start = 0;
        for (int i = at - 1; i > 0; i--)
        {
            if (EndsSentence(text, i))
            {
                start = i + 2; // past the period and its space
                break;
            }
        }

        int end = text.Length;
        for (int i = at + length; i < text.Length; i++)
        {
            if (EndsSentence(text, i))
            {
                end = i + 1;
                break;
            }
        }

        keywordAt = at - start;
        return text[start..end];
    }

    /// <summary>Guesses who a requirement binds: the last subject named before its keyword.</summary>
    /// <param name="sentence">The sentence.</param>
    /// <param name="keywordAt">Where the keyword starts in it.</param>
    /// <returns>The subject in the singular, lowercase ("server", "intermediary"), or empty.</returns>
    public static string Actor(string sentence, int keywordAt)
    {
        Match? last = null;
        foreach (Match m in Subject().Matches(sentence[..keywordAt]))
        {
            last = m;
        }

        if (last is null)
        {
            return "";
        }

        string word = last.Value.ToLowerInvariant();
        return word switch
        {
            "intermediaries" => "intermediary",
            "proxies" => "proxy",
            _ when word.EndsWith('s') => word[..^1],
            _ => word,
        };
    }

    /// <summary>Whether the character at <paramref name="i"/> ends a sentence.</summary>
    /// <param name="text">The paragraph.</param>
    /// <param name="i">The index of a candidate ".", "?" or "!".</param>
    /// <returns>True when it is one, followed by a space or the end, and not an abbreviation's period.</returns>
    private static bool EndsSentence(string text, int i)
    {
        if (text[i] is not ('.' or '?' or '!') || (i + 1 < text.Length && text[i + 1] != ' '))
        {
            return false;
        }

        // The word before the period: "e.g" and "i.e" are abbreviations, not sentence ends.
        int wordStart = text.LastIndexOf(' ', i) + 1;
        string word = text[wordStart..i];
        return word is not ("e.g" or "i.e" or "(e.g" or "(i.e" or "cf" or "vs");
    }
}

/// <summary>Extracts the rows of one prepped RFCXML v3 document.</summary>
/// <remarks>
/// Prepped XML numbers every block with a pn attribute ("section-6.3-2.1"), which is the
/// anchor the RFC Editor's HTML uses, and wraps every BCP 14 keyword in a bcp14 element. Both
/// make the extraction exact: no keyword is guessed from capital letters.
/// </remarks>
internal sealed class XmlExtractor
{
    /// <summary>The document being read.</summary>
    private readonly Document document;

    /// <summary>The parsed file.</summary>
    private readonly XDocument xml;

    /// <summary>The anchors of the bibliography's references: an xref to one renders as "[HTTP]".</summary>
    private readonly HashSet<string> references;

    /// <summary>Loads a document's pinned XML file.</summary>
    /// <param name="document">The document.</param>
    /// <param name="path">Its pinned file.</param>
    /// <exception cref="XmlException">The file is not well-formed XML.</exception>
    public XmlExtractor(Document document, string path)
    {
        this.document = document;

        // Prepped RFC XML may declare entities in an internal DTD subset, which the default
        // settings refuse. Parse that subset, but never fetch anything external.
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null };
        using XmlReader reader = XmlReader.Create(path, settings);
        xml = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        references = xml.Descendants("reference")
            .Select(r => (string?)r.Attribute("anchor"))
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>The document's rows: its BCP 14 keywords and grammar blocks, in document order.</summary>
    /// <returns>The rows.</returns>
    public IEnumerable<Requirement> Extract()
    {
        // Document order of every element, so keyword and grammar rows interleave as in the RFC.
        var order = new Dictionary<XElement, int>();
        foreach (XElement e in xml.Descendants())
        {
            order[e] = order.Count;
        }

        var rows = new List<(int Position, Requirement Row)>();

        // Keywords, grouped by their paragraph: the nearest enclosing element with a pn.
        foreach (var paragraph in xml.Descendants("bcp14").Where(b => !IsQuoted(b))
                     .GroupBy(b => b.Ancestors().First(a => a.Attribute("pn") is not null)))
        {
            List<XElement> keywords = paragraph.ToList();
            string pn = paragraph.Key.Attribute("pn")!.Value;
            (string section, string title) = SectionOf(paragraph.Key);
            for (int k = 0; k < keywords.Count; k++)
            {
                // Render the paragraph with this keyword marked, so its position survives the
                // whitespace normalization; then cut the sentence around it.
                var text = new StringBuilder();
                Render(paragraph.Key, keywords[k], text);
                string marked = Prose.Normalize(text.ToString());
                int at = marked.IndexOf(Prose.MarkStart);
                int length = marked.IndexOf(Prose.MarkEnd) - at - 1;
                string plain = marked.Replace(Prose.MarkStart.ToString(), "").Replace(Prose.MarkEnd.ToString(), "");
                string sentence = Prose.Sentence(plain, at, length, out int keywordAt);

                string id = $"{document.Id}-{Anchor(pn)}" + (keywords.Count > 1 ? $"#{k + 1}" : "");
                rows.Add((order[keywords[k]], new Requirement(
                    id, document.Id, section, title, Prose.Normalize(keywords[k].Value),
                    Prose.Actor(sentence, keywordAt), document.Milestone, $"{document.Html}#{pn}", sentence)));
            }
        }

        // Grammar blocks, except the collected-ABNF appendix, which repeats them all.
        foreach (XElement code in xml.Descendants("sourcecode").Where(IsGrammar))
        {
            string pn = code.Attribute("pn")!.Value;
            (string section, string title) = SectionOf(code);
            rows.Add((order[code], new Requirement(
                $"{document.Id}-{Anchor(pn)}", document.Id, section, title, "ABNF", "", document.Milestone,
                $"{document.Html}#{pn}", Prose.Normalize(code.Value))));
        }

        return rows.OrderBy(r => r.Position).Select(r => r.Row);
    }

    /// <summary>Turns a pn into the id's form: "section-6.3-2" gives "6.3-2"; "section-appendix.b.1-3" gives "B.1-3".</summary>
    /// <param name="pn">The pn attribute's value.</param>
    /// <returns>The anchor part of a row id.</returns>
    private static string Anchor(string pn)
    {
        string s = pn.StartsWith("section-", StringComparison.Ordinal) ? pn["section-".Length..] : pn;
        if (!s.StartsWith("appendix.", StringComparison.Ordinal))
        {
            return s;
        }

        // Appendices are lettered in the RFC ("Appendix B.1"); the pn spells them in lowercase.
        s = s["appendix.".Length..];
        return char.ToUpperInvariant(s[0]) + s[1..];
    }

    /// <summary>Whether a keyword is quoted, as in the BCP 14 boilerplate that defines the keywords.</summary>
    /// <param name="keyword">A bcp14 element.</param>
    /// <returns>True when a double quote stands right before and right after it.</returns>
    private static bool IsQuoted(XElement keyword) =>
        keyword.PreviousNode is XText before && before.Value.EndsWith('"')
        && keyword.NextNode is XText after && after.Value.StartsWith('"');

    /// <summary>Whether a sourcecode element is a grammar block worth a row.</summary>
    /// <param name="code">A sourcecode element.</param>
    /// <returns>True for type "abnf" or "abnf9110" and the like, except the collected-ABNF appendix.</returns>
    private static bool IsGrammar(XElement code) =>
        ((string?)code.Attribute("type"))?.StartsWith("abnf", StringComparison.Ordinal) == true
        && code.Attribute("pn") is not null
        && ((string?)code.Attribute("name"))?.EndsWith("parsed-abnf", StringComparison.Ordinal) != true;

    /// <summary>The number and title of the section that holds an element.</summary>
    /// <param name="element">A paragraph or grammar block.</param>
    /// <returns>("6.3", "Message Body Length"), or two empty strings in front matter.</returns>
    private (string Section, string Title) SectionOf(XElement element)
    {
        XElement? section = element.Ancestors("section").FirstOrDefault(s => s.Attribute("pn") is not null);
        if (section is null)
        {
            return ("", "");
        }

        var title = new StringBuilder();
        if (section.Element("name") is { } name)
        {
            Render(name, null, title);
        }

        return (Anchor(section.Attribute("pn")!.Value), Prose.Normalize(title.ToString()));
    }

    /// <summary>Appends an element's text as the RFC Editor renders it.</summary>
    /// <param name="node">The node to render.</param>
    /// <param name="mark">The bcp14 element to wrap in <see cref="Prose.MarkStart"/> and
    /// <see cref="Prose.MarkEnd"/>, or null.</param>
    /// <param name="text">Receives the text.</param>
    /// <remarks>
    /// Index entries (iref) and editorial comments (cref) render as nothing. An empty xref
    /// renders from its attributes: "Section 5.5 of [HTTP]", "[RFC5234], Section B.1", or the
    /// derived "6.3" of a counter. An empty eref renders as its URL.
    /// </remarks>
    private void Render(XNode node, XElement? mark, StringBuilder text)
    {
        if (node is XText t)
        {
            text.Append(t.Value);
            return;
        }

        if (node is not XElement e)
        {
            return; // comments, processing instructions
        }

        switch (e.Name.LocalName)
        {
            case "iref" or "cref":
                return;
            case "br":
                text.Append(' ');
                return;
            case "xref" when !e.Nodes().Any():
                text.Append(XrefText(e));
                return;
            case "eref" when !e.Nodes().Any():
                text.Append((string?)e.Attribute("target"));
                return;
        }

        bool marked = ReferenceEquals(e, mark);
        if (marked)
        {
            text.Append(Prose.MarkStart);
        }

        foreach (XNode child in e.Nodes())
        {
            Render(child, mark, text);
        }

        if (marked)
        {
            text.Append(Prose.MarkEnd);
        }
    }

    /// <summary>The text an empty xref renders as.</summary>
    /// <param name="xref">The xref element.</param>
    /// <returns>Its rendering, from its derivedContent, section and sectionFormat attributes.</returns>
    private string XrefText(XElement xref)
    {
        string target = (string?)xref.Attribute("target") ?? "";
        string content = (string?)xref.Attribute("derivedContent") ?? target;
        bool reference = references.Contains(target);
        if ((string?)xref.Attribute("section") is { } section)
        {
            return ((string?)xref.Attribute("sectionFormat")) switch
            {
                "comma" => $"[{content}], Section {section}",
                "parens" => $"[{content}] (Section {section})",
                "bare" => section,
                _ => $"Section {section} of [{content}]",
            };
        }

        // A reference to the bibliography renders in brackets; one inside the document
        // ("Section 6.3", "Appendix A", a counter) renders as its derived text.
        return reference ? $"[{content}]" : content;
    }
}

/// <summary>Extracts the rows of an older RFC's text file.</summary>
/// <remarks>
/// Text files carry no markup: the keywords are found by their capitals, sections by their
/// headings at column 0, and paragraphs by blank lines. Page furniture (the footer, the form
/// feed, the running header) is removed first, and a paragraph that a page break cut in two
/// is joined again.
/// </remarks>
internal static partial class TextExtractor
{
    /// <summary>The line that replaces a page break while paragraphs are assembled.</summary>
    private const string PageBreak = "\f";

    /// <summary>A page's footer: "Peon &amp; Ruellan    Standards Track    [Page 5]".</summary>
    [GeneratedRegex(@"^\S.*\[Page \d+\]\s*$")]
    private static partial Regex Footer();

    /// <summary>A page's running header: "RFC 7541    HPACK    May 2015".</summary>
    [GeneratedRegex(@"^RFC \d+\s{2,}.*\d{4}\s*$")]
    private static partial Regex RunningHeader();

    /// <summary>A section heading at column 0: "5.1.  Integer Representation", "Appendix A.  Static
    /// Table Definition", "A.1.  ...". Table-of-contents lines are indented, so they never match.</summary>
    [GeneratedRegex(@"^(?:Appendix )?(?<n>\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)\.\s+(?<t>\S.*)$")]
    private static partial Regex Heading();

    /// <summary>A BCP 14 keyword in capitals, not inside a longer word and not quoted. The longer
    /// forms come first, so "MUST NOT" is never read as "MUST".</summary>
    [GeneratedRegex("(?<![A-Za-z\"])(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|NOT RECOMMENDED|RECOMMENDED|MAY|OPTIONAL)(?![A-Za-z\"])")]
    private static partial Regex Keyword();

    /// <summary>The document's rows, in document order.</summary>
    /// <param name="document">The document.</param>
    /// <param name="path">Its pinned text file.</param>
    /// <returns>The rows.</returns>
    public static IEnumerable<Requirement> Extract(Document document, string path)
    {
        var rows = new List<Requirement>();
        string section = "", title = "";
        int paragraph = 0;
        bool started = false;

        foreach ((string Section, string Title, string Text) p in Paragraphs(Lines(path)))
        {
            if (p.Section != section)
            {
                section = p.Section;
                title = p.Title;
                paragraph = 0;
                started |= section == "1"; // front matter (abstract, status, contents) ends here
            }

            paragraph++;
            if (!started)
            {
                continue;
            }

            MatchCollection keywords = Keyword().Matches(p.Text);
            for (int k = 0; k < keywords.Count; k++)
            {
                Match m = keywords[k];
                string sentence = Prose.Sentence(p.Text, m.Index, m.Length, out int keywordAt);
                string anchor = char.IsAsciiLetter(section[0]) ? $"appendix-{section}" : $"section-{section}";
                string id = $"{document.Id}-{section}-p{paragraph}" + (keywords.Count > 1 ? $"#{k + 1}" : "");
                rows.Add(new Requirement(
                    id, document.Id, section, title, m.Value, Prose.Actor(sentence, keywordAt), document.Milestone,
                    $"{document.Html}#{anchor}", sentence));
            }
        }

        return rows;
    }

    /// <summary>The file's lines without page furniture; each page break becomes one <see cref="PageBreak"/> line.</summary>
    /// <param name="path">The text file.</param>
    /// <returns>The lines.</returns>
    private static List<string> Lines(string path)
    {
        string[] raw = File.ReadAllText(path).Replace("\r\n", "\n").Split('\n');
        var lines = new List<string>(raw.Length);
        for (int i = 0; i < raw.Length; i++)
        {
            if (Footer().IsMatch(raw[i]))
            {
                continue;
            }

            if (raw[i].Contains('\f'))
            {
                lines.Add(PageBreak);
                // The running header follows the form feed, on the same line or the next one.
                if (i + 1 < raw.Length && RunningHeader().IsMatch(raw[i + 1]))
                {
                    i++;
                }

                continue;
            }

            lines.Add(raw[i]);
        }

        return lines;
    }

    /// <summary>The paragraphs, each with its section, normalized to one line.</summary>
    /// <param name="lines">The lines without page furniture.</param>
    /// <returns>(section, title, text) per paragraph, in order.</returns>
    /// <remarks>
    /// A gap between two text lines ends the paragraph, unless a page break lies in the gap and
    /// the text before it stops mid-sentence (its last character is not ".", ":", ";", "!",
    /// "?" or ")"): then the page break cut one paragraph in two, and the parts are joined.
    /// </remarks>
    private static IEnumerable<(string Section, string Title, string Text)> Paragraphs(List<string> lines)
    {
        string section = "", title = "";
        var current = new List<string>();
        bool gap = false, pageBreakInGap = false;

        foreach (string line in lines)
        {
            if (line == PageBreak)
            {
                pageBreakInGap = true;
                gap = true;
                continue;
            }

            if (line.Trim().Length == 0)
            {
                gap = true;
                continue;
            }

            if (Heading().Match(line) is { Success: true } h)
            {
                if (current.Count > 0)
                {
                    yield return (section, title, Prose.Normalize(string.Join(' ', current)));
                    current.Clear();
                }

                section = h.Groups["n"].Value;
                title = Prose.Normalize(h.Groups["t"].Value);
                gap = pageBreakInGap = false;
                continue;
            }

            if (gap && current.Count > 0)
            {
                string last = current[^1].TrimEnd();
                bool cutByPage = pageBreakInGap && last.Length > 0 && last[^1] is not ('.' or ':' or ';' or '!' or '?' or ')');
                if (!cutByPage)
                {
                    yield return (section, title, Prose.Normalize(string.Join(' ', current)));
                    current.Clear();
                }
            }

            current.Add(line.Trim());
            gap = pageBreakInGap = false;
        }

        if (current.Count > 0)
        {
            yield return (section, title, Prose.Normalize(string.Join(' ', current)));
        }
    }
}
