// =============================================================================
// generate.cs - the core's tables, generated from the pinned official documents.
//
// Nothing that an RFC defines as a table is typed in by hand (docs/DESIGN.md, "Code
// conventions"). This tool reads the pinned files that specs/documents.json lists. It checks
// their SHA-256 first, so the tables always come from the pinned bytes, and writes:
//   src/HttpAsm.Core/include/generated/field_ids.inc   HA_FIELD_* ids of the known fields
//   src/HttpAsm.Core/include/generated/field_table.inc their names and the perfect hash
//   src/HttpAsm.Core/include/generated/hpack.inc       HPACK's static table (RFC 7541 appendix A)
//   src/HttpAsm.Core/include/generated/qpack.inc       QPACK's static table (RFC 9204 appendix A)
//   src/HttpAsm.Core/include/generated/huffman.inc     the Huffman code (RFC 7541 appendix B):
//                                                      encoder table, 4-bit decoder automaton
//   src/HttpAsm/include/httpasm_fields.h               the HTTPASM_FIELD_* ids, for C
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/generate.cs            write the files
//   dotnet run specs/generate.cs -- --check fail when a committed file differs (CI)
// Exit status: 0 success; 1 a check failed (a hash, a parse, a stale file); 2 wrong usage.
//
// The known fields: every name of HPACK's static table and then of QPACK's, in table order,
// followed by the connection-specific fields that RFC 9113 section 8.2.2 and RFC 9110 section
// 7.6.1 name (connection, keep-alive, proxy-connection, te, upgrade) and the trailer field of
// RFC 9110 section 6.6.2. An id never changes once given: new names are appended.
//
// The perfect hash: a name's key packs its first two and last two octets, each folded to lower
// case with | 0x20, and its length:
//   key = b0 | b1 << 8 | b[n-2] << 16 | b[n-1] << 24 | n << 32
// The slot is (key * M) >> 56 in a 256-slot table, with M an odd 64-bit multiplier. The
// multiplier is searched from a fixed seed until no two known names share a slot, so the
// output is the same on every run. A lookup then compares the candidate's name
// case-insensitively; names shorter than 2 octets are never known.
// =============================================================================
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/generate.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
if (!File.Exists(Path.Combine(root, "specs", "documents.json")))
{
    Console.Error.WriteLine("generate: run this from the repository root (specs/documents.json was not found)");
    return 2;
}

try
{
    var pinned = new Pinned(Path.Combine(root, "specs"));
    string hpackText = pinned.Text("RFC7541");
    XDocument qpackXml = pinned.Xml("RFC9204");

    IReadOnlyList<(int Index, string Name, string Value)> hpack = Tables.HpackStatic(hpackText);
    IReadOnlyList<(int Index, string Name, string Value)> qpack = Tables.QpackStatic(qpackXml);
    IReadOnlyList<(int Symbol, uint Code, int Length)> huffman = Tables.Huffman(hpackText);
    IReadOnlyList<string> fields = Fields.Known(hpack, qpack);
    PerfectHash hash = PerfectHash.Search(fields);
    IReadOnlyList<(int Code, string Reason)> statuses = Tables.Statuses(pinned.Xml("RFC9110"), pinned.Text("RFC6585"));

    var outputs = new Dictionary<string, string>
    {
        ["src/HttpAsm.Core/include/generated/field_ids.inc"] = Emit.FieldIds(fields),
        ["src/HttpAsm.Core/include/generated/field_table.inc"] = Emit.FieldTable(fields, hash),
        ["src/HttpAsm.Core/include/generated/hpack.inc"] = Emit.StaticTable("HPACK", "RFC 7541 appendix A", hpack, fields),
        ["src/HttpAsm.Core/include/generated/qpack.inc"] = Emit.StaticTable("QPACK", "RFC 9204 appendix A", qpack, fields),
        ["src/HttpAsm.Core/include/generated/huffman.inc"] = Emit.Huffman(huffman),
        ["src/HttpAsm.Core/include/generated/status.inc"] = Emit.StatusLines(statuses),
        ["src/HttpAsm/include/httpasm_fields.h"] = Emit.FieldIdsHeader(fields),
    };

    int stale = 0;
    foreach ((string relative, string text) in outputs)
    {
        string path = Path.Combine(root, relative);
        string current = File.Exists(path) ? File.ReadAllText(path).Replace("\r\n", "\n") : "";
        if (current == text)
        {
            continue;
        }

        if (check)
        {
            Console.Error.WriteLine($"generate: {relative} is out of date");
            stale++;
            continue;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text, new UTF8Encoding(false));
        Console.WriteLine($"wrote {relative}");
    }

    if (stale > 0)
    {
        throw new GenerateException($"{stale} generated file(s) out of date: run dotnet run specs/generate.cs and commit them");
    }

    Console.WriteLine($"{fields.Count} known fields (hash multiplier 0x{hash.Multiplier:X16}), HPACK {hpack.Count}, QPACK {qpack.Count}, Huffman {huffman.Count} codes, {statuses.Count} status codes");
    return 0;
}
catch (GenerateException e)
{
    Console.Error.WriteLine($"generate: {e.Message}");
    return 1;
}

/// <summary>A check that failed: a hash, a parse that found the wrong shape, or a stale file.</summary>
/// <param name="message">What failed; printed as the tool's last line.</param>
internal sealed class GenerateException(string message) : Exception(message);

/// <summary>The pinned documents, read only after their SHA-256 matches documents.json.</summary>
internal sealed class Pinned
{
    /// <summary>The specs/ folder.</summary>
    private readonly string specs;

    /// <summary>Each document's (file, pinned SHA-256), by id.</summary>
    private readonly Dictionary<string, (string File, string Sha256)> documents = new(StringComparer.Ordinal);

    /// <summary>Reads documents.json.</summary>
    /// <param name="specs">The specs/ folder.</param>
    /// <exception cref="GenerateException">The file lacks the documents array.</exception>
    public Pinned(string specs)
    {
        this.specs = specs;
        JsonNode root = JsonNode.Parse(File.ReadAllText(Path.Combine(specs, "documents.json")))
            ?? throw new GenerateException("documents.json is empty");
        foreach (JsonNode? d in root["documents"]?.AsArray() ?? throw new GenerateException("documents.json has no documents"))
        {
            documents[d!["id"]!.GetValue<string>()] = (d["file"]!.GetValue<string>(), d["sha256"]!.GetValue<string>());
        }
    }

    /// <summary>A text document's content, after its hash check.</summary>
    /// <param name="id">The document's id.</param>
    /// <returns>Its text, with LF line endings.</returns>
    /// <exception cref="GenerateException">The document is not pinned, or its file does not match the pin.</exception>
    public string Text(string id) => Encoding.UTF8.GetString(Verified(id)).Replace("\r\n", "\n");

    /// <summary>An XML document, after its hash check.</summary>
    /// <param name="id">The document's id.</param>
    /// <returns>The parsed document (internal DTD subset parsed, nothing external fetched).</returns>
    /// <exception cref="GenerateException">The document is not pinned, or its file does not match the pin.</exception>
    public XDocument Xml(string id)
    {
        using var stream = new MemoryStream(Verified(id));
        using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null });
        return XDocument.Load(reader);
    }

    /// <summary>A document's bytes, checked against its pinned SHA-256.</summary>
    /// <param name="id">The document's id.</param>
    /// <returns>The file's bytes.</returns>
    /// <exception cref="GenerateException">Not pinned, missing, or not matching.</exception>
    private byte[] Verified(string id)
    {
        if (!documents.TryGetValue(id, out var d))
        {
            throw new GenerateException($"{id} is not in documents.json");
        }

        string path = Path.Combine(specs, d.File);
        byte[] bytes = File.Exists(path) ? File.ReadAllBytes(path) : throw new GenerateException($"{id}: {d.File} is missing; run specs.cs fetch");
        if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != d.Sha256)
        {
            throw new GenerateException($"{id}: {d.File} does not match its pinned SHA-256; run specs.cs fetch");
        }

        return bytes;
    }
}

/// <summary>Parses the tables out of the documents.</summary>
internal static partial class Tables
{
    /// <summary>A row of RFC 7541 appendix A: "| 2     | :method          | GET     |".</summary>
    [GeneratedRegex(@"^\s*\|\s*(\d+)\s*\|\s*(\S+)\s*\|\s*(.*?)\s*\|\s*$", RegexOptions.Multiline)]
    private static partial Regex HpackRow();

    /// <summary>A row of RFC 7541 appendix B: "(  0)  |11111111|11000   1ff8  [13]", after an optional symbol picture.</summary>
    [GeneratedRegex(@"\(\s*(\d+)\)\s+\|([01|]+)\s+([0-9a-f]+)\s+\[\s*(\d+)\]")]
    private static partial Regex HuffmanRow();

    /// <summary>HPACK's static table: 61 rows, indices 1 to 61.</summary>
    /// <param name="text">RFC 7541's text.</param>
    /// <returns>The rows in index order.</returns>
    /// <exception cref="GenerateException">The rows are not exactly 1 to 61.</exception>
    public static IReadOnlyList<(int Index, string Name, string Value)> HpackStatic(string text)
    {
        // Appendix A starts at its heading; the rows before it (section 2.3's figure) are not the table.
        int start = text.IndexOf("Appendix A.  Static Table Definition", StringComparison.Ordinal);
        int end = text.IndexOf("Appendix B.  Huffman Code", start, StringComparison.Ordinal);
        if (start < 0 || end < 0)
        {
            throw new GenerateException("RFC7541: appendix A or B not found");
        }

        var rows = HpackRow().Matches(text[start..end])
            .Select(m => (Index: int.Parse(m.Groups[1].Value), Name: m.Groups[2].Value, Value: m.Groups[3].Value))
            .ToList();
        if (rows.Count != 61 || rows.Select((r, i) => r.Index == i + 1).Any(ok => !ok))
        {
            throw new GenerateException($"RFC7541 appendix A: expected rows 1-61, found {rows.Count}");
        }

        return rows;
    }

    /// <summary>QPACK's static table: 99 rows, indices 0 to 98.</summary>
    /// <param name="xml">RFC 9204's prepped XML.</param>
    /// <returns>The rows in index order.</returns>
    /// <exception cref="GenerateException">The table is missing or its rows are not exactly 0 to 98.</exception>
    public static IReadOnlyList<(int Index, string Name, string Value)> QpackStatic(XDocument xml)
    {
        // The table of appendix A ("Static Table"): its body rows are index, name, value.
        XElement table = xml.Descendants("section")
            .Where(s => (string?)s.Attribute("pn") == "section-appendix.a")
            .Descendants("table").FirstOrDefault()
            ?? throw new GenerateException("RFC9204: appendix A's table not found");

        var rows = table.Element("tbody")!.Elements("tr")
            .Select(tr => tr.Elements("td").Select(td => td.Value.Trim()).ToArray())
            .Select(td => (Index: int.Parse(td[0]), Name: td[1], Value: td[2]))
            .ToList();
        if (rows.Count != 99 || rows.Select((r, i) => r.Index == i).Any(ok => !ok))
        {
            throw new GenerateException($"RFC9204 appendix A: expected rows 0-98, found {rows.Count}");
        }

        return rows;
    }

    /// <summary>A section heading of RFC 6585: "4.  429 Too Many Requests".</summary>
    [GeneratedRegex(@"^\d+\.\s+(\d{3}) (\S.*?)\s*$", RegexOptions.Multiline)]
    private static partial Regex Rfc6585Status();

    /// <summary>
    /// The registered status codes and their descriptions: RFC 9110 section 18.3's table, then
    /// RFC 6585's codes (428, 429, 431, 511). Rows marked "(Unused)" are left out.
    /// </summary>
    /// <param name="rfc9110">RFC 9110's prepped XML.</param>
    /// <param name="rfc6585">RFC 6585's text.</param>
    /// <returns>(code, reason) in code order.</returns>
    /// <exception cref="GenerateException">The table is missing, or a code is out of 100-599 or repeated.</exception>
    public static IReadOnlyList<(int Code, string Reason)> Statuses(XDocument rfc9110, string rfc6585)
    {
        XElement table = rfc9110.Descendants("section")
            .FirstOrDefault(s => (string?)s.Element("name")?.Attribute("slugifiedName") == "name-status-code-registration")
            ?.Descendants("table").FirstOrDefault()
            ?? throw new GenerateException("RFC9110: the status code registration table was not found");

        var codes = table.Element("tbody")!.Elements("tr")
            .Select(tr => tr.Elements("td").Select(td => td.Value.Trim()).ToArray())
            .Where(td => !td[1].StartsWith('('))
            .Select(td => (Code: int.Parse(td[0]), Reason: td[1]))
            .ToList();
        codes.AddRange(Rfc6585Status().Matches(rfc6585).Select(m => (int.Parse(m.Groups[1].Value), m.Groups[2].Value)));

        // RFC 9110 registers 44 named codes and RFC 6585 adds 4: far fewer means a broken parse.
        if (codes.Count < 40 || codes.Any(c => c.Code is < 100 or > 599) || codes.Select(c => c.Code).Distinct().Count() != codes.Count)
        {
            throw new GenerateException($"status codes: {codes.Count} parsed, some out of range or repeated");
        }

        return codes.OrderBy(c => c.Code).ToList();
    }

    /// <summary>The Huffman code: 257 symbols (EOS is 256), each code checked against its hex and length columns.</summary>
    /// <param name="text">RFC 7541's text.</param>
    /// <returns>(symbol, code aligned to the least significant bit, length in bits), by symbol.</returns>
    /// <exception cref="GenerateException">A row disagrees with itself, or symbols are missing.</exception>
    public static IReadOnlyList<(int Symbol, uint Code, int Length)> Huffman(string text)
    {
        int start = text.IndexOf("Appendix B.  Huffman Code", StringComparison.Ordinal);
        var rows = new List<(int Symbol, uint Code, int Length)>();
        foreach (Match m in HuffmanRow().Matches(text[start..]))
        {
            int symbol = int.Parse(m.Groups[1].Value);
            string bits = m.Groups[2].Value.Replace("|", "");
            uint hex = Convert.ToUInt32(m.Groups[3].Value, 16);
            int length = int.Parse(m.Groups[4].Value);

            // The three columns say the same thing three ways; a parse that misread one fails here.
            if (bits.Length != length || Convert.ToUInt32(bits, 2) != hex)
            {
                throw new GenerateException($"RFC7541 appendix B: symbol {symbol}'s columns disagree");
            }

            rows.Add((symbol, hex, length));
        }

        if (rows.Count != 257 || rows.Select((r, i) => r.Symbol == i).Any(ok => !ok))
        {
            throw new GenerateException($"RFC7541 appendix B: expected symbols 0-256, found {rows.Count}");
        }

        return rows;
    }
}

/// <summary>The known fields and their ids.</summary>
internal static class Fields
{
    /// <summary>
    /// Names no static table holds but the semantics need by id: the connection-specific fields
    /// of RFC 9113 section 8.2.2 (RFC 9110 section 7.6.1) and the trailer field of RFC 9110
    /// section 6.6.2.
    /// </summary>
    private static readonly string[] Extras = ["connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"];

    /// <summary>The known fields in id order: id = index + 1 (0 means unknown).</summary>
    /// <param name="hpack">HPACK's static table.</param>
    /// <param name="qpack">QPACK's static table.</param>
    /// <returns>Distinct names, HPACK's first, then QPACK's, then the extras.</returns>
    /// <exception cref="GenerateException">More than 255 names (ids are octets in the hash table).</exception>
    public static IReadOnlyList<string> Known(
        IReadOnlyList<(int Index, string Name, string Value)> hpack, IReadOnlyList<(int Index, string Name, string Value)> qpack)
    {
        var names = new List<string>();
        foreach (string name in hpack.Select(r => r.Name).Concat(qpack.Select(r => r.Name)).Concat(Extras))
        {
            if (!names.Contains(name))
            {
                names.Add(name);
            }
        }

        return names.Count <= 255 ? names : throw new GenerateException($"{names.Count} known fields; ids are one octet");
    }

    /// <summary>The constant suffix of a name: ":method" gives PSEUDO_METHOD, "content-length" CONTENT_LENGTH.</summary>
    /// <param name="name">A known field's name.</param>
    /// <returns>Upper case, "-" as "_", a leading ":" as "PSEUDO_".</returns>
    public static string Constant(string name) =>
        (name.StartsWith(':') ? "PSEUDO_" + name[1..] : name).Replace('-', '_').ToUpperInvariant();
}

/// <summary>A collision-free hash of the known fields into 256 slots.</summary>
/// <param name="Multiplier">The odd 64-bit multiplier.</param>
/// <param name="Slots">256 slots, each a field id or 0.</param>
internal sealed record PerfectHash(ulong Multiplier, byte[] Slots)
{
    /// <summary>A name's key, exactly as the assembler computes it (see the file header).</summary>
    /// <param name="name">A name of at least two octets.</param>
    /// <returns>The key.</returns>
    public static ulong Key(string name)
    {
        int n = name.Length;
        ulong Fold(char c) => (ulong)((byte)c | 0x20);
        return Fold(name[0]) | Fold(name[1]) << 8 | Fold(name[n - 2]) << 16 | Fold(name[n - 1]) << 24 | (ulong)n << 32;
    }

    /// <summary>Searches a multiplier, from a fixed seed, that puts every known field in its own slot.</summary>
    /// <param name="fields">The known fields, in id order.</param>
    /// <returns>The hash.</returns>
    /// <exception cref="GenerateException">Two names share a key (the key would need more octets), or no
    /// multiplier was found in a million tries.</exception>
    public static PerfectHash Search(IReadOnlyList<string> fields)
    {
        ulong[] keys = fields.Select(Key).ToArray();
        if (keys.Distinct().Count() != keys.Length)
        {
            throw new GenerateException("two known fields share a key: the key needs more octets");
        }

        ulong state = 0x9E3779B97F4A7C15; // a fixed seed: the same multiplier on every run
        for (int attempt = 0; attempt < 1_000_000; attempt++)
        {
            // xorshift64*, then forced odd
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            ulong multiplier = (state * 0x2545F4914F6CDD1D) | 1;

            var slots = new byte[256];
            bool clash = false;
            for (int id = 1; id <= keys.Length && !clash; id++)
            {
                int slot = (int)((keys[id - 1] * multiplier) >> 56);
                clash = slots[slot] != 0;
                slots[slot] = (byte)id;
            }

            if (!clash)
            {
                return new PerfectHash(multiplier, slots);
            }
        }

        throw new GenerateException("no perfect-hash multiplier found");
    }
}

/// <summary>Writes the generated files.</summary>
internal static class Emit
{
    /// <summary>The banner every generated NASM file starts with.</summary>
    /// <param name="what">What the file holds.</param>
    /// <param name="source">Where it comes from.</param>
    /// <returns>The banner.</returns>
    private static string Banner(string what, string source) =>
        "; =============================================================================\n"
        + $"; {what}\n"
        + $"; GENERATED by specs/generate.cs from {source}: do not edit; regenerate.\n"
        + "; =============================================================================\n";

    /// <summary>A NASM string operand for any name or value: quoted text, with any quote or
    /// non-printable octet written as a number.</summary>
    /// <param name="s">The text (US-ASCII in every static table).</param>
    /// <returns>The operand, or "" for an empty string (the caller emits no db then).</returns>
    private static string Db(string s)
    {
        var parts = new List<string>();
        var run = new StringBuilder();
        foreach (char c in s)
        {
            if (c is >= ' ' and <= '~' and not '"')
            {
                run.Append(c);
                continue;
            }

            if (run.Length > 0)
            {
                parts.Add($"\"{run}\"");
                run.Clear();
            }

            parts.Add(((int)c).ToString());
        }

        if (run.Length > 0)
        {
            parts.Add($"\"{run}\"");
        }

        return string.Join(", ", parts);
    }

    /// <summary>generated/field_ids.inc: the ids, for any source.</summary>
    /// <param name="fields">The known fields in id order.</param>
    /// <returns>The file.</returns>
    public static string FieldIds(IReadOnlyList<string> fields)
    {
        var s = new StringBuilder(Banner("field_ids.inc - the ids of the known fields (0 = unknown).",
            "RFC 7541 appendix A, RFC 9204 appendix A, RFC 9113 8.2.2 and RFC 9110 6.6.2"));
        s.Append("%ifndef HTTPASM_GENERATED_FIELD_IDS_INC\n%define HTTPASM_GENERATED_FIELD_IDS_INC\n\n");
        s.Append($"HA_FIELD_COUNT      equ {fields.Count}\n");
        s.Append($"HA_FIELD_MAX_LENGTH equ {fields.Max(f => f.Length)}\n\n");
        for (int i = 0; i < fields.Count; i++)
        {
            s.Append($"HA_FIELD_{Fields.Constant(fields[i])} equ {i + 1}    ; {fields[i]}\n");
        }

        return s.Append("\n%endif\n").ToString();
    }

    /// <summary>generated/field_table.inc: names and the hash, as data (include once).</summary>
    /// <param name="fields">The known fields in id order.</param>
    /// <param name="hash">The perfect hash.</param>
    /// <returns>The file.</returns>
    public static string FieldTable(IReadOnlyList<string> fields, PerfectHash hash)
    {
        var s = new StringBuilder(Banner("field_table.inc - the known fields' names and their perfect hash (data).",
            "RFC 7541 appendix A, RFC 9204 appendix A, RFC 9113 8.2.2 and RFC 9110 6.6.2"));
        s.Append($"HA_FIELD_HASH_MULTIPLIER equ 0x{hash.Multiplier:X16}\n\n");
        s.Append("; ha_field_hash[(key * HA_FIELD_HASH_MULTIPLIER) >> 56] = the id whose key lands there, or 0.\n");
        s.Append("align 64\nha_field_hash:\n");
        for (int row = 0; row < 256; row += 16)
        {
            s.Append("    db ").Append(string.Join(", ", hash.Slots.Skip(row).Take(16))).Append('\n');
        }

        s.Append("\n; ha_field_names: id-indexed (id 0 unused) pairs of dd offset (into ha_field_text), dd length.\n");
        s.Append("align 8\nha_field_names:\n    dd 0, 0\n");
        int offset = 0;
        foreach (string f in fields)
        {
            s.Append($"    dd {offset}, {f.Length}    ; {f}\n");
            offset += f.Length;
        }

        s.Append("\n; ha_field_text: every known name, lower case, back to back.\nha_field_text:\n");
        foreach (string f in fields)
        {
            s.Append($"    db {Db(f)}\n");
        }

        return s.ToString();
    }

    /// <summary>generated/hpack.inc or qpack.inc: a static table (data, include once).</summary>
    /// <param name="table">"HPACK" or "QPACK".</param>
    /// <param name="source">The appendix it comes from.</param>
    /// <param name="rows">The rows, in index order.</param>
    /// <param name="fields">The known fields, for each row's field id.</param>
    /// <returns>The file.</returns>
    /// <remarks>Each entry is 16 octets: dd name offset, dd value offset (into the table's text),
    /// dw name length, dw value length, db field id, 3 octets of padding. The first entry is the
    /// table's first index (1 for HPACK, 0 for QPACK).</remarks>
    public static string StaticTable(string table, string source, IReadOnlyList<(int Index, string Name, string Value)> rows,
        IReadOnlyList<string> fields)
    {
        string lower = table.ToLowerInvariant();
        var s = new StringBuilder(Banner($"{lower}.inc - {table}'s static table (data).", source));
        s.Append($"HA_{table}_STATIC_FIRST equ {rows[0].Index}\n");
        s.Append($"HA_{table}_STATIC_COUNT equ {rows.Count}\n\n");
        s.Append($"; ha_{lower}_static: 16-octet entries from index HA_{table}_STATIC_FIRST: dd name offset, dd value\n");
        s.Append($"; offset (into ha_{lower}_text), dw name length, dw value length, db field id, 3 octets padding.\n");
        s.Append($"align 16\nha_{lower}_static:\n");
        int offset = 0;
        foreach ((int index, string name, string value) in rows)
        {
            int id = fields.ToList().IndexOf(name) + 1;
            s.Append($"    dd {offset}, {offset + name.Length}\n    dw {name.Length}, {value.Length}\n    db {id}, 0, 0, 0    ; {index}: {name}: {value}\n");
            offset += name.Length + value.Length;
        }

        s.Append($"\nha_{lower}_text:\n");
        foreach ((_, string name, string value) in rows)
        {
            string both = name + value;
            s.Append($"    db {Db(both)}\n");
        }

        return s.ToString();
    }

    /// <summary>generated/huffman.inc: the encoder's table and the 4-bit decoder automaton (data, include once).</summary>
    /// <param name="code">The 257 codes.</param>
    /// <returns>The file.</returns>
    /// <exception cref="GenerateException">The code is not prefix-free or a nibble completes two symbols.</exception>
    /// <remarks>
    /// The automaton: one state per internal node of the code's binary tree (root = 0; 256
    /// internal nodes for 257 leaves). ha_huff_decode[state * 16 + nibble] is a dword:
    ///   bits 0-7   the next state
    ///   bits 8-15  the symbol completed, when bit 16 is set
    ///   bit 16     HA_HUFF_SYMBOL: this nibble completed a symbol
    ///   bit 17     HA_HUFF_ACCEPT: ending the string here is valid (RFC 7541 5.2): the bits since
    ///              the last symbol are all 1, fewer than 8, so they are a prefix of EOS's code
    ///   bit 18     HA_HUFF_FAIL: the nibble completed EOS, which a string must never contain
    /// No code is shorter than 5 bits, so a nibble completes one symbol at most.
    /// </remarks>
    public static string Huffman(IReadOnlyList<(int Symbol, uint Code, int Length)> code)
    {
        // The tree: children[node] = (zero child, one child); a child >= 0 is an internal node,
        // a child < 0 is the leaf of symbol -(child + 1).
        var children = new List<int[]> { new[] { int.MinValue, int.MinValue } };
        foreach ((int symbol, uint bits, int length) in code)
        {
            int node = 0;
            for (int i = length - 1; i >= 0; i--)
            {
                int bit = (int)((bits >> i) & 1);
                int child = children[node][bit];
                if (i == 0)
                {
                    if (child != int.MinValue)
                    {
                        throw new GenerateException($"Huffman: symbol {symbol}'s code is not prefix-free");
                    }

                    children[node][bit] = -(symbol + 1);
                }
                else if (child == int.MinValue)
                {
                    children.Add(new[] { int.MinValue, int.MinValue });
                    children[node][bit] = children.Count - 1;
                    node = children.Count - 1;
                }
                else
                {
                    node = child >= 0 ? child : throw new GenerateException($"Huffman: symbol {symbol} passes through a leaf");
                }
            }
        }

        if (children.Count != 256)
        {
            throw new GenerateException($"Huffman: {children.Count} internal nodes, expected 256");
        }

        // The states where a string may end: the root, and the all-ones path below it to depth 7.
        var accept = new HashSet<int> { 0 };
        for (int node = 0, depth = 1; depth <= 7; depth++)
        {
            node = children[node][1];
            accept.Add(node);
        }

        var s = new StringBuilder(Banner("huffman.inc - HPACK's Huffman code: the encoder's table and the decoder's automaton (data).",
            "RFC 7541 appendix B"));
        s.Append("HA_HUFF_SYMBOL equ 0x10000\nHA_HUFF_ACCEPT equ 0x20000\nHA_HUFF_FAIL   equ 0x40000\n\n");
        s.Append("; ha_huff_code[symbol]: the code, aligned to the least significant bit (symbols 0-256, EOS last).\n");
        s.Append("align 64\nha_huff_code:\n");
        for (int row = 0; row < 257; row += 8)
        {
            s.Append("    dd ").Append(string.Join(", ", code.Skip(row).Take(8).Select(c => $"0x{c.Code:X8}"))).Append('\n');
        }

        s.Append("\n; ha_huff_length[symbol]: the code's length in bits.\nha_huff_length:\n");
        for (int row = 0; row < 257; row += 16)
        {
            s.Append("    db ").Append(string.Join(", ", code.Skip(row).Take(16).Select(c => c.Length))).Append('\n');
        }

        s.Append("\n; ha_huff_decode[state * 16 + nibble]: see generate.cs Emit.Huffman.\nalign 64\nha_huff_decode:\n");
        for (int state = 0; state < 256; state++)
        {
            var entries = new uint[16];
            for (int nibble = 0; nibble < 16; nibble++)
            {
                int node = state;
                uint flags = 0, symbol = 0;
                for (int i = 3; i >= 0; i--)
                {
                    int child = children[node][(nibble >> i) & 1];
                    if (child >= 0)
                    {
                        node = child;
                        continue;
                    }

                    int completed = -(child + 1);
                    if (completed == 256)
                    {
                        flags |= 0x40000; // EOS inside a string: a decoding error
                        node = 0;
                        break;
                    }

                    if ((flags & 0x10000) != 0)
                    {
                        throw new GenerateException("Huffman: a nibble completes two symbols");
                    }

                    flags |= 0x10000;
                    symbol = (uint)completed;
                    node = 0;
                }

                if ((flags & 0x40000) == 0 && accept.Contains(node))
                {
                    flags |= 0x20000;
                }

                entries[nibble] = (uint)node | symbol << 8 | flags;
            }

            s.Append("    dd ").Append(string.Join(", ", entries.Select(e => $"0x{e:X5}"))).Append($"    ; {state}\n");
        }

        return s.ToString();
    }

    /// <summary>generated/status.inc: HTTP/1.1 status lines of the registered codes (data, include once).</summary>
    /// <param name="statuses">The registered codes and reasons.</param>
    /// <returns>The file.</returns>
    /// <remarks>ha_status_line[code - 100] is a dword: the line's offset in ha_status_text shifted
    /// left 8, or'ed with its length; 0 for a code with no registered reason. Each line is
    /// "HTTP/1.1 " code SP reason CRLF.</remarks>
    public static string StatusLines(IReadOnlyList<(int Code, string Reason)> statuses)
    {
        var s = new StringBuilder(Banner("status.inc - the status lines of the registered status codes (data).",
            "RFC 9110 section 18.3 and RFC 6585"));
        var byCode = statuses.ToDictionary(x => x.Code, x => x.Reason);
        s.Append("; ha_status_line[code - 100] = offset << 8 | length of its line in ha_status_text, or 0.\n");
        s.Append("align 4\nha_status_line:\n");
        int offset = 0;
        var text = new StringBuilder();
        for (int code = 100; code <= 599; code++)
        {
            if (!byCode.TryGetValue(code, out string? reason))
            {
                s.Append("    dd 0\n");
                continue;
            }

            string line = $"HTTP/1.1 {code} {reason}";
            int length = line.Length + 2;
            s.Append($"    dd 0x{offset << 8 | length:X}    ; {code} {reason}\n");
            text.Append($"    db {Db(line)}, 13, 10\n");
            offset += length;
        }

        s.Append("\nha_status_text:\n").Append(text);
        return s.ToString();
    }

    /// <summary>include/httpasm_fields.h: the ids for C consumers.</summary>
    /// <param name="fields">The known fields in id order.</param>
    /// <returns>The file.</returns>
    public static string FieldIdsHeader(IReadOnlyList<string> fields)
    {
        var s = new StringBuilder();
        s.Append("/*\n * httpasm_fields.h - the ids of the known fields: httpasm_field.id, and httpasm_field_id().\n");
        s.Append(" * GENERATED by specs/generate.cs from RFC 7541 appendix A, RFC 9204 appendix A, RFC 9113\n");
        s.Append(" * section 8.2.2 and RFC 9110 section 6.6.2: do not edit; regenerate. 0 means unknown, and an\n");
        s.Append(" * id never changes once given.\n */\n");
        s.Append("#ifndef HTTPASM_FIELDS_H\n#define HTTPASM_FIELDS_H\n\n");
        s.Append($"#define HTTPASM_FIELD_COUNT {fields.Count}\n\n");
        for (int i = 0; i < fields.Count; i++)
        {
            s.Append($"#define HTTPASM_FIELD_{Fields.Constant(fields[i])} {i + 1} /* {fields[i]} */\n");
        }

        return s.Append("\n#endif /* HTTPASM_FIELDS_H */\n").ToString();
    }
}
