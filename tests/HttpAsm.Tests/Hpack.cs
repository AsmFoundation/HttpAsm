using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>A field as the HPACK tests see it: name, value, record flags and known-field id.</summary>
/// <param name="Name">The name.</param>
/// <param name="Value">The value.</param>
/// <param name="Flags">HTTPASM_FIELD_FLAG_* (decoder: NEVER_INDEXED; encoder: its instructions).</param>
/// <param name="Id">The known-field id the decoder reported (0 when unknown, or for encoder input).</param>
internal sealed record HpackField(string Name, string Value, int Flags = 0, int Id = 0)
{
    /// <summary>"name: value", as RFC 7541's examples print a field.</summary>
    /// <returns>The text.</returns>
    public override string ToString() => $"{Name}: {Value}";
}

/// <summary>What one httpasm_hpack_decode call reported.</summary>
/// <param name="Result">0, 1 (fields or space ran out), or -HTTPASM_ERROR_HPACK_*.</param>
/// <param name="Fields">The records written, in order.</param>
/// <param name="ListSize">The header list's size over every field (RFC 9113 6.5.2).</param>
/// <param name="SpaceUsed">Octets of space the records' strings took.</param>
internal sealed record HpackDecoded(long Result, IReadOnlyList<HpackField> Fields, ulong ListSize, ulong SpaceUsed);

/// <summary>
/// One HPACK table (httpasm_hpack_init) in native memory, a decoder's or an encoder's, with the
/// calls the tests make on it. Strings are Latin-1: one char per octet, as HPACK carries them.
/// </summary>
internal sealed unsafe class HpackTable : IDisposable
{
    /// <summary>The table's memory, owned by this object.</summary>
    private byte* memory;

    /// <summary>Allocates and initializes a table.</summary>
    /// <param name="limit">The limit (decoder: the SETTINGS value advertised; encoder: the most it uses).</param>
    /// <param name="flags">HTTPASM_HPACK_*.</param>
    /// <exception cref="InvalidOperationException">httpasm_hpack_init refused the limit.</exception>
    public HpackTable(uint limit, uint flags = 0)
    {
        nuint size = Native.HpackSize(limit);
        memory = (byte*)NativeMemory.AllocZeroed(size == 0 ? 1 : size);
        int result = Native.HpackInit(memory, size, limit, flags);
        if (result != 0)
        {
            NativeMemory.Free(memory);
            memory = null;
            throw new InvalidOperationException($"httpasm_hpack_init({limit}): {result}");
        }
    }

    /// <summary>The dynamic table's size (RFC 7541 4.1).</summary>
    public uint Size => Native.HpackTableSize(memory, null);

    /// <summary>The dynamic table's maximum now.</summary>
    public uint MaxSize
    {
        get
        {
            uint max;
            Native.HpackTableSize(memory, &max);
            return max;
        }
    }

    /// <summary>The dynamic table's entries, newest first (indices 62 on).</summary>
    /// <returns>The entries.</returns>
    public List<HpackField> Entries()
    {
        var entries = new List<HpackField>();
        HttpField field;
        for (uint index = 62; Native.HpackEntry(memory, index, &field) == 0; index++)
        {
            entries.Add(Copy(field));
        }

        return entries;
    }

    /// <summary>The entry at an HPACK index, or null.</summary>
    /// <param name="index">The index.</param>
    /// <returns>The entry, or null when the index is 0 or past both tables.</returns>
    public HpackField? Entry(uint index)
    {
        HttpField field;
        return Native.HpackEntry(memory, index, &field) == 0 ? Copy(field) : null;
    }

    /// <summary>Decodes a header block.</summary>
    /// <param name="block">The block.</param>
    /// <param name="maxFields">The records' room.</param>
    /// <param name="space">The strings' room.</param>
    /// <param name="room">
    /// The strings' memory, when the test inspects it afterwards (prefilled with a canary, say):
    /// at least <paramref name="space"/> octets, of which the decoder may use the first
    /// <paramref name="space"/>. Null: a fresh array of that size.
    /// </param>
    /// <returns>What the call reported.</returns>
    /// <exception cref="ArgumentException"><paramref name="room"/> is shorter than <paramref name="space"/>.</exception>
    public HpackDecoded Decode(byte[] block, int maxFields = 256, int space = 65536, byte[]? room = null)
    {
        var records = new HttpField[Math.Max(maxFields, 1)];
        if (room != null && room.Length < space)
        {
            throw new ArgumentException("The room is shorter than the space it must hold.", nameof(room));
        }

        // A caller's room is used as it is (its canary must survive what the decoder skips); a
        // fresh one needs at least one octet so `fixed` yields a pointer even for space 0.
        room ??= new byte[Math.Max(space, 1)];
        fixed (byte* b = block)
        fixed (HttpField* f = records)
        fixed (byte* s = room)
        {
            var output = new HpackOutput { Fields = f, Space = s, SpaceSize = (nuint)space, MaxFields = (uint)maxFields };
            long result = Native.HpackDecode(memory, b, (nuint)block.Length, &output);
            var fields = new List<HpackField>();
            for (int i = 0; i < output.Count; i++)
            {
                fields.Add(Copy(f[i]));
            }

            return new HpackDecoded(result, fields, output.ListSize, output.SpaceUsed);
        }
    }

    /// <summary>Encodes fields as one header block.</summary>
    /// <param name="fields">The fields (their Flags are the encoder's instructions).</param>
    /// <returns>The block.</returns>
    /// <exception cref="InvalidOperationException">The encoder wrote nothing although the buffer held the bound.</exception>
    public byte[] Encode(IReadOnlyList<HpackField> fields)
    {
        using var native = new NativeFields(fields.Select(f => (f.Name, f.Value)).ToArray());
        for (int i = 0; i < fields.Count; i++)
        {
            native.Pointer[i].Flags = (ushort)fields[i].Flags;
        }

        nuint bound = Native.HpackEncodeBound(native.Pointer, native.Count);
        byte[] output = new byte[(int)bound];
        fixed (byte* o = output)
        {
            long length = Native.HpackEncode(memory, native.Pointer, native.Count, o, bound);
            if (length <= 0 && bound > 12)
            {
                throw new InvalidOperationException($"httpasm_hpack_encode wrote {length} with a buffer of the bound ({bound}).");
            }

            return output[..(int)length];
        }
    }

    /// <summary>httpasm_hpack_encode with a given capacity, for the too-small case.</summary>
    /// <param name="fields">The fields.</param>
    /// <param name="cap">The capacity offered.</param>
    /// <returns>What it returned.</returns>
    public long EncodeInto(IReadOnlyList<HpackField> fields, int cap)
    {
        using var native = new NativeFields(fields.Select(f => (f.Name, f.Value)).ToArray());
        byte[] output = new byte[Math.Max(cap, 1)];
        fixed (byte* o = output)
        {
            return Native.HpackEncode(memory, native.Pointer, native.Count, o, (nuint)cap);
        }
    }

    /// <summary>The peer's SETTINGS_HEADER_TABLE_SIZE, for an encoder.</summary>
    /// <param name="limit">The setting.</param>
    public void EncoderLimit(uint limit) => Native.HpackEncoderLimit(memory, limit);

    /// <summary>Frees the memory.</summary>
    public void Dispose()
    {
        if (memory != null)
        {
            NativeMemory.Free(memory);
            memory = null;
        }
    }

    /// <summary>Copies a record into a managed field.</summary>
    /// <param name="f">The record.</param>
    /// <returns>The copy.</returns>
    private static HpackField Copy(HttpField f) =>
        new(Encoding.Latin1.GetString(f.Name, (int)f.NameLength), Encoding.Latin1.GetString(f.Value, (int)f.ValueLength), f.Flags, f.Id);
}

/// <summary>One entry of an example's dynamic table, as RFC 7541 prints it.</summary>
/// <param name="Size">Its size, "s =".</param>
/// <param name="Text">"name: value", wrapped lines joined with one space.</param>
internal sealed record HpackExampleEntry(int Size, string Text);

/// <summary>One example of RFC 7541 Appendix C, read from the pinned RFC file.</summary>
/// <param name="Section">Its section number ("C.3.1").</param>
/// <param name="Headers">"Header list to encode".</param>
/// <param name="Encoded">"Hex dump of encoded data".</param>
/// <param name="Table">"Dynamic Table (after decoding)", newest first; empty when the RFC says "empty".</param>
/// <param name="TableSize">"Table size", 0 for an empty table.</param>
/// <param name="Decoded">"Decoded header list".</param>
internal sealed record HpackExample(
    string Section,
    IReadOnlyList<HpackField> Headers,
    byte[] Encoded,
    IReadOnlyList<HpackExampleEntry> Table,
    int TableSize,
    IReadOnlyList<HpackField> Decoded);

/// <summary>
/// RFC 7541's Appendix C examples, parsed from specs/rfc/rfc7541.txt (the pinned file the
/// registry comes from), so the tests check the official text itself rather than a copy that
/// could drift from it.
/// </summary>
internal static partial class Rfc7541
{
    /// <summary>The examples, by section, read once.</summary>
    private static readonly Lazy<IReadOnlyDictionary<string, HpackExample>> LazyExamples = new(Load);

    /// <summary>Every example of C.2 to C.6, by section number.</summary>
    /// <exception cref="InvalidDataException">An example's text does not have the expected parts.</exception>
    public static IReadOnlyDictionary<string, HpackExample> Examples => LazyExamples.Value;

    /// <summary>The page footer RFC text files repeat.</summary>
    [GeneratedRegex(@"^Peon & Ruellan\s+Standards Track\s+\[Page \d+\]$")]
    private static partial Regex Footer();

    /// <summary>The page header.</summary>
    [GeneratedRegex(@"^RFC 7541\s+HPACK\s+May 2015$")]
    private static partial Regex Header();

    /// <summary>An example's heading: "C.3.1.  First Request".</summary>
    [GeneratedRegex(@"^(C\.[2-6]\.\d)\.\s{2}")]
    private static partial Regex Heading();

    /// <summary>A dynamic table entry: "[  1] (s =  57) :authority: www.example.com".</summary>
    [GeneratedRegex(@"^\s+\[\s*\d+\] \(s =\s*(\d+)\) (.*)$")]
    private static partial Regex Entry();

    /// <summary>"Table size: 57".</summary>
    [GeneratedRegex(@"^\s+Table size:\s*(\d+)$")]
    private static partial Regex TableSize();

    /// <summary>Splits "name: value", where a pseudo-field's name starts with its own colon.</summary>
    /// <param name="line">The line, trimmed.</param>
    /// <returns>The field.</returns>
    /// <exception cref="InvalidDataException">There is no ": ".</exception>
    public static HpackField Split(string line)
    {
        int at = line.IndexOf(": ", line.StartsWith(':') ? 1 : 0, StringComparison.Ordinal);
        return at > 0 ? new HpackField(line[..at], line[(at + 2)..]) : throw new InvalidDataException($"Not a field: \"{line}\".");
    }

    /// <summary>Reads the file and parses every example.</summary>
    /// <returns>The examples by section.</returns>
    /// <exception cref="InvalidDataException">An example lacks a part.</exception>
    private static IReadOnlyDictionary<string, HpackExample> Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc7541.txt");

        // Page breaks (footer, form feed, header) can fall inside an example: drop them first.
        string[] lines = File.ReadAllLines(path)
            .Where(l => !Footer().IsMatch(l) && !Header().IsMatch(l) && l != "\f")
            .ToArray();
        var examples = new Dictionary<string, HpackExample>(StringComparer.Ordinal);
        for (int i = 0; i < lines.Length; i++)
        {
            Match heading = Heading().Match(lines[i]);
            if (!heading.Success)
            {
                continue;
            }

            int end = i + 1;
            while (end < lines.Length && (lines[end].Length == 0 || lines[end][0] == ' '))
            {
                end++;                      // an example ends at the next unindented line
            }

            examples.Add(heading.Groups[1].Value, Parse(heading.Groups[1].Value, lines[(i + 1)..end]));
            i = end - 1;
        }

        return examples;
    }

    /// <summary>Parses one example's lines.</summary>
    /// <param name="section">Its section number.</param>
    /// <param name="lines">Its lines, after the heading.</param>
    /// <returns>The example.</returns>
    /// <exception cref="InvalidDataException">A part is missing.</exception>
    private static HpackExample Parse(string section, string[] lines)
    {
        int Find(string text, int from = 0)
        {
            for (int k = from; k < lines.Length; k++)
            {
                if (lines[k].Trim().StartsWith(text, StringComparison.Ordinal))
                {
                    return k;
                }
            }

            throw new InvalidDataException($"RFC 7541 {section}: no \"{text}\".");
        }

        int headers = Find("Header list to encode:");
        int hex = Find("Hex dump of encoded data:", headers);
        int process = Find("Decoding process:", hex);
        int decoded = Find("Decoded header list:", process);

        var toEncode = lines[(headers + 1)..hex].Select(l => l.Trim()).Where(l => l.Length > 0).Select(Split).ToList();
        var octets = new List<byte>();
        foreach (string line in lines[(hex + 1)..process])
        {
            int bar = line.IndexOf('|', StringComparison.Ordinal);
            foreach (string group in (bar < 0 ? line : line[..bar]).Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                octets.AddRange(Convert.FromHexString(group));
            }
        }

        var table = new List<HpackExampleEntry>();
        int tableSize = 0;
        int dynamic = Array.FindIndex(lines, process, l => l.Contains("(after decoding)", StringComparison.Ordinal));
        if (!lines[dynamic].TrimEnd().EndsWith("empty.", StringComparison.Ordinal))
        {
            for (int k = dynamic + 1; k < decoded; k++)
            {
                Match entry = Entry().Match(lines[k]);
                Match size = TableSize().Match(lines[k]);
                if (entry.Success)
                {
                    table.Add(new HpackExampleEntry(int.Parse(entry.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture), entry.Groups[2].Value.Trim()));
                }
                else if (size.Success)
                {
                    tableSize = int.Parse(size.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                }
                else if (lines[k].Trim().Length > 0)
                {
                    HpackExampleEntry last = table[^1];   // a wrapped entry's next line
                    table[^1] = last with { Text = last.Text + " " + lines[k].Trim() };
                }
            }
        }

        var list = lines[(decoded + 1)..].Select(l => l.Trim()).Where(l => l.Length > 0).Select(Split).ToList();
        return new HpackExample(section, toEncode, octets.ToArray(), table, tableSize, list);
    }
}
