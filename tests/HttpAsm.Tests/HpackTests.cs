using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// HPACK (RFC 7541) through the C ABI: Appendix C's examples in both directions, read from the
/// pinned RFC file; every decoding error the RFC names; the table kept in step when the output
/// runs out; size updates; never-indexed fields; the Huffman code against the RFC's own table;
/// and random round trips where the encoder's and decoder's tables must stay identical.
/// </summary>
public sealed partial class HpackTests
{
    /// <summary>The single examples of C.2, each with a fresh table.</summary>
    public static TheoryData<string> Single => new() { "C.2.1", "C.2.2", "C.2.3", "C.2.4" };

    /// <summary>The connection examples: three header lists on one table each.</summary>
    public static TheoryData<string, uint, uint> Connections => new()
    {
        { "C.3", 4096, 0 },
        { "C.4", 4096, Abi.HpackHuffman },
        { "C.5", 256, 0 },
        { "C.6", 256, Abi.HpackHuffman },
    };

    /// <summary>The output structure and the table's memory have the library's sizes.</summary>
    [Fact]
    public void StructuresMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(48, Unsafe.SizeOf<HpackOutput>());
        Assert.Equal((uint)Unsafe.SizeOf<HpackOutput>(), Native.StructSize(8));
        Assert.Equal(9344u, (uint)Native.HpackSize(4096));
        Assert.Equal(0u, (uint)Native.HpackSize(0x1000001));
        Assert.True(Native.HpackSize(0x1000000) > 0);
    }

    /// <summary>A limit past the maximum, or memory smaller than httpasm_hpack_size, is refused.</summary>
    [Fact]
    public unsafe void RefusesLimitsAndMemoryThatDoNotFit()
    {
        Platform.RequireLinuxX64();
        byte* memory = stackalloc byte[16];
        Assert.Equal(-(int)ParseError.HpackLimit, Native.HpackInit(memory, 16, 4096, 0));
        Assert.Equal(-(int)ParseError.HpackLimit, Native.HpackInit(memory, 16, 0x1000001, 0));
        using var table = new HpackTable(0);
        Assert.Equal(0u, table.MaxSize);
    }

    /// <summary>
    /// C.2's examples decode to the RFC's header list and leave the RFC's dynamic table; the
    /// never-indexed literal (C.2.3) keeps its flag on the record.
    /// </summary>
    /// <param name="section">The example.</param>
    [Theory]
    [MemberData(nameof(Single))]
    [Requirement("RFC7541-2.1-p1#2", "RFC7541-3.2-p1")]
    public void DecodesTheSingleExamples(string section)
    {
        Platform.RequireLinuxX64();
        HpackExample example = Rfc7541.Examples[section];
        using var decoder = new HpackTable(4096);

        HpackDecoded decoded = decoder.Decode(example.Encoded);

        Assert.Equal(0, decoded.Result);
        AssertFields(example.Decoded, decoded.Fields);
        Assert.Equal(section == "C.2.3" ? Abi.FieldNeverIndexed : 0, Assert.Single(decoded.Fields).Flags);
        AssertTable(example, decoder);
    }

    /// <summary>
    /// C.3 to C.6: three header lists on one connection decode in turn, each leaving the RFC's
    /// table (C.5 and C.6 with a 256-octet table, so entries are evicted).
    /// </summary>
    /// <param name="group">"C.3" to "C.6".</param>
    /// <param name="limit">The table's limit.</param>
    /// <param name="flags">Unused by the decoder (the encoder's Huffman setting).</param>
    [Theory]
    [MemberData(nameof(Connections))]
    [Requirement("RFC7541-2.1-p1#2", "RFC7541-3.2-p1")]
    public void DecodesTheConnectionExamples(string group, uint limit, uint flags)
    {
        Platform.RequireLinuxX64();
        _ = flags;
        using var decoder = new HpackTable(limit);
        for (int n = 1; n <= 3; n++)
        {
            HpackExample example = Rfc7541.Examples[$"{group}.{n}"];
            HpackDecoded decoded = decoder.Decode(example.Encoded);
            Assert.Equal(0, decoded.Result);
            AssertFields(example.Decoded, decoded.Fields);
            AssertTable(example, decoder);
        }
    }

    /// <summary>
    /// The encoder writes C.2's examples octet for octet with its default policy: a new name is
    /// indexed (C.2.1), :path is not (C.2.2), a field flagged never-indexed keeps that form
    /// (C.2.3), an exact static match is an index (C.2.4).
    /// </summary>
    /// <param name="section">The example.</param>
    [Theory]
    [MemberData(nameof(Single))]
    [Requirement("RFC7541-2.1-p1#1", "RFC7541-6.2.3-p6#1")]
    public void EncodesTheSingleExamples(string section)
    {
        Platform.RequireLinuxX64();
        HpackExample example = Rfc7541.Examples[section];
        using var encoder = new HpackTable(4096);
        var fields = example.Headers.Select(f => section == "C.2.3" ? f with { Flags = Abi.FieldNeverIndexed } : f).ToList();

        byte[] block = encoder.Encode(fields);

        Assert.Equal(Convert.ToHexString(example.Encoded), Convert.ToHexString(block));
        AssertTable(example, encoder);
    }

    /// <summary>
    /// The encoder writes C.3 to C.6 octet for octet, Huffman-coded or not, indexing as the RFC
    /// does (HTTPASM_HPACK_INDEX_ALL: the examples index location and set-cookie, which the
    /// default policy keeps out), with the RFC's tables after each list.
    /// </summary>
    /// <param name="group">"C.3" to "C.6".</param>
    /// <param name="limit">The table's limit.</param>
    /// <param name="flags">HTTPASM_HPACK_HUFFMAN for C.4 and C.6.</param>
    [Theory]
    [MemberData(nameof(Connections))]
    [Requirement("RFC7541-2.1-p1#1")]
    public void EncodesTheConnectionExamples(string group, uint limit, uint flags)
    {
        Platform.RequireLinuxX64();
        using var encoder = new HpackTable(limit, flags | Abi.HpackIndexAll);
        for (int n = 1; n <= 3; n++)
        {
            HpackExample example = Rfc7541.Examples[$"{group}.{n}"];
            byte[] block = encoder.Encode(example.Headers);
            Assert.Equal(Convert.ToHexString(example.Encoded), Convert.ToHexString(block));
            AssertTable(example, encoder);
        }
    }

    /// <summary>
    /// C.1's integers, as the 5-bit prefix of a table size update: 10 is "2a" (C.1.1) and 1337
    /// is "3f 9a 0a" (C.1.2), both written by the encoder and read by the decoder; 3000 needs two
    /// continuation octets. (4096, the starting size, would be no change and signal nothing.)
    /// </summary>
    /// <param name="value">The integer.</param>
    /// <param name="hex">Its representation as a size update.</param>
    [Theory]
    [InlineData(10u, "2A")]
    [InlineData(1337u, "3F9A0A")]
    [InlineData(3000u, "3F9917")]
    [Requirement("RFC7541-4.2-p3")]
    public void CodesIntegersAsTheRfcShows(uint value, string hex)
    {
        Platform.RequireLinuxX64();
        using var encoder = new HpackTable(4096);
        using var decoder = new HpackTable(4096);
        encoder.EncoderLimit(value);

        byte[] block = encoder.Encode([]);
        HpackDecoded decoded = decoder.Decode(block);

        Assert.Equal(hex, Convert.ToHexString(block));
        Assert.Equal(0, decoded.Result);
        Assert.Equal(value, decoder.MaxSize);
    }

    /// <summary>Malformed blocks are refused with the rule they break (in HTTP/2, COMPRESSION_ERROR).</summary>
    /// <param name="hex">The block.</param>
    /// <param name="error">The error expected.</param>
    /// <remarks>
    /// The cases, in order: index 0; index 62 with an empty dynamic table; a literal whose name
    /// index is past both tables; an integer with six continuation octets; one worth 2^32 + 126;
    /// an integer cut off; a literal without its value; a value shorter than its length; EOS
    /// inside a Huffman string; 'a' then 11 bits of padding; 'a' then padding of zeros; a size
    /// update after a field; a size update to 4097, above the 4096 limit.
    /// </remarks>
    [Theory]
    [InlineData("80", ParseError.HpackIndex)]
    [InlineData("BE", ParseError.HpackIndex)]
    [InlineData("7E0161", ParseError.HpackIndex)]
    [InlineData("FFFFFFFFFFFF00", ParseError.HpackInteger)]
    [InlineData("FFFFFFFFFF0F", ParseError.HpackInteger)]
    [InlineData("FF", ParseError.HpackTruncated)]
    [InlineData("8241", ParseError.HpackTruncated)]
    [InlineData("41056162", ParseError.HpackTruncated)]
    [InlineData("4184FFFFFFFF", ParseError.HpackHuffman)]
    [InlineData("41821FFF", ParseError.HpackHuffman)]
    [InlineData("418118", ParseError.HpackHuffman)]
    [InlineData("8220", ParseError.HpackSizeUpdate)]
    [InlineData("3FE21F", ParseError.HpackSizeUpdate)]
    [Requirement("RFC7541-6.1-p5", "RFC7541-2.3.3-p4", "RFC7541-5.1-p15", "RFC7541-5.2-p10#1", "RFC7541-5.2-p10#2",
        "RFC7541-5.2-p10#3", "RFC7541-4.2-p3", "RFC7541-6.3-p5#2", "RFC7541-3.2-p1")]
    public void RefusesMalformedBlocks(string hex, ParseError error)
    {
        Platform.RequireLinuxX64();
        using var decoder = new HpackTable(4096);

        Assert.Equal(-(long)error, decoder.Decode(Convert.FromHexString(hex)).Result);
    }

    /// <summary>A block may repeat a field; the decoder keeps both, in order.</summary>
    [Fact]
    [Requirement("RFC7541-2.3.2-p3", "RFC7541-2.1-p1#2")]
    public void KeepsDuplicateFields()
    {
        Platform.RequireLinuxX64();
        using var decoder = new HpackTable(4096);

        HpackDecoded decoded = decoder.Decode(Convert.FromHexString("8240016101614001610162"));

        Assert.Equal(0, decoded.Result);
        Assert.Equal([":method: GET", "a: a", "a: b"], decoded.Fields.Select(f => f.ToString()));
    }

    /// <summary>
    /// When the records or the space run out, the block is still decoded to its end and every
    /// literal with incremental indexing still enters the table (taken again from the block, a
    /// Huffman string and a dynamic name included), so the next block decodes against the same
    /// table as the peer's encoder. The result says 1, and list_size counts every field.
    /// </summary>
    /// <param name="maxFields">The records' room.</param>
    /// <param name="space">The strings' room.</param>
    [Theory]
    [InlineData(0, 65536)]
    [InlineData(64, 0)]
    [InlineData(1, 4)]
    public void KeepsTheTableInStepWhenTheOutputRunsOut(int maxFields, int space)
    {
        Platform.RequireLinuxX64();
        using var encoder = new HpackTable(4096, Abi.HpackHuffman | Abi.HpackIndexAll);
        using var decoder = new HpackTable(4096);
        HpackField[] first = [new("custom-key", "custom-header"), new("x-huffman", "www.example.com")];
        HpackField[] second = [new("custom-key", "another"), new("x-huffman", "www.example.com"), new(":path", "/a/b")];

        HpackDecoded starved = decoder.Decode(encoder.Encode(first), maxFields, space);
        Assert.Equal(1, starved.Result);
        Assert.Equal((ulong)first.Sum(f => f.Name.Length + f.Value.Length + 32), starved.ListSize);
        AssertSameTables(encoder, decoder);

        HpackDecoded fed = decoder.Decode(encoder.Encode(second));
        Assert.Equal(0, fed.Result);
        AssertFields(second, fed.Fields);
        AssertSameTables(encoder, decoder);

        // A name from the dynamic table, starved again: the entry is looked up anew after the
        // insertion made room (a compaction moves entries, never their indices).
        byte[] third = encoder.Encode([new HpackField("custom-key", "third"), new HpackField("x-huffman", "again")]);
        Assert.Equal(0x40, third[0] & 0xC0);        // a literal with incremental indexing...
        Assert.True((third[0] & 0x3F) > 61);        // ...whose name is a dynamic entry
        Assert.Equal(1, decoder.Decode(third, maxFields, space).Result);
        AssertSameTables(encoder, decoder);
    }

    /// <summary>
    /// Once the output is full, the decoder writes nothing more: every later field is only
    /// measured, whatever its representation. This is the defense against the HPACK bomb's CPU
    /// cost (RFC 7541 7.3, RFC 9113 10.5). A block of 1-octet references to a 600-octet dynamic
    /// entry used to copy the entry for each reference even past the limits, so the decoder did
    /// 600 times the work of the octets it read. Each case fills the output first, through the
    /// field count or through the space. A canary fills the space past what the records use,
    /// and every kind of field then follows: indexed dynamic, literals with dynamic, static and
    /// new names, raw and Huffman-coded, and an insertion. The canary must survive, while the
    /// insertion still reaches the table (RFC 9113 10.5.1: the block is processed whole).
    /// </summary>
    /// <param name="maxFields">The records' room.</param>
    /// <param name="space">The strings' room.</param>
    /// <param name="used">The space the two records the output takes use (the second field
    /// overflows the 700-octet space, which holds the first only).</param>
    [Theory]
    [InlineData(2, 4096, 1210)]
    [InlineData(256, 700, 605)]
    [Requirement("RFC9113-10.5-6#1", "RFC9113-10.5.1-3")]
    public void WritesNothingOnceTheOutputIsFull(int maxFields, int space, int used)
    {
        Platform.RequireLinuxX64();
        string big = new('a', 600);
        var block = new List<byte>();
        block.AddRange([0x40, .. RawLiteral("x-big"), .. RawLiteral(big)]);     // index 62 from here on
        block.Add(0xBE);                                                        // indexed: 62
        for (int i = 0; i < 50; i++)
        {
            block.Add(0xBE);                                                    // the bomb's references
        }

        block.AddRange([.. Integer(62, 4, 0x00), .. RawLiteral(new string('v', 300))]);    // dynamic name, not indexed
        block.AddRange([.. Integer(4, 4, 0x00), .. RawLiteral("/" + new string('p', 99))]); // static name (:path)
        block.AddRange([0x00, .. RawLiteral("x-new"), .. RawLiteral(new string('w', 100))]); // new name
        block.AddRange([0x00, .. HuffmanLiteral("custom-key"u8.ToArray()), .. HuffmanLiteral("custom-value"u8.ToArray())]);
        block.AddRange([0x40, .. RawLiteral("x-ins"), .. RawLiteral(new string('z', 200))]);  // an insertion

        byte[] room = new byte[space + 64];
        Array.Fill(room, (byte)0xA5);
        using var decoder = new HpackTable(4096);
        HpackDecoded decoded = decoder.Decode([.. block], maxFields, space, room);

        Assert.Equal(1, decoded.Result);
        Assert.Equal((ulong)used, decoded.SpaceUsed);
        int written = Array.FindIndex(room, used, b => b != 0xA5);
        Assert.True(written < 0, $"the decoder wrote at offset {written} of the space after the output was full");
        ulong expected = (5 + 600 + 32) * 52UL + (5 + 300 + 32) + (5 + 100 + 32) + (5 + 100 + 32) + (10 + 12 + 32) + (5 + 200 + 32);
        Assert.Equal(expected, decoded.ListSize);                               // every field counted
        Assert.Equal("x-ins: " + new string('z', 200), decoder.Entry(62)?.ToString());   // inserted all the same
        Assert.Equal("x-big: " + big, decoder.Entry(63)?.ToString());
    }

    /// <summary>
    /// The encoder follows the peer's table size: a change is applied at once and signalled at
    /// the start of the next block; after several changes, the smallest maximum comes first, then
    /// the final one; an unchanged limit, or one above what the memory holds, signals nothing.
    /// </summary>
    [Fact]
    [Requirement("RFC7541-4.2-p2", "RFC7541-4.2-p3", "RFC7541-4.2-p4", "RFC7541-6.3-p5#1")]
    public void SignalsTableSizeChanges()
    {
        Platform.RequireLinuxX64();
        using var encoder = new HpackTable(4096, Abi.HpackIndexAll);
        using var decoder = new HpackTable(4096);
        HpackField[] fields = [new("custom-key", "custom-value")];
        Assert.Equal(0, decoder.Decode(encoder.Encode(fields)).Result);

        encoder.EncoderLimit(65536);                // more than the memory: 4096 stays, nothing to say
        Assert.Equal("BE", Convert.ToHexString(encoder.Encode(fields)));

        encoder.EncoderLimit(0);                    // evicts everything at once
        encoder.EncoderLimit(4096);
        Assert.Equal(0u, encoder.Size);
        byte[] block = encoder.Encode(fields);
        Assert.StartsWith("203FE11F", Convert.ToHexString(block), StringComparison.Ordinal);
        Assert.Equal(0, decoder.Decode(block).Result);
        AssertSameTables(encoder, decoder);

        encoder.EncoderLimit(100);
        encoder.EncoderLimit(300);
        block = encoder.Encode([]);
        Assert.Equal("3F453F8D02", Convert.ToHexString(block));   // 100, then 300
        Assert.Equal(0, decoder.Decode(block).Result);
        Assert.Equal(300u, decoder.MaxSize);
    }

    /// <summary>
    /// A field that arrived never-indexed is encoded never-indexed again when its flag is kept,
    /// and so are credentials (authorization, proxy-authorization, a cookie under 20 octets)
    /// even without the flag; none of them enters the encoder's table. A longer cookie and other
    /// fields are indexed as usual.
    /// </summary>
    [Fact]
    [Requirement("RFC7541-6.2.3-p6#1", "RFC7541-6.2.3-p6#2", "RFC7541-6.2.3-p1", "RFC7541-7.1.3-p3#1", "RFC7541-7.1.3-p3#2")]
    public void KeepsSensitiveFieldsOutOfTheTables()
    {
        Platform.RequireLinuxX64();
        using var upstream = new HpackTable(4096);
        HpackField received = Assert.Single(upstream.Decode(Convert.FromHexString("100870617373776F726406736563726574")).Fields);
        Assert.Equal(Abi.FieldNeverIndexed, received.Flags);

        using var encoder = new HpackTable(4096);
        using var decoder = new HpackTable(4096);
        HpackField[] fields =
        [
            received,                               // forwarded with its flag
            new("authorization", "Bearer abc"),
            new("proxy-authorization", "Basic xyz"),
            new("cookie", "short=1"),
            new("cookie", "long-session-cookie=0123456789"),
            new("x-plain", "value"),
        ];
        byte[] block = encoder.Encode(fields);
        HpackDecoded decoded = decoder.Decode(block);

        Assert.Equal([2, 2, 2, 2, 0, 0], decoded.Fields.Select(f => f.Flags));
        Assert.Equal(["x-plain: value", "cookie: long-session-cookie=0123456789"], encoder.Entries().Select(e => e.ToString()));
        AssertSameTables(encoder, decoder);
        Assert.Equal(0x10, block[0] & 0xF0);        // the first field's literal is 0001xxxx
    }

    /// <summary>
    /// A known name without a static entry ("connection") enters the table as its caller spelled
    /// it, and the peer's entry keeps that spelling, so a later field must reuse that entry's name
    /// only when spelled the same: tests/fuzz/hpack found "connectiOn" and then "connection" coming
    /// back from the peer as "connectiOn" twice (CI, 2026-11-27). Spelled the same, the name is
    /// reused, and both tables stay entry for entry the same.
    /// </summary>
    [Fact]
    public void ReusesAnEntrysNameOnlyAsThePeerSpellsIt()
    {
        Platform.RequireLinuxX64();
        using var encoder = new HpackTable(4096);
        using var decoder = new HpackTable(4096);
        HpackField first = Assert.Single(decoder.Decode(encoder.Encode([new HpackField("connectiOn", "a")])).Fields);
        Assert.Equal("connectiOn: a", first.ToString());
        HpackDecoded second = decoder.Decode(encoder.Encode([new HpackField("connection", "b"), new HpackField("connectiOn", "c")]));
        Assert.Equal(["connection: b", "connectiOn: c"], second.Fields.Select(f => f.ToString()));
        AssertSameTables(encoder, decoder);
    }

    /// <summary>Encode writes nothing and leaves the table alone when the buffer is below the bound.</summary>
    [Fact]
    public void EncodeRefusesABufferBelowTheBound()
    {
        Platform.RequireLinuxX64();
        using var encoder = new HpackTable(4096);
        HpackField[] fields = [new("x-a", "b")];

        Assert.Equal(0, encoder.EncodeInto(fields, 10));
        Assert.Empty(encoder.Entries());
    }

    /// <summary>
    /// Every octet value, Huffman-coded with the code table of RFC 7541 Appendix B (parsed from the
    /// pinned file, independently of the generator), decodes back; and the encoder's Huffman output
    /// for text where Huffman is shorter is exactly what that table gives.
    /// </summary>
    [Fact]
    [Requirement("RFC7541-5.2-p10#2")]
    public void FollowsTheRfcHuffmanCode()
    {
        Platform.RequireLinuxX64();
        using var decoder = new HpackTable(4096);
        for (int octet = 0; octet < 256; octet++)
        {
            byte[] value = [(byte)octet, (byte)'x', (byte)octet];
            byte[] block = [0x00, 0x01, (byte)'v', .. HuffmanLiteral(value)];   // literal, new name "v"
            HpackDecoded decoded = decoder.Decode(block);
            Assert.Equal(0, decoded.Result);
            Assert.Equal(Encoding.Latin1.GetString(value), Assert.Single(decoded.Fields).Value);
        }

        using var encoder = new HpackTable(4096, Abi.HpackHuffman);
        const string text = "custom-value: www.example.com/some/path?with=query&and=more";
        byte[] encoded = encoder.Encode([new HpackField("x-test", text, Abi.FieldNoIndex)]);
        byte[] expected = [0x00, .. HuffmanLiteral(Encoding.Latin1.GetBytes("x-test")), .. HuffmanLiteral(Encoding.Latin1.GetBytes(text))];
        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(encoded));
    }

    /// <summary>
    /// Random header lists, block after block on one connection, with random flags, table size
    /// changes, Huffman on or off and both indexing policies: every list decodes to itself, and
    /// after every block the encoder's and the decoder's tables hold the same entries.
    /// </summary>
    /// <param name="seed">The random seed.</param>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [Requirement("RFC7541-2.1-p1#1", "RFC7541-2.1-p1#2", "RFC7541-4.2-p2")]
    public unsafe void RoundTripsRandomLists(int seed)
    {
        Platform.RequireLinuxX64();
        var random = new Random(seed);
        uint flags = (uint)(seed & 1) * Abi.HpackHuffman | (uint)(seed & 2) / 2 * Abi.HpackIndexAll;
        using var encoder = new HpackTable(4096, flags);
        using var decoder = new HpackTable(4096);
        string[] names =
        [
            ":method", ":path", ":authority", ":status", "content-type", "accept", "user-agent", "cookie",
            "authorization", "x-request-id", "x-custom", "date", "server", "set-cookie", "content-length",
        ];

        for (int round = 0; round < 300; round++)
        {
            if (random.Next(20) == 0)
            {
                encoder.EncoderLimit((uint)random.Next(5) switch { 0 => 0, 1 => 64, 2 => 256, 3 => 1000, _ => 4096 });
            }

            var fields = new List<HpackField>();
            for (int i = random.Next(0, 12); i > 0; i--)
            {
                string name = random.Next(4) == 0 ? "x-" + RandomText(random, random.Next(1, 20), lower: true) : names[random.Next(names.Length)];
                string value = random.Next(6) == 0 ? "" : RandomText(random, random.Next(1, random.Next(8) == 0 ? 3000 : 60), lower: false);
                int fieldFlags = random.Next(10) switch { 0 => Abi.FieldNeverIndexed, 1 => Abi.FieldNoIndex, _ => 0 };
                fields.Add(new HpackField(name, value, fieldFlags));
            }

            HpackDecoded decoded = decoder.Decode(encoder.Encode(fields));

            Assert.Equal(0, decoded.Result);
            AssertFields(fields, decoded.Fields);
            for (int i = 0; i < fields.Count; i++)
            {
                bool never = (fields[i].Flags & Abi.FieldNeverIndexed) != 0 || fields[i].Name is "authorization"
                    || (fields[i].Name == "cookie" && fields[i].Value.Length < 20);
                Assert.Equal(never ? Abi.FieldNeverIndexed : 0, decoded.Fields[i].Flags);
                Assert.Equal(KnownId(fields[i].Name), decoded.Fields[i].Id);
            }

            AssertSameTables(encoder, decoder);
        }
    }

    /// <summary>
    /// A name that matches a known one only when every octet is folded with | 0x20 is not that
    /// field: the decoder gives it id 0, and the encoder sends its own octets, never the static
    /// table's name. tests/fuzz/hpack found the decoder giving "\x1apatH" the id of :path
    /// (2026-11-26); its encoder would have sent "content\rlength", a field nobody reads, as
    /// content-length, which frames a message. The cases: 0x1A | 0x20 is ":", CR | 0x20 is
    /// "-"; and letters still fold, as RFC 9110 5.1 says: "Content-LENGTH" is content-length.
    /// </summary>
    /// <param name="name">The name, as Latin-1 text.</param>
    /// <param name="known">The known field it is, or null for none.</param>
    [Theory]
    [InlineData("\u001apath", null)]
    [InlineData("\u001aauthority", null)]
    [InlineData("content\rlength", null)]
    [InlineData("x-frame\roptions", null)]
    [InlineData("transfer\rencoding", null)]
    [InlineData("Content-LENGTH", "content-length")]
    [InlineData(":PATH", ":path")]
    [Requirement("RFC9110-5.1-6#1")]
    public void MatchesKnownNamesByTheirLettersOnly(string name, string? known)
    {
        Platform.RequireLinuxX64();
        int id = known is null ? 0 : KnownId(known);
        byte[] octets = Encoding.Latin1.GetBytes(name);
        byte[] block = [0x00, (byte)octets.Length, .. octets, 0x01, (byte)'v'];   // a literal, new name, not indexed
        using var decoder = new HpackTable(4096);
        HpackDecoded decoded = decoder.Decode(block);
        Assert.Equal(0, decoded.Result);
        Assert.Equal(name, decoded.Fields[0].Name);
        Assert.Equal(id, decoded.Fields[0].Id);

        // Encoded and decoded again: an unknown name keeps its octets; a known one may come
        // back with lower-case letters (sent by the static table's index), never as another.
        using var encoder = new HpackTable(4096);
        using var peer = new HpackTable(4096);
        HpackDecoded back = peer.Decode(encoder.Encode([new HpackField(name, "v")]));
        Assert.Equal(0, back.Result);
        Assert.Equal(known ?? name, back.Fields[0].Name);
        Assert.Equal(id, back.Fields[0].Id);
    }

    /// <summary>A code table row of RFC 7541 Appendix B: "(  0)  |11111111|11000   1ff8  [13]".</summary>
    [GeneratedRegex(@"\(\s*(\d+)\)\s+\|[01|]+\s+([0-9a-f]+)\s+\[\s*(\d+)\]")]
    private static partial Regex HuffmanRow();

    /// <summary>Appendix B's codes (symbol 256 is EOS), read from the pinned RFC file once.</summary>
    private static readonly Lazy<(uint Code, int Length)[]> Codes = new(() =>
    {
        string text = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc7541.txt"));
        var codes = new (uint, int)[257];
        int found = 0;
        foreach (Match m in HuffmanRow().Matches(text[text.IndexOf("Appendix B.  Huffman Code", StringComparison.Ordinal)..]))
        {
            codes[int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)] =
                (Convert.ToUInt32(m.Groups[2].Value, 16), int.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture));
            found++;
        }

        return found == 257 ? codes : throw new InvalidDataException($"RFC 7541 Appendix B: {found} codes, expected 257.");
    });

    /// <summary>An integer with an N-bit prefix (RFC 7541 5.1), the first octet's high bits given.</summary>
    /// <param name="value">The integer.</param>
    /// <param name="prefix">The prefix's bits (1-8).</param>
    /// <param name="high">The first octet's bits above the prefix (the representation's pattern).</param>
    /// <returns>The octets.</returns>
    private static byte[] Integer(int value, int prefix, byte high)
    {
        int max = (1 << prefix) - 1;
        if (value < max)
        {
            return [(byte)(high | value)];
        }

        var octets = new List<byte> { (byte)(high | max) };
        for (value -= max; value >= 128; value >>= 7)
        {
            octets.Add((byte)(0x80 | (value & 0x7F)));
        }

        octets.Add((byte)value);
        return [.. octets];
    }

    /// <summary>A raw (not Huffman-coded) string literal: H clear, the length with a 7-bit prefix.</summary>
    /// <param name="text">The string (Latin-1).</param>
    /// <returns>The literal's octets.</returns>
    private static byte[] RawLiteral(string text) => [.. Integer(text.Length, 7, 0x00), .. Encoding.Latin1.GetBytes(text)];

    /// <summary>A Huffman-coded string literal (H set, 7-bit length), by Appendix B's table.</summary>
    /// <param name="octets">The string.</param>
    /// <returns>The literal's octets.</returns>
    private static byte[] HuffmanLiteral(byte[] octets)
    {
        var bits = new List<bool>();
        foreach (byte b in octets)
        {
            (uint code, int length) = Codes.Value[b];
            for (int i = length - 1; i >= 0; i--)
            {
                bits.Add(((code >> i) & 1) != 0);
            }
        }

        while (bits.Count % 8 != 0)
        {
            bits.Add(true);                         // padding: the most significant bits of EOS
        }

        byte[] data = new byte[bits.Count / 8];
        for (int i = 0; i < bits.Count; i++)
        {
            data[i / 8] |= (byte)((bits[i] ? 1 : 0) << (7 - (i % 8)));
        }

        Assert.True(data.Length < 127);             // these tests keep to a one-octet length
        return [(byte)(0x80 | data.Length), .. data];
    }

    /// <summary>Random field text: lower-case token octets, or any visible ASCII and some obs-text.</summary>
    /// <param name="random">The generator.</param>
    /// <param name="length">How many octets.</param>
    /// <param name="lower">Token octets for a name.</param>
    /// <returns>The text.</returns>
    private static string RandomText(Random random, int length, bool lower)
    {
        const string token = "abcdefghijklmnopqrstuvwxyz0123456789-_.";
        var s = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            s.Append(lower ? token[random.Next(token.Length)] : (char)(random.Next(10) == 0 ? random.Next(0x80, 0x100) : random.Next(0x21, 0x7F)));
        }

        return s.ToString();
    }

    /// <summary>
    /// The known-field id a decoder reports for a name: the pseudo-fields' own ids (1-5, from
    /// the generated table), else httpasm_field_id, which takes token names only.
    /// </summary>
    /// <param name="name">The name.</param>
    /// <returns>Its id, 0 when unknown.</returns>
    private static unsafe int KnownId(string name)
    {
        int pseudo = Array.IndexOf([":authority", ":method", ":path", ":scheme", ":status"], name);
        if (pseudo >= 0)
        {
            return pseudo + 1;
        }

        byte[] octets = Encoding.Latin1.GetBytes(name);
        fixed (byte* p = octets)
        {
            return (int)Native.FieldId(p, (nuint)octets.Length);
        }
    }

    /// <summary>Two header lists are equal: names and values, in order.</summary>
    /// <param name="expected">The list expected.</param>
    /// <param name="actual">The list decoded.</param>
    private static void AssertFields(IReadOnlyList<HpackField> expected, IReadOnlyList<HpackField> actual) =>
        Assert.Equal(expected.Select(f => f.ToString()), actual.Select(f => f.ToString()));

    /// <summary>A table holds what an example's "Dynamic Table" lists, with its sizes and total.</summary>
    /// <param name="example">The example.</param>
    /// <param name="table">The decoder's or encoder's table.</param>
    private static void AssertTable(HpackExample example, HpackTable table)
    {
        List<HpackField> entries = table.Entries();
        Assert.Equal(example.Table.Select(e => e.Size), entries.Select(e => e.Name.Length + e.Value.Length + 32));
        Assert.Equal(example.Table.Select(e => e.Text), entries.Select(e => e.ToString()));
        Assert.Equal((uint)example.TableSize, table.Size);
    }

    /// <summary>The encoder's and decoder's tables hold the same entries, sizes and maximum.</summary>
    /// <param name="encoder">The encoder's table.</param>
    /// <param name="decoder">The decoder's table.</param>
    private static void AssertSameTables(HpackTable encoder, HpackTable decoder)
    {
        Assert.Equal(encoder.Entries().Select(e => e.ToString()), decoder.Entries().Select(e => e.ToString()));
        Assert.Equal(encoder.Size, decoder.Size);
        Assert.Equal(encoder.MaxSize, decoder.MaxSize);
    }
}
