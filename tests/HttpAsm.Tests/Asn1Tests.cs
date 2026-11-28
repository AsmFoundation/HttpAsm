using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// The ASN.1 reader (asn1/asn1.asm) through the C ABI: every rule of ITU-T X.690 it applies,
/// each with the encodings that keep it and those that break it, under DER and under BER. The
/// rows named are specs/x690.tsv's (the ITU's PDF may not be redistributed, so its normative
/// statements are transcribed there). Every encoding is read from the end of a page followed by
/// a guard page (<see cref="GuardedBuffer"/>), so an octet read past the input kills the run
/// instead of passing; and .NET's System.Formats.Asn1, an independent reader of the same rules,
/// is the oracle of a differential test over random and mutated encodings.
/// </summary>
/// <param name="output">Receives the differential test's counts.</param>
public sealed unsafe class Asn1Tests(ITestOutputHelper output)
{
    /// <summary>What one read returned: its status and, on 0, the element's fields (the contents
    /// as an offset into the input, so the test can compare positions).</summary>
    /// <param name="Status">0, or -1.</param>
    /// <param name="Tag">The tag (class, form, number).</param>
    /// <param name="ContentOffset">Where the contents start in the input.</param>
    /// <param name="ContentLength">Their octets.</param>
    /// <param name="Length">The whole encoding's octets.</param>
    /// <param name="Flags"><see cref="Asn1.Indefinite"/> or 0.</param>
    private readonly record struct Read(int Status, uint Tag, int ContentOffset, int ContentLength, int Length, uint Flags);

    /// <summary>Reads the first element of an encoding given in hex (spaces ignored).</summary>
    /// <param name="hex">The encoding.</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>The read's status and fields.</returns>
    private static Read ReadHex(string hex, int rules) => ReadOctets(Convert.FromHexString(hex.Replace(" ", "")), rules);

    /// <summary>Reads the first element of an encoding placed at the end of a page that a guard
    /// page follows (a larger encoding: in native memory without the guard).</summary>
    /// <param name="input">The encoding.</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>The read's status and fields.</returns>
    private static Read ReadOctets(byte[] input, int rules)
    {
        if (input.Length > GuardedBuffer.PageSize)
        {
            byte* block = (byte*)NativeMemory.Alloc((nuint)input.Length);
            try
            {
                input.CopyTo(new Span<byte>(block, input.Length));
                return Run(block);
            }
            finally
            {
                NativeMemory.Free(block);
            }
        }

        using var guard = new GuardedBuffer();
        return Run(guard.AtPageEnd(input));

        Read Run(byte* at)
        {
            Asn1Element e;
            int status = Native.Asn1Read(&e, at, (nuint)input.Length, rules);
            return status != 0
                ? new Read(status, 0, 0, 0, 0, 0)
                : new Read(0, e.Tag, (int)(e.Content - at), (int)e.ContentLength, (int)e.Length, e.Flags);
        }
    }

    /// <summary>Whether the first element of a hex encoding reads under the rules.</summary>
    /// <param name="hex">The encoding.</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <returns>True when the read returned 0.</returns>
    private static bool Reads(string hex, int rules) => ReadHex(hex, rules).Status == 0;

    /// <summary>The encoding of a string type's value: tag, short or long length, the octets.</summary>
    /// <param name="tag">The identifier octet.</param>
    /// <param name="value">The contents.</param>
    /// <returns>Hex.</returns>
    private static string Tlv(byte tag, byte[] value) => Convert.ToHexString(Encode(tag, value));

    /// <summary>A primitive or constructed encoding with a definite length in DER's form.</summary>
    /// <param name="identifier">The identifier octet.</param>
    /// <param name="content">The contents.</param>
    /// <returns>The encoding.</returns>
    private static byte[] Encode(byte identifier, byte[] content)
    {
        var o = new List<byte> { identifier };
        if (content.Length < 128)
        {
            o.Add((byte)content.Length);
        }
        else
        {
            byte[] n = BitConverter.GetBytes(content.Length).Reverse().SkipWhile(b => b == 0).ToArray();
            o.Add((byte)(0x80 | n.Length));
            o.AddRange(n);
        }

        o.AddRange(content);
        return [.. o];
    }

    /// <summary>
    /// The .NET copy of httpasm_asn1 has the library's size, 32 octets, under struct id 23 (the
    /// end of the registry is checked by the newest structure's tests: PemTests).
    /// </summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(32, sizeof(Asn1Element));
        Assert.Equal((uint)sizeof(Asn1Element), Native.StructSize(23));
    }

    /// <summary>Rules other than DER's and BER's are refused, and so is the internal flag the
    /// reader uses for its own segment walk (0x100), which a caller must never be able to set.</summary>
    /// <param name="rules">The value passed.</param>
    [Theory]
    [InlineData(2)]
    [InlineData(-1)]
    [InlineData(0x100)]
    [InlineData(0x101)]
    public void RefusesUnknownRules(int rules)
    {
        Platform.RequireLinuxX64();
        byte[] input = [0x30, 0x00];
        fixed (byte* p = input)
        {
            Asn1Element e;
            Assert.Equal(-1, Native.Asn1Read(&e, p, 2, rules));
            Asn1Element seq = default;
            seq.Tag = Asn1.Sequence;
            Assert.Equal(-1, Native.Asn1Check(&seq, Asn1.Sequence, rules));
            Assert.Equal(-1, Native.Asn1CheckSetOf(&seq, rules));
            uint unused = 7;
            Assert.Equal(-1L, Native.Asn1Octets(&seq, p, 2, rules));
            Assert.Equal(-1L, Native.Asn1Bits(&seq, p, 2, &unused, rules));
            Assert.Equal(7u, unused);
        }
    }

    /// <summary>
    /// The one-octet identifier (8.1.2.2): the class in bits 8-7, the form in bit 6, numbers 0 to
    /// 30 in bits 5-1, every combination of the three classes other than universal (whose types
    /// have rules of their own) and both forms; the tag reports them as the identifier's bits
    /// shifted up by 24 and the number.
    /// </summary>
    [Fact]
    [Requirement("X690-8.1.2.1", "X690-8.1.2.2", "X690-8.1.2.5", "X690-8.1.4")]
    public void ReadsEveryLowTagNumber()
    {
        Platform.RequireLinuxX64();
        foreach (int cls in new[] { 0x40, 0x80, 0xC0 })
        {
            foreach (int form in new[] { 0x00, 0x20 })
            {
                for (int number = 0; number <= 30; number++)
                {
                    foreach (int rules in new[] { Asn1.Der, Asn1.Ber })
                    {
                        Read r = ReadOctets([(byte)(cls | form | number), 0x02, 0xAA, 0xBB, 0xCC], rules);
                        Assert.Equal(0, r.Status);
                        Assert.Equal(((uint)(cls | form) << 24) | (uint)number, r.Tag);
                        Assert.Equal((2, 2, 4, 0u), (r.ContentOffset, r.ContentLength, r.Length, r.Flags));
                    }
                }
            }
        }
    }

    /// <summary>
    /// The high-tag-number form (8.1.2.4): a leading octet with bits 5-1 all ones, then the
    /// number seven bits an octet, bit 8 set on all but the last; numbers from 31 up to 2^28 - 1
    /// (four subsequent octets, the reader's limit), each in the fewest octets.
    /// </summary>
    /// <param name="number">The tag number.</param>
    [Theory]
    [InlineData(31)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(16383)]
    [InlineData(16384)]
    [InlineData((1 << 21) - 1)]
    [InlineData(1 << 21)]
    [InlineData((1 << 28) - 1)]
    [Requirement("X690-8.1.2.4", "X690-8.1.2.4.1", "X690-8.1.2.4.2a", "X690-8.1.2.4.2b")]
    public void ReadsHighTagNumbers(int number)
    {
        Platform.RequireLinuxX64();
        var septets = new List<byte>();
        for (int n = number; n > 0; n >>= 7)
        {
            septets.Insert(0, (byte)(n & 0x7F));
        }

        for (int i = 0; i < septets.Count - 1; i++)
        {
            septets[i] |= 0x80;
        }

        byte[] input = [0xBF, .. septets, 0x01, 0x05];
        foreach (int rules in new[] { Asn1.Der, Asn1.Ber })
        {
            Read r = ReadOctets(input, rules);
            Assert.Equal(0, r.Status);
            Assert.Equal(Asn1.Context | Asn1.Constructed | (uint)number, r.Tag);
            Assert.Equal((input.Length - 1, 1, input.Length), (r.ContentOffset, r.ContentLength, r.Length));
        }
    }

    /// <summary>
    /// High tags that break the form: a first subsequent octet of 0x80 (leading zero bits, 8.1.2.4.2
    /// c), the high form for a number of 30 or less (8.1.2.2 gives those the one octet), five
    /// subsequent octets (past 2^28 - 1), and identifiers cut short; refused under both rules.
    /// </summary>
    /// <param name="hex">The encoding.</param>
    [Theory]
    [InlineData("9F80 1F 00")]
    [InlineData("9F8000 00")]
    [InlineData("9F1E 00")]
    [InlineData("9F00 00")]
    [InlineData("9F01 00")]
    [InlineData("BF8180808000 00")]
    [InlineData("9F81")]
    [InlineData("9F")]
    [InlineData("9F7F")]
    [Requirement("X690-8.1.2.4.2c", "X690-8.1.2.2")]
    public void RefusesMalformedHighTags(string hex)
    {
        Platform.RequireLinuxX64();
        Assert.False(Reads(hex, Asn1.Der));
        Assert.False(Reads(hex, Asn1.Ber));
    }

    /// <summary>
    /// Definite lengths (8.1.3.3): the short form up to 127 (8.1.3.4), the long form from 128
    /// (8.1.3.5), its subsequent octets the length's big-endian octets; the element's contents and
    /// whole length follow, under both rules, for lengths around each octet boundary.
    /// </summary>
    /// <param name="length">The contents' octets.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(4000)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(70000)]
    [Requirement("X690-8.1.3.3", "X690-8.1.3.4", "X690-8.1.3.5", "X690-8.1.3.5d", "X690-10.1")]
    public void ReadsDefiniteLengths(int length)
    {
        Platform.RequireLinuxX64();
        byte[] content = new byte[length];
        Random.Shared.NextBytes(content);
        byte[] input = Encode(0x04, content);
        foreach (int rules in new[] { Asn1.Der, Asn1.Ber })
        {
            Read r = ReadOctets([.. input, 0x05, 0x00], rules);
            Assert.Equal(0, r.Status);
            Assert.Equal(Asn1.OctetString, r.Tag);
            Assert.Equal((input.Length - length, length, input.Length, 0u), (r.ContentOffset, r.ContentLength, r.Length, r.Flags));
        }
    }

    /// <summary>
    /// The long form with more octets than needed is a sender's option in BER (8.1.3.5's NOTE 2),
    /// as is the long form for a length below 128; DER takes the fewest octets (10.1). Up to the
    /// 126 subsequent octets the form allows, leading zeros and all, a BER length reads.
    /// </summary>
    /// <param name="hex">An OCTET STRING of 5 octets with its length in a longer form.</param>
    [Theory]
    [InlineData("04 81 05 0102030405")]
    [InlineData("04 82 0005 0102030405")]
    [InlineData("04 84 00000005 0102030405")]
    [InlineData("04 88 0000000000000005 0102030405")]
    [InlineData("04 89 000000000000000005 0102030405")]
    [Requirement("X690-10.1", "X690-8.1.3.3", "X690-7.3")]
    public void BerTakesLongerLengthsDerDoesNot(string hex)
    {
        Platform.RequireLinuxX64();
        Assert.False(Reads(hex, Asn1.Der));
        Read r = ReadHex(hex, Asn1.Ber);
        Assert.Equal(0, r.Status);
        Assert.Equal(5, r.ContentLength);

        // and the widest: 126 subsequent octets, all but the last zero
        string wide = "04 FE" + new string('0', 125 * 2) + "05 0102030405";
        Assert.Equal(5, ReadHex(wide, Asn1.Ber).ContentLength);
        Assert.False(Reads(wide, Asn1.Der));
    }

    /// <summary>
    /// Lengths that cannot be: the initial octet 0xFF (8.1.3.5 c, under both rules), contents
    /// longer than the input, length octets that run past it, and lengths at or past 2^64 (which
    /// no input holds), each refused without reading past the input.
    /// </summary>
    /// <param name="hex">The encoding.</param>
    [Theory]
    [InlineData("04 FF 01")]
    [InlineData("04 05 01020304")]
    [InlineData("04 81")]
    [InlineData("04 82 01")]
    [InlineData("04 84 FFFFFFFF 00")]
    [InlineData("04 88 FFFFFFFFFFFFFFFF 00")]
    [InlineData("04 89 010000000000000000 00")]
    [InlineData("04")]
    [InlineData("")]
    [Requirement("X690-8.1.3.5c", "X690-8.1.1.1")]
    public void RefusesImpossibleLengths(string hex)
    {
        Platform.RequireLinuxX64();
        Assert.False(Reads(hex, Asn1.Der));
        Assert.False(Reads(hex, Asn1.Ber));
    }

    /// <summary>
    /// BER's indefinite length (8.1.3.6): one octet 0x80 (8.1.3.6.1), the contents ended by two
    /// zero octets (8.1.3.6.2, 8.1.5) at the same level, nested ones each ended by their own; the
    /// element's contents stop before its end-of-contents octets and its length takes them in.
    /// DER refuses the form (10.1); a primitive encoding never takes it (8.1.3.2 a).
    /// </summary>
    [Fact]
    [Requirement("X690-8.1.3.6", "X690-8.1.3.6.1", "X690-8.1.3.6.2", "X690-8.1.5", "X690-8.1.5b", "X690-8.1.3.2a", "X690-10.1", "X690-7.3")]
    public void ReadsIndefiniteLengthsUnderBerOnly()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(new Read(0, Asn1.Sequence, 2, 3, 7, Asn1.Indefinite), ReadHex("30 80 020105 0000 FF", Asn1.Ber));
        Assert.Equal(new Read(0, Asn1.Sequence, 2, 9, 13, Asn1.Indefinite), ReadHex("30 80 3080 020105 0000 0500 0000", Asn1.Ber));
        Assert.Equal(new Read(0, Asn1.Sequence, 2, 5, 9, Asn1.Indefinite), ReadHex("30 80 3003 020105 0000", Asn1.Ber));
        Assert.Equal(new Read(0, Asn1.Context | Asn1.Constructed | 3, 2, 0, 4, Asn1.Indefinite), ReadHex("A3 80 0000", Asn1.Ber));
        Assert.False(Reads("30 80 020105 0000", Asn1.Der));
        Assert.False(Reads("04 80 01 0000", Asn1.Ber));             // primitive
        Assert.False(Reads("30 80 020105", Asn1.Ber));              // no end-of-contents
        Assert.False(Reads("30 80 020105 00", Asn1.Ber));           // half of it
        Assert.False(Reads("30 80 3080 020105 0000", Asn1.Ber));    // the inner ended, the outer not
        Assert.False(Reads("30 80 0001 00 0000", Asn1.Ber));        // a universal 0 that is no end
        Assert.False(Reads("30 80 02020005 0000", Asn1.Ber));       // a nested element that breaks its rules
    }

    /// <summary>
    /// The end-of-contents octets are no element (8.1.1.1, 8.1.5): read where an element should
    /// start they are refused, as is any universal tag 0 encoding.
    /// </summary>
    /// <param name="hex">The encoding.</param>
    [Theory]
    [InlineData("0000")]
    [InlineData("0001 00")]
    [InlineData("2000")]
    [InlineData("0081 00")]
    [Requirement("X690-8.1.1.1b", "X690-8.1.5")]
    public void RefusesEndOfContentsAsAnElement(string hex)
    {
        Platform.RequireLinuxX64();
        Assert.False(Reads(hex, Asn1.Der));
        Assert.False(Reads(hex, Asn1.Ber));
    }

    /// <summary>
    /// The reader follows indefinite lengths 32 levels deep and refuses the 33rd: each level costs
    /// stack, so the bound is what keeps a hostile encoding of "30 80" repeated from exhausting it.
    /// </summary>
    [Fact]
    public void FollowsIndefiniteNestingThirtyTwoLevelsDeep()
    {
        Platform.RequireLinuxX64();
        static string Nested(int levels) =>
            string.Concat(Enumerable.Repeat("3080", levels)) + "0500" + string.Concat(Enumerable.Repeat("0000", levels));
        Assert.True(Reads(Nested(32), Asn1.Ber));
        Assert.False(Reads(Nested(33), Asn1.Ber));
        Assert.False(Reads(Nested(1000), Asn1.Ber));
    }

    /// <summary>
    /// Nested indefinite segments cost time linear in the input: a constructed BIT STRING, OCTET
    /// STRING and UTF8String each 32 levels of "x 80" deep reads (the 33rd level is refused), as
    /// does a 31-level one holding 8,000 segments, whose 8,000 octets httpasm_asn1_octets
    /// gathers; and the 198 octets tests/fuzz/asn1.c timed out on are refused, all of it well
    /// within a second. The reader's first version found an indefinite string's end by reading
    /// every segment whole and then walked the segments again to check them, each re-read
    /// reading the deeper levels whole once more: the work doubled with each level (26 levels
    /// took 1.1 s, 32 would take 72 s; the fuzzer's input 2.7 s), a denial of service in a
    /// few hundred octets of a key file or any BER a caller reads. A segment walk now ends a
    /// string as it checks it. Also the ends' edge: a string whose end-of-contents octets are
    /// missing, or half there, is refused, at the top and in a segment.
    /// </summary>
    [Fact]
    [Requirement("X690-8.1.3.6.2", "X690-8.6.4", "X690-8.7.3", "X690-8.23.3")]
    public void ReadsDeepSegmentsInLinearTime()
    {
        Platform.RequireLinuxX64();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        // (the string's tag, its segments' tag, a primitive segment)
        var kinds = new (byte Outer, byte Segment, string Leaf)[] { (0x23, 0x23, "03020041"), (0x24, 0x24, "040141"), (0x2C, 0x24, "040141") };
        foreach ((byte outer, byte segment, string leaf) in kinds)
        {
            string Chain(int levels) =>
                $"{outer:X2}80" + string.Concat(Enumerable.Repeat($"{segment:X2}80", levels - 1)) + leaf + string.Concat(Enumerable.Repeat("0000", levels));
            Read deep = ReadHex(Chain(32), Asn1.Ber);
            Assert.Equal(0, deep.Status);
            Assert.Equal((2, Chain(32).Length / 2 - 4, Chain(32).Length / 2, Asn1.Indefinite), (deep.ContentOffset, deep.ContentLength, deep.Length, deep.Flags));
            Assert.False(Reads(Chain(33), Asn1.Ber));
        }

        // 31 levels, then 8,000 segments: read, and gathered
        string wide = string.Concat(Enumerable.Repeat("2480", 31)) + string.Concat(Enumerable.Repeat("040141", 8000)) + string.Concat(Enumerable.Repeat("0000", 31));
        byte[] input = Convert.FromHexString(wide);
        fixed (byte* p = input)
        {
            Asn1Element e;
            Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
            Assert.Equal((nuint)input.Length, e.Length);
            byte[] value = new byte[8001];
            fixed (byte* v = value)
            {
                Assert.Equal(8000L, Native.Asn1Octets(&e, v, (nuint)value.Length, Asn1.Ber));
            }

            Assert.True(value[..8000].All(b => b == 0x41));
        }

        byte[] finding = Convert.FromBase64String(
            "I4AjgCOAI4AAACOAI4AjgCOAAAAjgCOAI4AjgCOAAAAjgCOAI4AjgAAAI4AjgCOAI4AjgCOAAAAjgCOAI4AjgAAAI4AjgCOAI4AjgAAAI4AjgCOAI4AAACOAI4AjgCOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOAI4AAACOAI4AjgCMAI4AjgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjgCOAAAAjgCOAI4AjAAAA");
        Assert.Equal(198, finding.Length);
        Assert.NotEqual(0, ReadOctets(finding, Asn1.Ber).Status);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"took {clock.Elapsed}");

        Assert.False(Reads("2480 040141", Asn1.Ber));                // no end-of-contents
        Assert.False(Reads("2480 040141 00", Asn1.Ber));             // half of it
        Assert.False(Reads("2480 2480 040141 0000", Asn1.Ber));      // the segment ended, the string not
        Assert.False(Reads("2404 2480 0401", Asn1.Ber));             // a segment's end past its parent's
        Assert.True(Reads("2407 2480 040141 0000", Asn1.Ber));       // an indefinite segment in a definite string
    }

    /// <summary>
    /// The functions that take an element refuse one whose flags httpasm_asn1_read never returns
    /// (any bit but HTTPASM_ASN1_INDEFINITE): the reader's internal mark of a string whose end is
    /// not found yet would make the segment walk take the contents' length for a bound and write
    /// the caller's const element. The same element with its own flags is checked as usual.
    /// </summary>
    [Fact]
    public void RefusesElementsItNeverReturns()
    {
        Platform.RequireLinuxX64();
        byte[] input = Convert.FromHexString("2480040141 0000".Replace(" ", ""));
        fixed (byte* p = input)
        {
            Asn1Element e;
            Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
            Assert.Equal(Asn1.Indefinite, e.Flags);
            byte* out8 = stackalloc byte[8];
            uint unused;
            Assert.Equal(0, Native.Asn1Check(&e, Asn1.OctetString, Asn1.Ber));
            Assert.Equal(1L, Native.Asn1Octets(&e, out8, 8, Asn1.Ber));
            foreach (uint flags in new uint[] { 2, 3, 0x80000000, 0xFFFFFFFF })
            {
                Asn1Element changed = e;
                changed.Flags = flags;
                Assert.Equal(-1, Native.Asn1Check(&changed, Asn1.OctetString, Asn1.Ber));
                Assert.Equal(-1L, Native.Asn1Octets(&changed, out8, 8, Asn1.Ber));
                Assert.Equal(-1L, Native.Asn1Bits(&changed, out8, 8, &unused, Asn1.Ber));
                Assert.Equal(flags, changed.Flags);  // nothing written
            }
        }
    }

    /// <summary>BOOLEAN (8.2): primitive, one octet; any non-zero octet is TRUE under BER, all ones
    /// under DER (11.1).</summary>
    [Fact]
    [Requirement("X690-8.2.1", "X690-8.2.2", "X690-11.1")]
    public void ReadsBooleans()
    {
        Platform.RequireLinuxX64();
        foreach (int rules in new[] { Asn1.Der, Asn1.Ber })
        {
            Assert.True(Reads("0101 00", rules));
            Assert.True(Reads("0101 FF", rules));
            Assert.False(Reads("0100", rules));
            Assert.False(Reads("0102 0000", rules));
            Assert.False(Reads("2103 010100", rules));
        }

        Assert.True(Reads("0101 01", Asn1.Ber));
        Assert.True(Reads("0101 80", Asn1.Ber));
        Assert.False(Reads("0101 01", Asn1.Der));
        Assert.False(Reads("0101 80", Asn1.Der));
    }

    /// <summary>
    /// INTEGER and ENUMERATED (8.3, 8.4): primitive, one octet or more, in the fewest octets under
    /// both rules: the first octet's bits and the second's bit 8 neither all zero nor all ones.
    /// </summary>
    /// <param name="value">The contents in hex.</param>
    /// <param name="valid">Whether they are an integer's.</param>
    [Theory]
    [InlineData("00", true)]
    [InlineData("7F", true)]
    [InlineData("80", true)]
    [InlineData("FF", true)]
    [InlineData("0080", true)]
    [InlineData("FF7F", true)]
    [InlineData("00FF", true)]
    [InlineData("0100", true)]
    [InlineData("007F", false)]
    [InlineData("0000", false)]
    [InlineData("FF80", false)]
    [InlineData("FFFF", false)]
    [InlineData("00000001", false)]
    [InlineData("", false)]
    [Requirement("X690-8.3.1", "X690-8.3.2", "X690-8.4")]
    public void ReadsIntegersInTheFewestOctets(string value, bool valid)
    {
        Platform.RequireLinuxX64();
        byte[] v = Convert.FromHexString(value);
        foreach (byte tag in new byte[] { 0x02, 0x0A })
        {
            Assert.Equal(valid, Reads(Tlv(tag, v), Asn1.Der));
            Assert.Equal(valid, Reads(Tlv(tag, v), Asn1.Ber));
        }

        Assert.False(Reads("2203 020100", Asn1.Ber));             // constructed
    }

    /// <summary>
    /// BIT STRING's primitive form (8.6.2): an initial octet counting the final octet's unused bits,
    /// 0 to 7 (8.6.2.2), 0 when the string is empty (8.6.2.3); under DER every unused bit zero
    /// (11.2.1). X.690's own example (8.6.4.2: '0A3B5F291CD'H) reads under both rules.
    /// </summary>
    /// <param name="value">The contents in hex.</param>
    /// <param name="der">Whether DER takes them.</param>
    /// <param name="ber">Whether BER takes them.</param>
    [Theory]
    [InlineData("00", true, true)]
    [InlineData("040A3B5F291CD0", true, true)]
    [InlineData("0780", true, true)]
    [InlineData("0781", false, true)]
    [InlineData("01FE", true, true)]
    [InlineData("01FF", false, true)]
    [InlineData("00FF", true, true)]
    [InlineData("01", false, false)]
    [InlineData("08FF", false, false)]
    [InlineData("FF00", false, false)]
    [InlineData("", false, false)]
    [Requirement("X690-8.6.1", "X690-8.6.2", "X690-8.6.2.2", "X690-8.6.2.3", "X690-11.2.1")]
    public void ReadsPrimitiveBitStrings(string value, bool der, bool ber)
    {
        Platform.RequireLinuxX64();
        byte[] v = Convert.FromHexString(value);
        Assert.Equal(der, Reads(Tlv(0x03, v), Asn1.Der));
        Assert.Equal(ber, Reads(Tlv(0x03, v), Asn1.Ber));
    }

    /// <summary>
    /// BER's constructed BIT STRING (8.6.3, 8.6.4): segments that are BIT STRINGs themselves
    /// (universal 3, 8.6.4.1), possibly constructed in turn, every one but the last whole
    /// octets; X.690's own constructed example reads, and its bits join to the primitive
    /// example's. DER refuses the form (10.2).
    /// </summary>
    [Fact]
    [Requirement("X690-8.6.3", "X690-8.6.4", "X690-8.6.4.1", "X690-10.2", "X690-7.3")]
    public void ReadsConstructedBitStringsUnderBerOnly()
    {
        Platform.RequireLinuxX64();
        const string example = "2380 0303000A3B 0305045F291CD0 0000";
        Assert.True(Reads(example, Asn1.Ber));
        Assert.False(Reads(example, Asn1.Der));
        Assert.True(Reads("230A 0303000A3B 2303 030100", Asn1.Ber));       // a constructed segment, empty
        Assert.True(Reads("2300", Asn1.Ber));                              // no segment: the empty value
        Assert.True(Reads("2380 2380 0302000A 0000 0302045F 0000", Asn1.Ber));
        Assert.False(Reads("2380 0302040A 0302005F 0000", Asn1.Ber));     // a segment after one ending mid-octet
        Assert.False(Reads("2380 0402000A 0000", Asn1.Ber));              // an OCTET STRING segment
        Assert.False(Reads("2380 0301 08 0000", Asn1.Ber));               // a segment breaking 8.6.2.2
        Assert.False(Reads("2380 0300 0000", Asn1.Ber));                  // a segment without its initial octet

        // httpasm_asn1_bits joins the segments' bits and gives the last one's unused count
        byte[] input = Convert.FromHexString(example.Replace(" ", ""));
        fixed (byte* p = input)
        {
            Asn1Element e;
            Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
            byte* bits = stackalloc byte[16];
            uint unused = 99;
            Assert.Equal(6L, Native.Asn1Bits(&e, bits, 16, &unused, Asn1.Ber));
            Assert.Equal("0A3B5F291CD0", Convert.ToHexString(new ReadOnlySpan<byte>(bits, 6)));
            Assert.Equal(4u, unused);
            Assert.Equal(-1L, Native.Asn1Bits(&e, bits, 5, &unused, Asn1.Ber));      // does not fit
            Assert.Equal(-1L, Native.Asn1Bits(&e, bits, 16, &unused, Asn1.Der));     // DER: refused
        }

        // the unused count is the last primitive segment's, whatever empty constructed segments
        // follow it (indefinite or definite, nested or not; tests/fuzz/asn1.c found the first)
        byte* trailedBits = stackalloc byte[4];
        foreach (string trailed in new[] { "2380 0303020A40 2380 0000 0000", "2380 0303020A40 2300 2380 2380 0000 0000 0000", "2309 0303020A40 2302 2300" })
        {
            byte[] t = Convert.FromHexString(trailed.Replace(" ", ""));
            fixed (byte* p = t)
            {
                Asn1Element e;
                Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)t.Length, Asn1.Ber));
                uint unused = 99;
                Assert.Equal(2L, Native.Asn1Bits(&e, trailedBits, 4, &unused, Asn1.Ber));
                Assert.True(unused == 2, $"{trailed}: {unused} unused bits");
            }
        }
    }

    /// <summary>
    /// BER's segments in a definite-length constructed string, which the reader walks itself
    /// (no indefinite walk read them first): a nested segment of another type, a BIT STRING
    /// segment without its initial octet, with more than 7 unused bits, or of one octet with
    /// unused bits, each refused (8.6.2, 8.6.2.2, 8.6.2.3, 8.7.3.2); and segments nested past the
    /// reader's 32 levels, definite all the way down, refused too (each level takes stack).
    /// </summary>
    [Fact]
    [Requirement("X690-8.6.2", "X690-8.6.2.2", "X690-8.6.2.3", "X690-8.7.3.2")]
    public void ChecksDefiniteSegmentsToo()
    {
        Platform.RequireLinuxX64();
        Assert.True(Reads("2405 2403 040100", Asn1.Ber));
        Assert.False(Reads("2405 2403 030100", Asn1.Ber));       // a nested segment: a BIT STRING
        Assert.True(Reads("2303 030100", Asn1.Ber));
        Assert.False(Reads("2302 0300", Asn1.Ber));              // no initial octet
        Assert.False(Reads("2303 030108", Asn1.Ber));            // 8 unused bits
        Assert.False(Reads("2303 030103", Asn1.Ber));            // one octet, unused bits
        static byte[] Nest(int levels)
        {
            byte[] e = [0x04, 0x01, 0xAA];
            for (int i = 0; i < levels; i++)
            {
                e = Encode(0x24, e);
            }

            return e;
        }

        Assert.Equal(0, ReadOctets(Nest(20), Asn1.Ber).Status);
        Assert.NotEqual(0, ReadOctets(Nest(40), Asn1.Ber).Status);
    }

    /// <summary>
    /// OCTET STRING (8.7): any octets in the primitive form; under BER the constructed form too,
    /// its segments OCTET STRINGs (8.7.3, 8.7.3.2), joined by httpasm_asn1_octets; DER refuses
    /// the constructed form (10.2).
    /// </summary>
    [Fact]
    [Requirement("X690-8.7.1", "X690-8.7.3", "X690-8.7.3.2", "X690-10.2", "X690-7.3")]
    public void ReadsOctetStrings()
    {
        Platform.RequireLinuxX64();
        Assert.True(Reads("0400", Asn1.Der));
        Assert.True(Reads("0403 000102", Asn1.Der));
        const string segmented = "2480 04020102 2480 0401 03 0400 0000 0000";
        Assert.True(Reads(segmented, Asn1.Ber));
        Assert.False(Reads(segmented, Asn1.Der));
        Assert.False(Reads("2480 03020102 0000", Asn1.Ber));          // a BIT STRING segment
        Assert.False(Reads("2480 0C020102 0000", Asn1.Ber));          // a UTF8String segment
        Assert.True(Reads("2404 04020102", Asn1.Ber));                // definite, segmented

        byte[] input = Convert.FromHexString(segmented.Replace(" ", ""));
        fixed (byte* p = input)
        {
            Asn1Element e;
            Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
            byte* octets = stackalloc byte[8];
            Assert.Equal(3L, Native.Asn1Octets(&e, octets, 8, Asn1.Ber));
            Assert.Equal("010203", Convert.ToHexString(new ReadOnlySpan<byte>(octets, 3)));
            Assert.Equal(-1L, Native.Asn1Octets(&e, octets, 2, Asn1.Ber));
        }
    }

    /// <summary>NULL (8.8): primitive, no contents octet.</summary>
    [Fact]
    [Requirement("X690-8.8.1", "X690-8.8.2")]
    public void ReadsNull()
    {
        Platform.RequireLinuxX64();
        foreach (int rules in new[] { Asn1.Der, Asn1.Ber })
        {
            Assert.True(Reads("0500", rules));
            Assert.False(Reads("0501 00", rules));
            Assert.False(Reads("2500", rules));
        }
    }

    /// <summary>
    /// OBJECT IDENTIFIER (8.19): primitive (8.19.1), one subidentifier at least (8.19.3), each in
    /// the fewest octets (no leading 0x80) and the last ended (bit 8 clear) (8.19.2); rsaEncryption
    /// and id-ecPublicKey, the arcs over 2^32 that the rules allow, and their broken forms.
    /// </summary>
    /// <param name="value">The contents in hex.</param>
    /// <param name="valid">Whether they are an object identifier's.</param>
    [Theory]
    [InlineData("2A864886F70D010101", true)]
    [InlineData("2A8648CE3D0201", true)]
    [InlineData("00", true)]
    [InlineData("7F", true)]
    [InlineData("8100", true)]
    [InlineData("2B8F8F8F8F8F8F8F8F7F", true)]
    [InlineData("", false)]
    [InlineData("80", false)]
    [InlineData("8001", false)]
    [InlineData("2A8001", false)]
    [InlineData("2A86", false)]
    [InlineData("2A864886F70D0101", true)]
    [InlineData("2A864886F70D0181", false)]
    [Requirement("X690-8.19.1", "X690-8.19.2", "X690-8.19.3")]
    public void ReadsObjectIdentifiers(string value, bool valid)
    {
        Platform.RequireLinuxX64();
        byte[] v = Convert.FromHexString(value);
        Assert.Equal(valid, Reads(Tlv(0x06, v), Asn1.Der));
        Assert.Equal(valid, Reads(Tlv(0x06, v), Asn1.Ber));
        Assert.False(Reads("2603 0601 2A", Asn1.Ber));
    }

    /// <summary>SEQUENCE, SEQUENCE OF, SET and SET OF are constructed (8.9.1, 8.10.1, 8.11.1,
    /// 8.12.1): the primitive form of their tags is refused, whatever the contents.</summary>
    [Fact]
    [Requirement("X690-8.9.1", "X690-8.10.1", "X690-8.11.1", "X690-8.12.1")]
    public void SequencesAndSetsAreConstructed()
    {
        Platform.RequireLinuxX64();
        foreach (int rules in new[] { Asn1.Der, Asn1.Ber })
        {
            Assert.True(Reads("3000", rules));
            Assert.True(Reads("3100", rules));
            Assert.True(Reads("3003 020101", rules));
            Assert.False(Reads("1000", rules));
            Assert.False(Reads("1100", rules));
            Assert.False(Reads("1003 020101", rules));
        }
    }

    /// <summary>The single-octet string types' sets (8.23.3 with X.680's tables): each type with
    /// every octet value, allowed exactly where its set has it.</summary>
    /// <param name="tag">The type's tag number.</param>
    /// <param name="allowed">The set, as a description the test turns into a predicate.</param>
    [Theory]
    [InlineData(19, "printable")]
    [InlineData(18, "numeric")]
    [InlineData(22, "ia5")]
    [InlineData(26, "visible")]
    [InlineData(20, "any")]
    [InlineData(21, "any")]
    [InlineData(25, "any")]
    [InlineData(27, "any")]
    [Requirement("X690-8.23.3")]
    public void ReadsEachStringTypesCharacters(int tag, string allowed)
    {
        Platform.RequireLinuxX64();
        const string printable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
        Func<int, bool> ok = allowed switch
        {
            "printable" => c => c < 128 && printable.Contains((char)c),
            "numeric" => c => c == ' ' || (c >= '0' && c <= '9'),
            "ia5" => c => c < 128,
            "visible" => c => c >= 0x20 && c <= 0x7E,
            _ => _ => true,
        };
        for (int c = 0; c < 256; c++)
        {
            byte[] value = [(byte)'A', (byte)c, (byte)'1'];
            if (allowed == "numeric")
            {
                value = [(byte)'1', (byte)c, (byte)'2'];
            }

            Assert.True(ok(c) == Reads(Tlv((byte)tag, value), Asn1.Der), $"tag {tag}, octet 0x{c:X2}");
        }
    }

    /// <summary>
    /// UTF8String (8.23.10): ISO 10646 Annex D's octets, each character in the fewest octets (no
    /// overlong form), no surrogate, nothing past U+10FFFF, no character cut short.
    /// </summary>
    /// <param name="value">The contents in hex.</param>
    /// <param name="valid">Whether they are UTF-8.</param>
    [Theory]
    [InlineData("", true)]
    [InlineData("41", true)]
    [InlineData("C3A9", true)]
    [InlineData("E282AC", true)]
    [InlineData("F09F9880", true)]
    [InlineData("F48FBFBF", true)]
    [InlineData("EFBFBF", true)]
    [InlineData("ED9FBF", true)]
    [InlineData("EE8080", true)]
    [InlineData("C080", false)]
    [InlineData("C1BF", false)]
    [InlineData("E080BF", false)]
    [InlineData("E09FBF", false)]
    [InlineData("F08FBFBF", false)]
    [InlineData("EDA080", false)]
    [InlineData("EDBFBF", false)]
    [InlineData("F4908080", false)]
    [InlineData("F5808080", false)]
    [InlineData("FF", false)]
    [InlineData("80", false)]
    [InlineData("C3", false)]
    [InlineData("E282", false)]
    [InlineData("C341", false)]
    [Requirement("X690-8.23.10")]
    public void ReadsUtf8Strings(string value, bool valid)
    {
        Platform.RequireLinuxX64();
        byte[] v = Convert.FromHexString(value);
        Assert.Equal(valid, Reads(Tlv(0x0C, v), Asn1.Der));
        Assert.Equal(valid, Reads(Tlv(0x0C, v), Asn1.Ber));
        if (valid)
        {
            Assert.Equal(value, Convert.ToHexString(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(v))));
        }
    }

    /// <summary>
    /// BMPString (8.23.8) is two octets a character in the BMP's form, which has no surrogates;
    /// UniversalString (8.23.7) is four, up to U+10FFFF, without surrogates either.
    /// </summary>
    [Fact]
    [Requirement("X690-8.23.7", "X690-8.23.8")]
    public void ReadsBmpAndUniversalStrings()
    {
        Platform.RequireLinuxX64();
        Assert.True(Reads(Tlv(0x1E, Convert.FromHexString("0041FFFF00E9")), Asn1.Der));
        Assert.True(Reads(Tlv(0x1E, []), Asn1.Der));
        Assert.False(Reads(Tlv(0x1E, Convert.FromHexString("0041D800")), Asn1.Der));
        Assert.False(Reads(Tlv(0x1E, Convert.FromHexString("DBFFDFFF")), Asn1.Der));   // a surrogate pair: not BMP's form
        Assert.False(Reads(Tlv(0x1E, Convert.FromHexString("004100")), Asn1.Der));     // half a character
        Assert.True(Reads(Tlv(0x1C, Convert.FromHexString("000000410010FFFF")), Asn1.Der));
        Assert.False(Reads(Tlv(0x1C, Convert.FromHexString("00110000")), Asn1.Der));
        Assert.False(Reads(Tlv(0x1C, Convert.FromHexString("0000D800")), Asn1.Der));
        Assert.False(Reads(Tlv(0x1C, Convert.FromHexString("0000004100")), Asn1.Der));
        Assert.False(Reads(Tlv(0x1C, Convert.FromHexString("80000041")), Asn1.Der));
    }

    /// <summary>
    /// BER's constructed strings (8.23.3, 8.23.6): segments of OCTET STRING whose octets, joined,
    /// are the string; a UTF-8 character may span two segments, and an invalid one across them is
    /// refused as it would be whole; DER refuses the form (10.2).
    /// </summary>
    [Fact]
    [Requirement("X690-8.23.3", "X690-8.23.6", "X690-10.2", "X690-7.3")]
    public void ReadsConstructedStringsUnderBerOnly()
    {
        Platform.RequireLinuxX64();
        const string split = "2C80 0401C3 0401A9 0000";
        Assert.True(Reads(split, Asn1.Ber));
        Assert.False(Reads(split, Asn1.Der));
        Assert.False(Reads("2C80 0401C3 040141 0000", Asn1.Ber));     // a continuation missing
        Assert.False(Reads("2C80 0401C3 0000", Asn1.Ber));            // a character cut at the end
        Assert.True(Reads("3380 0402 4142 0401 43 0000", Asn1.Ber));  // PrintableString "ABC"
        Assert.False(Reads("3380 0402 4142 0401 2A 0000", Asn1.Ber)); // ... with '*'
        Assert.False(Reads("3380 1302 4142 0000", Asn1.Ber));         // a PrintableString segment: OCTET STRINGs only
        Assert.True(Reads("3E80 040100 0403 41D7FF 0000", Asn1.Ber));  // BMP: a character across segments
        Assert.False(Reads("3E80 040100 0401 41 0401D8 0000", Asn1.Ber));

        byte[] input = Convert.FromHexString(split.Replace(" ", ""));
        fixed (byte* p = input)
        {
            Asn1Element e;
            Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
            byte* octets = stackalloc byte[4];
            Assert.Equal(2L, Native.Asn1Octets(&e, octets, 4, Asn1.Ber));
            Assert.Equal("é", Encoding.UTF8.GetString(octets, 2));
        }
    }

    /// <summary>
    /// UTCTime under DER (11.8): YYMMDDhhmmssZ, with X.690's valid and invalid examples (11.8.4,
    /// 11.8.5), every field's range, February's 29th in the years RFC 5280's 1950-2049 makes leap,
    /// and the characters of VisibleString (8.25).
    /// </summary>
    /// <param name="time">The characters.</param>
    /// <param name="valid">Whether DER takes them.</param>
    [Theory]
    [InlineData("920521000000Z", true)]
    [InlineData("920622123421Z", true)]
    [InlineData("920722132100Z", true)]
    [InlineData("920520240000Z", false)]
    [InlineData("9207221321Z", false)]
    [InlineData("920722132100", false)]
    [InlineData("920722132100+0000", false)]
    [InlineData("921322132100Z", false)]
    [InlineData("920022132100Z", false)]
    [InlineData("920732132100Z", false)]
    [InlineData("920700132100Z", false)]
    [InlineData("920431000000Z", false)]
    [InlineData("920430000000Z", true)]
    [InlineData("000229000000Z", true)]
    [InlineData("480229000000Z", true)]
    [InlineData("990229000000Z", false)]
    [InlineData("500228235959Z", true)]
    [InlineData("920722136000Z", false)]
    [InlineData("920722135960Z", false)]
    [InlineData("92072213210AZ", false)]
    [InlineData("920722132100z", false)]
    [Requirement("X690-11.8.1", "X690-11.8.2", "X690-11.8.3", "X690-8.25")]
    public void ReadsUtcTimesInDerForm(string time, bool valid)
    {
        Platform.RequireLinuxX64();
        Assert.Equal(valid, Reads(Tlv(0x17, Encoding.ASCII.GetBytes(time)), Asn1.Der));
    }

    /// <summary>
    /// GeneralizedTime under DER (11.7): YYYYMMDDhhmmss, a fraction with "." and without trailing
    /// zeros, then Z; X.690's valid and invalid examples, the Gregorian leap years (2000 is one,
    /// 1900 is not), and every field's range.
    /// </summary>
    /// <param name="time">The characters.</param>
    /// <param name="valid">Whether DER takes them.</param>
    [Theory]
    [InlineData("19920521000000Z", true)]
    [InlineData("19920622123421Z", true)]
    [InlineData("19920722132100.3Z", true)]
    [InlineData("19920520240000Z", false)]
    [InlineData("19920622123421.0Z", false)]
    [InlineData("19920722132100.30Z", false)]
    [InlineData("19920722132100.Z", false)]
    [InlineData("19920722132100,3Z", false)]
    [InlineData("199207221321Z", false)]
    [InlineData("19920722132100", false)]
    [InlineData("19920722132100+0100", false)]
    [InlineData("20000229000000Z", true)]
    [InlineData("19000229000000Z", false)]
    [InlineData("20240229000000Z", true)]
    [InlineData("20230229000000Z", false)]
    [InlineData("24000229000000Z", true)]
    [InlineData("99991231235959.999999999Z", true)]
    [InlineData("00000101000000Z", true)]
    [InlineData("19921301000000Z", false)]
    [InlineData("19920100000000Z", false)]
    [InlineData("19920101236000Z", false)]
    [InlineData("19920101235960Z", false)]
    [Requirement("X690-11.7.1", "X690-11.7.2", "X690-11.7.3", "X690-11.7.4", "X690-11.7.5", "X690-8.25")]
    public void ReadsGeneralizedTimesInDerForm(string time, bool valid)
    {
        Platform.RequireLinuxX64();
        Assert.Equal(valid, Reads(Tlv(0x18, Encoding.ASCII.GetBytes(time)), Asn1.Der));
    }

    /// <summary>
    /// The times under BER (8.25 with X.680's forms): UTCTime without its seconds or with a
    /// differential; GeneralizedTime with the minute and second optional, a fraction of any unit
    /// written with "." or ",", local time (no suffix), Z, or a differential of hours with or
    /// without minutes (a sign without two digits after it, or characters after its minutes, is
    /// refused). Fields stay in range, and a time in BER's constructed form is checked whole, its
    /// characters gathered from its segments.
    /// </summary>
    /// <param name="tag">23 or 24.</param>
    /// <param name="time">The characters.</param>
    /// <param name="valid">Whether BER takes them.</param>
    [Theory]
    [InlineData(23, "9205211230Z", true)]
    [InlineData(23, "920521123045Z", true)]
    [InlineData(23, "9205211230+0100", true)]
    [InlineData(23, "920521123045-1130", true)]
    [InlineData(23, "9205211230+01", false)]
    [InlineData(23, "9205211230", false)]
    [InlineData(23, "92052112Z", false)]
    [InlineData(23, "9205211230+2400", false)]
    [InlineData(23, "9205211230+0160", false)]
    [InlineData(23, "92052112304Z", false)]
    [InlineData(23, "9205211230+", false)]
    [InlineData(23, "9205211230+1", false)]
    [InlineData(23, "9205211230-01005", false)]
    [InlineData(24, "1992052112", true)]
    [InlineData(24, "1992052112Z", true)]
    [InlineData(24, "199205211230", true)]
    [InlineData(24, "19920521123045", true)]
    [InlineData(24, "19920521123045.50Z", true)]
    [InlineData(24, "19920521123045,5", true)]
    [InlineData(24, "1992052112.5Z", true)]
    [InlineData(24, "199205211230.25-05", true)]
    [InlineData(24, "19920521123045+0530", true)]
    [InlineData(24, "19920521123045.", false)]
    [InlineData(24, "19920521123045+053", false)]
    [InlineData(24, "19920521123045+05300", false)]
    [InlineData(24, "1992052112-x5", false)]
    [InlineData(24, "1992052112305", false)]
    [InlineData(24, "199205211", false)]
    [InlineData(24, "1992052124", false)]
    [InlineData(24, "19920521123045ZZ", false)]
    [Requirement("X690-8.25", "X690-7.3")]
    public void ReadsTimesInBerForms(int tag, string time, bool valid)
    {
        Platform.RequireLinuxX64();
        byte[] octets = Encoding.ASCII.GetBytes(time);
        Assert.Equal(valid, Reads(Tlv((byte)tag, octets), Asn1.Ber));

        // the same characters in two segments
        int half = octets.Length / 2;
        byte[] constructed = Encode((byte)(0x20 | tag), [.. Encode(0x04, octets[..half]), .. Encode(0x04, octets[half..])]);
        Assert.Equal(valid, ReadOctets(constructed, Asn1.Ber).Status == 0);
        Assert.False(ReadOctets(constructed, Asn1.Der).Status == 0);
    }

    /// <summary>
    /// A constructed time's characters are gathered into 64 octets of the reader's own: a
    /// GeneralizedTime whose fraction would take more is refused under BER's constructed form
    /// (the limit no real time comes near), though the primitive form of the same time reads.
    /// </summary>
    [Fact]
    public void RefusesConstructedTimesPastSixtyFourCharacters()
    {
        Platform.RequireLinuxX64();
        string time = "19920521123045." + new string('5', 64 - 16) + "Z";
        string longer = "19920521123045." + new string('5', 64 - 15) + "Z";
        Assert.Equal(64, time.Length);
        foreach ((string t, bool ok) in new[] { (time, true), (longer, false) })
        {
            byte[] octets = Encoding.ASCII.GetBytes(t);
            Assert.True(Reads(Tlv(0x18, octets), Asn1.Ber));
            byte[] constructed = Encode(0x38, [.. Encode(0x04, octets[..10]), .. Encode(0x04, octets[10..])]);
            Assert.Equal(ok, ReadOctets(constructed, Asn1.Ber).Status == 0);
        }
    }

    /// <summary>
    /// Universal types the reader does not check are refused rather than passed through: REAL,
    /// EXTERNAL, EMBEDDED PDV, ObjectDescriptor, RELATIVE-OID, TIME, number 15 (reserved),
    /// CHARACTER STRING, and the numbers from 31 on (DATE, TIME-OF-DAY, DATE-TIME, DURATION, the
    /// OID-IRIs, and the unassigned).
    /// </summary>
    /// <param name="hex">An encoding of such a type.</param>
    [Theory]
    [InlineData("0900")]
    [InlineData("0903 0380FF")]
    [InlineData("2800")]
    [InlineData("2B00")]
    [InlineData("0700")]
    [InlineData("0D01 01")]
    [InlineData("0E00")]
    [InlineData("0F00")]
    [InlineData("3D00")]
    [InlineData("1F1F 00")]
    [InlineData("1F22 00")]
    [InlineData("1F24 00")]
    [InlineData("1F25 00")]
    [InlineData("1F8100 00")]
    public void RefusesTypesTheReaderDoesNotCheck(string hex)
    {
        Platform.RequireLinuxX64();
        Assert.False(Reads(hex, Asn1.Der));
        Assert.False(Reads(hex, Asn1.Ber));
    }

    /// <summary>
    /// An application, context-specific or private tag's type is the caller's to know: its
    /// contents are not looked at (primitive or constructed alike), and a constructed one's
    /// nested elements are the caller's to read in turn, unless the length is indefinite, when
    /// the reader must read them to find the end.
    /// </summary>
    [Fact]
    public void LeavesOtherClassesContentsToTheCaller()
    {
        Platform.RequireLinuxX64();
        Assert.True(Reads("8003 FFFFFF", Asn1.Der));
        Assert.True(Reads("A003 FFFFFF", Asn1.Der));
        Assert.True(Reads("4100", Asn1.Der));
        Assert.True(Reads("C5 02 0000", Asn1.Der));
        Assert.True(Reads("3003 FFFFFF", Asn1.Der));             // a SEQUENCE's contents too
        Assert.False(Reads("A080 FFFFFF 0000", Asn1.Ber));       // indefinite: they are read
    }

    /// <summary>
    /// httpasm_asn1_check applies a universal type's rules to an element read under an implicit
    /// tag (8.14.4): the element keeps its own form (a primitive [0] is no SEQUENCE, 8.14.4 a), the
    /// contents are the base encoding's (b); a type the reader does not check, or a class bit in
    /// the type, is refused.
    /// </summary>
    [Fact]
    [Requirement("X690-8.14.4")]
    public void ChecksImplicitlyTaggedElements()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(0, Check("8102 0780", Asn1.BitString, Asn1.Der));
        Assert.Equal(-1, Check("8102 0781", Asn1.BitString, Asn1.Der));
        Assert.Equal(0, Check("8102 0781", Asn1.BitString, Asn1.Ber));
        Assert.Equal(-1, Check("8002 0005", Asn1.Integer, Asn1.Der));
        Assert.Equal(0, Check("8002 0085", Asn1.Integer, Asn1.Der));
        Assert.Equal(0, Check("A003 020101", Asn1.Sequence, Asn1.Der));
        Assert.Equal(0, Check("A003 020101", 16, Asn1.Der));                // the form bit is optional in type
        Assert.Equal(-1, Check("8000", Asn1.Sequence, Asn1.Der));
        Assert.Equal(-1, Check("8000", 9, Asn1.Der));                       // REAL: not checked
        Assert.Equal(-1, Check("8000", Asn1.Context | Asn1.Null, Asn1.Der));
        Assert.Equal(0, Check("8000", Asn1.Null, Asn1.Der));
        Assert.Equal(-1, Check("8000", 31, Asn1.Der));
        Assert.Equal(-1, Check("A380 0401C3 0401A9 0000", Asn1.Utf8String, Asn1.Der));
        Assert.Equal(0, Check("A380 0401C3 0401A9 0000", Asn1.Utf8String, Asn1.Ber));

        static int Check(string hex, uint type, int rules)
        {
            byte[] input = Convert.FromHexString(hex.Replace(" ", ""));
            fixed (byte* p = input)
            {
                Asn1Element e;
                Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
                return Native.Asn1Check(&e, type, rules);
            }
        }
    }

    /// <summary>
    /// A SET OF's components under DER are in ascending order of their encodings (11.6), equal
    /// ones allowed; under BER any order. Every component is read under the rules, and a
    /// primitive element is no SET OF (8.12.1).
    /// </summary>
    [Fact]
    [Requirement("X690-11.6", "X690-8.12.1")]
    public void ChecksSetOfOrder()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(0, SetOf("3106 020101 020102", Asn1.Der));
        Assert.Equal(-1, SetOf("3106 020102 020101", Asn1.Der));
        Assert.Equal(0, SetOf("3106 020102 020101", Asn1.Ber));
        Assert.Equal(0, SetOf("3106 020101 020101", Asn1.Der));
        Assert.Equal(0, SetOf("3107 020101 02020100", Asn1.Der));           // 02 01 01 < 02 02 01 00
        Assert.Equal(-1, SetOf("3107 02020100 020101", Asn1.Der));
        Assert.Equal(0, SetOf("3109 0C0141 0C0142 0C0143", Asn1.Der));
        Assert.Equal(0, SetOf("3100", Asn1.Der));
        Assert.Equal(0, SetOf("3103 020180", Asn1.Der));                    // one component
        Assert.Equal(-1, SetOf("3104 02020005", Asn1.Der));                 // a component breaking 8.3.2
        Assert.Equal(-1, SetOf("1100", Asn1.Ber, read: false));

        static int SetOf(string hex, int rules, bool read = true)
        {
            byte[] input = Convert.FromHexString(hex.Replace(" ", ""));
            fixed (byte* p = input)
            {
                Asn1Element e;
                if (read)
                {
                    Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)input.Length, Asn1.Ber));
                }
                else
                {
                    e = default;
                    e.Content = p + 2;
                    e.Tag = 17;
                }

                return Native.Asn1CheckSetOf(&e, rules);
            }
        }
    }

    /// <summary>
    /// Every prefix of real encodings (a SEQUENCE of each type, nested, indefinite under BER) is
    /// refused, never read past: each is placed at the end of a page before a guard page, so an
    /// octet read past the prefix would end the run.
    /// </summary>
    [Fact]
    public void NeverReadsPastTheInput()
    {
        Platform.RequireLinuxX64();
        string[] encodings =
        [
            "3057 0101FF 020300FFFF 0303040A30 040401020304 0500 06092A864886F70D010101 0C03C3A941 130441424344 170D3932303532313030303030305A 180F31393932303532313030303030305A 3100 A003020101 BF81000100",
            "3080 2480 0401C3 0000 2380 030100 0000 2C80 0401C3 0401A9 0000 3080 0500 0000 0000",
        ];
        foreach (string hex in encodings)
        {
            byte[] whole = Convert.FromHexString(hex.Replace(" ", ""));
            int rules = whole[1] == 0x80 ? Asn1.Ber : Asn1.Der;
            Assert.Equal(0, ReadOctets(whole, rules).Status);
            for (int n = 0; n < whole.Length; n++)
            {
                Assert.NotEqual(0, ReadOctets(whole[..n], rules).Status);
            }
        }
    }

    /// <summary>
    /// The differential test: .NET's System.Formats.Asn1 is an independent implementation of the
    /// same rules. Random structures that .NET's AsnWriter encodes (under DER, and CER for BER,
    /// whose long strings are constructed with indefinite lengths), then those structures
    /// mutated (an octet changed, inserted or removed, or the encoding cut), are walked element by
    /// element with both readers in step: at every element they must agree on its acceptance and
    /// its length, and where both accept a constructed element (not a string) the walk goes on
    /// into its contents. Where they disagree, the element responsible (found by descending
    /// through an indefinite length's nested elements) must belong to a triaged class, where the
    /// two readings differ on purpose; each class is counted and printed: tag numbers past the
    /// reader's 2^28 - 1, BMPString surrogate pairs (.NET decodes UTF-16; X.690 8.23.8's BMP form
    /// has none), and times .NET's DateTimeOffset cannot hold (year 0000, differentials past
    /// 14 hours) or forms it reads differently.
    /// </summary>
    [Fact]
    [Requirement("X690-7.3")]
    public void AgreesWithDotNetOnRandomAndMutatedEncodings()
    {
        Platform.RequireLinuxX64();
        var random = new Random(20261128);
        var triaged = new SortedDictionary<string, int>(StringComparer.Ordinal);
        int nodes = 0, accepted = 0;
        for (int round = 0; round < 2000; round++)
        {
            int rules = round % 3 == 0 ? Asn1.Ber : Asn1.Der;
            byte[] encoding = RandomEncoding(random, rules);
            Assert.True(Walk(encoding, rules) == encoding.Length, $"a valid encoding refused: {Convert.ToHexString(encoding)}");
            for (int m = 0; m < 4; m++)
            {
                _ = Walk(Mutate(random, encoding), rules);
            }
        }

        output.WriteLine($"{nodes:N0} elements compared, {accepted:N0} accepted by both");
        foreach ((string cls, int count) in triaged)
        {
            output.WriteLine($"  triaged: {cls}: {count}");
        }

        Assert.True(nodes > 20000, $"only {nodes} elements compared");

        // Compares the first element of input with both readers; returns its length when both
        // read it (after walking its contents), or -1.
        int Walk(byte[] input, int rules)
        {
            nodes++;
            Read ours = ReadOctets(input, rules);
            bool theirs = DotNetNode(input, rules, out int theirLength, out string? why);
            if ((ours.Status == 0) != theirs)
            {
                byte[] culprit = Culprit(input, rules);
                DotNetNode(culprit, rules, out _, out string? culpritWhy);
                string? cls = Triage(culprit, rules, culpritWhy ?? why);
                Assert.True(cls is not null,
                    $"disagreement under {(rules == Asn1.Der ? "DER" : "BER")}: ours {ours.Status == 0}, .NET {theirs} ({culpritWhy ?? why}) at {Convert.ToHexString(culprit)} in {Convert.ToHexString(input)}");
                triaged[cls!] = triaged.GetValueOrDefault(cls!) + 1;
                return -1;
            }

            if (ours.Status != 0)
            {
                return -1;
            }

            accepted++;
            Assert.True(ours.Length == theirLength, $"lengths {ours.Length} and {theirLength} for {Convert.ToHexString(input)}");
            if ((ours.Tag & Asn1.Constructed) != 0 && !IsUniversalString(ours.Tag))
            {
                int at = ours.ContentOffset, end = ours.ContentOffset + ours.ContentLength;
                while (at < end)
                {
                    int n = Walk(input[at..end], rules);
                    if (n < 0)
                    {
                        break;
                    }

                    at += n;
                }
            }

            return ours.Length;
        }
    }

    /// <summary>Whether a universal tag (either form) is a string type's or a time's: their
    /// constructed form holds segments, which the reader checks itself.</summary>
    /// <param name="tag">The tag.</param>
    /// <returns>True for BIT STRING, OCTET STRING, the restricted character strings and the times.</returns>
    private static bool IsUniversalString(uint tag)
    {
        if ((tag & 0xC0000000) != 0)
        {
            return false;
        }

        uint n = tag & 0x1FFFFFFF;
        return n is 3 or 4 or 12 or (>= 18 and <= 28) or 30;
    }

    /// <summary>
    /// .NET's verdict on the first element of input, with the reader's semantics: the element's
    /// structure, its universal type's rules through .NET's typed reader for that type, and,
    /// when its length is indefinite (the reader must walk its contents to find the end), the
    /// same verdict on every nested element.
    /// </summary>
    /// <param name="input">The encoding.</param>
    /// <param name="rules"><see cref="Asn1.Der"/> or <see cref="Asn1.Ber"/>.</param>
    /// <param name="consumed">The element's whole length, when it reads.</param>
    /// <param name="why">.NET's message, when it refused.</param>
    /// <returns>True when .NET reads it.</returns>
    private static bool DotNetNode(ReadOnlySpan<byte> input, int rules, out int consumed, out string? why)
    {
        AsnEncodingRules r = rules == Asn1.Der ? AsnEncodingRules.DER : AsnEncodingRules.BER;
        consumed = 0;
        why = null;
        try
        {
            if (!AsnDecoder.TryReadEncodedValue(input, r, out Asn1Tag tag, out int contentOffset, out int contentLength, out consumed))
            {
                why = "no element";
                return false;
            }

            if (tag.TagClass == TagClass.Universal)
            {
                Asn1Tag t = tag;
                int read;
                switch ((UniversalTagNumber)tag.TagValue)
                {
                    case UniversalTagNumber.Boolean: AsnDecoder.ReadBoolean(input, r, out read, t); break;
                    case UniversalTagNumber.Integer: AsnDecoder.ReadIntegerBytes(input, r, out read, t); break;
                    case UniversalTagNumber.Enumerated: AsnDecoder.ReadEnumeratedBytes(input, r, out read, t); break;
                    case UniversalTagNumber.BitString: AsnDecoder.ReadBitString(input, r, out _, out read, t); break;
                    case UniversalTagNumber.OctetString: AsnDecoder.ReadOctetString(input, r, out read, t); break;
                    case UniversalTagNumber.Null: AsnDecoder.ReadNull(input, r, out read, t); break;
                    case UniversalTagNumber.ObjectIdentifier: AsnDecoder.ReadObjectIdentifier(input, r, out read, t); break;
                    case UniversalTagNumber.Sequence: AsnDecoder.ReadSequence(input, r, out _, out _, out read, t); break;
                    case UniversalTagNumber.Set: AsnDecoder.ReadSetOf(input, r, out _, out _, out read, skipSortOrderValidation: true, t); break;
                    case UniversalTagNumber.UtcTime: AsnDecoder.ReadUtcTime(input, r, out read, 2049, t); break;
                    case UniversalTagNumber.GeneralizedTime: AsnDecoder.ReadGeneralizedTime(input, r, out read, t); break;
                    case UniversalTagNumber.UTF8String:
                    case UniversalTagNumber.NumericString:
                    case UniversalTagNumber.PrintableString:
                    case UniversalTagNumber.T61String:
                    case UniversalTagNumber.IA5String:
                    case UniversalTagNumber.VisibleString:
                    case UniversalTagNumber.BMPString:
                    case UniversalTagNumber.UniversalString:
                        AsnDecoder.ReadCharacterString(input, r, (UniversalTagNumber)tag.TagValue, out read, t);
                        break;
                    case UniversalTagNumber.VideotexString:
                    case UniversalTagNumber.GraphicString:
                    case UniversalTagNumber.GeneralString:
                        {
                            // .NET has no typed reader for these: read as what X.690 8.23.3 says
                            // they are, [UNIVERSAL x] IMPLICIT OCTET STRING, by giving the copy
                            // OCTET STRING's identifier (their numbers fit the one octet).
                            byte[] retagged = input.ToArray();
                            retagged[0] = (byte)((retagged[0] & 0x20) | 0x04);
                            AsnDecoder.ReadOctetString(retagged, r, out read);
                            break;
                        }
                    default:
                        why = "a universal type the library does not check";
                        return false;
                }

                if (read != consumed)
                {
                    why = "the typed read took another length";
                    return false;
                }

                if (IsUniversalString(tag.IsConstructed ? (uint)tag.TagValue | Asn1.Constructed : (uint)tag.TagValue))
                {
                    return true;                    // its segments: the typed reader checked them
                }
            }

            if (tag.IsConstructed && consumed == contentOffset + contentLength + 2)
            {
                // an indefinite length: the nested elements are read whole to find the end
                ReadOnlySpan<byte> contents = input.Slice(contentOffset, contentLength);
                while (!contents.IsEmpty)
                {
                    if (!DotNetNode(contents, rules, out int n, out why))
                    {
                        return false;
                    }

                    contents = contents[n..];
                }
            }

            return true;
        }
        catch (Exception e) when (e is AsnContentException or ArgumentException or OverflowException or FormatException)
        {
            why = e.Message;
            return false;
        }
    }

    /// <summary>The element a disagreement on input's first element comes from: the element
    /// itself, or, when it has an indefinite length (both readers read its nested elements), the
    /// first nested one they disagree on, found recursively.</summary>
    /// <param name="input">The encoding whose first element they disagree on.</param>
    /// <param name="rules">The rules.</param>
    /// <returns>The responsible element's encoding (and what follows it in its parent).</returns>
    private static byte[] Culprit(byte[] input, int rules)
    {
        Read ours = ReadOctets(input, rules);
        bool theirs = DotNetNode(input, rules, out int theirLength, out _);
        int start, end;
        if (ours.Status == 0 && (ours.Flags & Asn1.Indefinite) != 0)
        {
            (start, end) = (ours.ContentOffset, ours.ContentOffset + ours.ContentLength);
        }
        else if (theirs && AsnDecoder.TryReadEncodedValue(input, rules == Asn1.Der ? AsnEncodingRules.DER : AsnEncodingRules.BER,
                     out Asn1Tag tag, out int offset, out int length, out _) && tag.IsConstructed && theirLength == offset + length + 2)
        {
            (start, end) = (offset, offset + length);
        }
        else
        {
            return input;
        }

        while (start < end)
        {
            byte[] nested = input[start..end];
            Read n = ReadOctets(nested, rules);
            bool d = DotNetNode(nested, rules, out int dn, out _);
            if ((n.Status == 0) != d)
            {
                return Culprit(nested, rules);
            }

            if (!d)
            {
                break;
            }

            start += dn;
        }

        return input;
    }

    /// <summary>The class a disagreement's responsible element belongs to, or null when it
    /// belongs to none (a bug in one reader or the other, to be looked at).</summary>
    /// <param name="element">The element's encoding.</param>
    /// <param name="rules">The rules.</param>
    /// <param name="why">.NET's message, when it refused.</param>
    /// <returns>The class's name.</returns>
    private static string? Triage(byte[] element, int rules, string? why)
    {
        bool ours = ReadOctets(element, rules).Status == 0;
        if (element.Length >= 2 && (element[0] & 0x1F) == 0x1F && !ours)
        {
            int subsequent = 0;
            for (int i = 1; i < element.Length; i++)
            {
                subsequent++;
                if ((element[i] & 0x80) == 0)
                {
                    break;
                }
            }

            if (subsequent > 4)
            {
                return "tag numbers past 2^28 - 1";
            }
        }

        int number = element.Length > 0 ? element[0] & 0x1F : -1;
        bool universal = element.Length > 0 && (element[0] & 0xC0) == 0;
        if (universal && number == 30 && !ours && why is null)
        {
            return "BMPString surrogate pairs";
        }

        if (universal && number is 23 or 24 && ours && why is not null)
        {
            return "times .NET's DateTimeOffset reads otherwise";
        }

        return null;
    }

    /// <summary>A random structure: a SEQUENCE of random elements of each type the library checks,
    /// nested up to a few levels, encoded by .NET's AsnWriter under DER (or CER under BER, whose
    /// long strings are constructed with an indefinite length).</summary>
    /// <param name="random">The source.</param>
    /// <param name="rules">The rules.</param>
    /// <returns>The encoding.</returns>
    private static byte[] RandomEncoding(Random random, int rules)
    {
        var writer = new AsnWriter(rules == Asn1.Der ? AsnEncodingRules.DER : AsnEncodingRules.CER);
        using (writer.PushSequence())
        {
            Elements(writer, random, 0);
        }

        return writer.Encode();

        static void Elements(AsnWriter w, Random random, int depth)
        {
            int count = random.Next(1, 6);
            for (int i = 0; i < count; i++)
            {
                switch (random.Next(depth < 3 ? 16 : 14))
                {
                    case 0: w.WriteBoolean(random.Next(2) == 0); break;
                    case 1: w.WriteInteger(new System.Numerics.BigInteger(RandomOctets(random, random.Next(1, 20)))); break;
                    case 2: w.WriteOctetString(RandomOctets(random, random.Next(0, random.Next(2) == 0 ? 40 : 1200))); break;
                    case 3:
                        {
                            int unused = random.Next(8);
                            byte[] bits = RandomOctets(random, random.Next(1, 30));
                            bits[^1] &= (byte)(0xFF << unused);
                            w.WriteBitString(bits, unused);
                            break;
                        }

                    case 4: w.WriteNull(); break;
                    case 5: w.WriteObjectIdentifier($"{random.Next(3)}.{random.Next(40)}.{random.Next()}.{random.Next(1000)}"); break;
                    case 6: w.WriteCharacterString(UniversalTagNumber.UTF8String, "réseau ✓ 𝄞 " + random.Next()); break;
                    case 7: w.WriteCharacterString(UniversalTagNumber.PrintableString, "Hello (" + random.Next() + ") ?"); break;
                    case 8: w.WriteCharacterString(UniversalTagNumber.IA5String, "user@example.com" + random.Next()); break;
                    case 9: w.WriteUtcTime(new DateTimeOffset(1950 + random.Next(100), random.Next(1, 13), random.Next(1, 29), random.Next(24), random.Next(60), random.Next(60), TimeSpan.Zero)); break;
                    case 10: w.WriteGeneralizedTime(new DateTimeOffset(random.Next(1, 9999), random.Next(1, 13), random.Next(1, 29), random.Next(24), random.Next(60), random.Next(60), random.Next(1000), TimeSpan.Zero)); break;
                    case 11: w.WriteCharacterString(UniversalTagNumber.BMPString, "Grüße " + random.Next()); break;
                    case 12: w.WriteEnumeratedValue((UniversalTagNumber)random.Next(1, 30)); break;
                    case 13:
                        w.WriteOctetString(RandomOctets(random, random.Next(0, 20)), new Asn1Tag(TagClass.ContextSpecific, random.Next(0, 1 << random.Next(1, 20))));
                        break;
                    case 14:
                        using (w.PushSequence())
                        {
                            Elements(w, random, depth + 1);
                        }

                        break;
                    default:
                        using (w.PushSetOf())
                        {
                            Elements(w, random, depth + 1);
                        }

                        break;
                }
            }
        }
    }

    /// <summary>Random octets.</summary>
    /// <param name="random">The source.</param>
    /// <param name="n">How many.</param>
    /// <returns>The octets.</returns>
    private static byte[] RandomOctets(Random random, int n)
    {
        byte[] b = new byte[n];
        random.NextBytes(b);
        return b;
    }

    /// <summary>An encoding with one random change: an octet replaced, inserted or removed, or the
    /// encoding cut short.</summary>
    /// <param name="random">The source.</param>
    /// <param name="encoding">The original.</param>
    /// <returns>The mutated copy.</returns>
    private static byte[] Mutate(Random random, byte[] encoding)
    {
        var o = encoding.ToList();
        int at = random.Next(o.Count);
        switch (random.Next(4))
        {
            case 0: o[at] = (byte)random.Next(256); break;
            case 1: o.Insert(at, (byte)random.Next(256)); break;
            case 2: o.RemoveAt(at); break;
            default: o = o.Take(at).ToList(); break;
        }

        return [.. o];
    }
}
