using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// PEM (RFC 7468) through httpasm_pem_read (asn1/pem.asm): RFC 7468's and RFC 8410's own examples,
/// every rule of the boundaries, the label and the lax base64 text, the decoding's quanta, pads
/// and pad bits, files of several blocks, the -2 answer and its untouched buffer, and a
/// differential test against .NET's PemEncoding, an independent reader of the same RFC. Every
/// text is read from the end of a page before a guard page, so a read past it ends the run.
/// </summary>
/// <param name="output">Receives the differential test's counts.</param>
public sealed unsafe class PemTests(ITestOutputHelper output)
{
    /// <summary>What one call returned.</summary>
    /// <param name="Status">0, 1, -1 or -2.</param>
    /// <param name="Label">The label (on 0).</param>
    /// <param name="Der">The decoded octets (on 0).</param>
    /// <param name="DerLength">The block's der_length (on 0 and -2).</param>
    /// <param name="End">The block's end (on 0).</param>
    private readonly record struct Decoded(int Status, string Label, byte[] Der, long DerLength, long End);

    /// <summary>Reads the first block of a text placed at the end of a page before a guard page
    /// (larger texts: native memory), into a buffer of the given room (default: plenty).</summary>
    /// <param name="text">The PEM text.</param>
    /// <param name="capacity">The room for the octets; -1 for the text's length.</param>
    /// <returns>The call's results.</returns>
    private static Decoded Read(byte[] text, int capacity = -1)
    {
        int room = capacity < 0 ? text.Length + 1 : capacity;
        byte[] der = new byte[Math.Max(room, 1)];
        if (text.Length > GuardedBuffer.PageSize)
        {
            byte* block = (byte*)NativeMemory.Alloc((nuint)text.Length);
            try
            {
                text.CopyTo(new Span<byte>(block, text.Length));
                return Run(block);
            }
            finally
            {
                NativeMemory.Free(block);
            }
        }

        using var guard = new GuardedBuffer();
        return Run(guard.AtPageEnd(text));

        Decoded Run(byte* at)
        {
            PemBlock b;
            int status;
            fixed (byte* d = der)
            {
                status = Native.PemRead(&b, at, (nuint)text.Length, d, (nuint)room);
            }

            if (status != 0)
            {
                return new Decoded(status, "", [], status == -2 ? (long)b.DerLength : 0, 0);
            }

            string label = Encoding.ASCII.GetString(b.Label, (int)b.LabelLength);
            Assert.True(b.Label >= at && b.Label + b.LabelLength <= at + text.Length, "the label points outside the text");
            return new Decoded(0, label, der[..(int)b.DerLength], (long)b.DerLength, (long)b.End);
        }
    }

    /// <summary>The same for a string, one octet a character (Latin-1: octets above 0x7F too).</summary>
    /// <param name="text">The PEM text.</param>
    /// <returns>The call's results.</returns>
    private static Decoded Read(string text) => Read(Encoding.Latin1.GetBytes(text));

    /// <summary>
    /// The .NET copy of httpasm_pem has the library's size, 32 octets, under struct id 24 (the
    /// end of the registry is checked by the newest structure's tests: KeyTests).
    /// </summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(32, sizeof(PemBlock));
        Assert.Equal((uint)sizeof(PemBlock), Native.StructSize(24));
    }

    /// <summary>RFC 7468's figure 6 (a certificate), as it prints it.</summary>
    private const string Figure6 =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G\n" +
        "A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y\n" +
        "aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0\n" +
        "ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw\n" +
        "CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy\n" +
        "dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu\n" +
        "dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB\n" +
        "BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X\n" +
        "uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud\n" +
        "DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG\n" +
        "SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA\n" +
        "l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=\n" +
        "-----END CERTIFICATE-----\n";

    /// <summary>
    /// RFC 7468's examples: figure 6's certificate; figure 7's, after explanatory text (5.2: tools
    /// print the certificate's fields before it); figure 15's public key; and RFC 8410's Ed25519
    /// private key (10.3). Each decodes to the base64 of its body, under its label, and the DER of
    /// the certificate reads as one SEQUENCE spanning it.
    /// </summary>
    [Fact]
    [Requirement("RFC7468-2-p1#1", "RFC7468-5.1-p1")]
    public void DecodesTheRfcsExamples()
    {
        Platform.RequireLinuxX64();
        Decoded d = Read(Figure6);
        Assert.Equal(0, d.Status);
        Assert.Equal("CERTIFICATE", d.Label);
        Assert.Equal(Body(Figure6), d.Der);
        Assert.Equal(Figure6.Length - 1, d.End);
        fixed (byte* p = d.Der)
        {
            Asn1Element e;
            Assert.Equal(0, Native.Asn1Read(&e, p, (nuint)d.Der.Length, Asn1.Der));
            Assert.Equal((Asn1.Sequence, (nuint)d.Der.Length), (e.Tag, e.Length));
        }

        string figure7 =
            "Subject: CN=Atlantis\nIssuer: CN=Atlantis\nValidity: from 7/9/2012 3:10:38 AM UTC to 7/9/2013 3:10:37 AM UTC\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBmTCCAUegAwIBAgIBKjAJBgUrDgMCHQUAMBMxETAPBgNVBAMTCEF0bGFudGlz\n" +
            "MB4XDTEyMDcwOTAzMTAzOFoXDTEzMDcwOTAzMTAzN1owEzERMA8GA1UEAxMIQXRs\n" +
            "YW50aXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAu+BXo+miabDIHHx+yquqzqNh\n" +
            "Ryn/XtkJIIHVcYtHvIX+S1x5ErgMoHehycpoxbErZmVR4GCq1S2diNmRFZCRtQID\n" +
            "AQABo4GJMIGGMAwGA1UdEwEB/wQCMAAwIAYDVR0EAQH/BBYwFDAOMAwGCisGAQQB\n" +
            "gjcCARUDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzA1BgNVHQEE\n" +
            "LjAsgBA0jOnSSuIHYmnVryHAdywMoRUwEzERMA8GA1UEAxMIQXRsYW50aXOCASow\n" +
            "CQYFKw4DAh0FAANBAKi6HRBaNEL5R0n56nvfclQNaXiDT174uf+lojzA4lhVInc0\n" +
            "ILwpnZ1izL4MlI9eCSHhVQBHEp2uQdXJB+d5Byg=\n" +
            "-----END CERTIFICATE-----\n";
        d = Read(figure7);
        Assert.Equal((0, "CERTIFICATE"), (d.Status, d.Label));
        Assert.Equal(Body(figure7), d.Der);

        string figure15 =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn1LlwLN/KBYQRVH6HfIMTzfEqJOVztLe\n" +
            "kLchp2hi78cCaMY81FBlYs8J9l7krc+M4aBeCGYFjba+hiXttJWPL7ydlE+5UG4U\n" +
            "Nkn3Eos8EiZByi9DVsyfy9eejh+8AXgp\n" +
            "-----END PUBLIC KEY-----\n";
        d = Read(figure15);
        Assert.Equal((0, "PUBLIC KEY"), (d.Status, d.Label));
        Assert.Equal(Body(figure15), d.Der);

        string ed25519 = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
        d = Read(ed25519);
        Assert.Equal((0, "PRIVATE KEY"), (d.Status, d.Label));
        Assert.Equal("302E020100300506032B657004220420D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842", Convert.ToHexString(d.Der));
    }

    /// <summary>The base64 between a text's first boundaries, decoded by .NET.</summary>
    /// <param name="text">The PEM text.</param>
    /// <returns>The octets.</returns>
    private static byte[] Body(string text)
    {
        int begin = text.IndexOf("-----BEGIN ", StringComparison.Ordinal);
        int start = text.IndexOf("-----", begin + 11, StringComparison.Ordinal) + 5;
        int end = text.IndexOf("-----END ", start, StringComparison.Ordinal);
        return Convert.FromBase64String(text[start..end]);
    }

    /// <summary>
    /// RFC 8410's second example ends with six hyphen-minuses ("-----END PRIVATE KEY------", an
    /// error in the RFC): exactly five on either side (RFC 7468 2), so the block is refused, and
    /// with five it reads.
    /// </summary>
    [Fact]
    [Requirement("RFC7468-2-p4#1")]
    public void RefusesRfc8410sSixHyphenMinuses()
    {
        Platform.RequireLinuxX64();
        const string body = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n" +
                            "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n" +
                            "Z9w7lshQhqowtrbLDFw4rXAxZuE=\n";
        Assert.Equal(-1, Read("-----BEGIN PRIVATE KEY-----\n" + body + "-----END PRIVATE KEY------\n").Status);
        Decoded d = Read("-----BEGIN PRIVATE KEY-----\n" + body + "-----END PRIVATE KEY-----\n");
        Assert.Equal(0, d.Status);
        Assert.Equal(116, d.Der.Length);
    }

    /// <summary>
    /// Every length of octets from 0 to 300, random each, written by .NET's PemEncoding in the
    /// strict form (64-character lines, LF) and in lax variants: CRLF and CR line ends (2: parsers
    /// MUST handle different newline conventions), other line widths (2: MAY), whitespace of every
    /// kind anywhere in the base64 (Figure 2), empty space after the BEGIN line (2), and the pads
    /// left out; each decodes to the octets.
    /// </summary>
    [Fact]
    [Requirement("RFC7468-2-p1#3", "RFC7468-2-p5", "RFC7468-2-p8#3", "RFC7468-2-p1#2")]
    public void DecodesEveryLengthInEveryLayout()
    {
        Platform.RequireLinuxX64();
        var random = new Random(7468);
        char[] spaces = [' ', '\t', '\r', '\n', '\v', '\f'];
        for (int n = 0; n <= 300; n++)
        {
            byte[] data = new byte[n];
            random.NextBytes(data);
            string strict = new(PemEncoding.Write("TEST", data));
            string b64 = Convert.ToBase64String(data);
            string[] variants =
            [
                strict,
                strict.Replace("\n", "\r\n"),
                strict.Replace("\n", "\r"),
                "-----BEGIN TEST-----\n" + string.Join("\n", Chunks(b64, 1 + random.Next(100))) + "\n-----END TEST-----",
                "-----BEGIN TEST-----" + b64 + "-----END TEST-----",
                "-----BEGIN TEST-----\n \t\n\n" + b64 + "\n-----END TEST-----\n",
                "-----BEGIN TEST-----\n" + Scatter(b64, random, spaces) + "-----END TEST-----",
                "-----BEGIN TEST-----\n" + b64.TrimEnd('=') + "\n-----END TEST-----\n",
                "-----BEGIN TEST-----\n" + b64.Replace("=", " = ") + "\t\n-----END TEST-----\n",
            ];
            foreach (string v in variants)
            {
                Decoded d = Read(v);
                Assert.True(d.Status == 0, $"{n} octets: {d.Status} for {v}");
                Assert.Equal("TEST", d.Label);
                Assert.Equal(data, d.Der);
            }
        }

        static IEnumerable<string> Chunks(string s, int width)
        {
            for (int i = 0; i < s.Length; i += width)
            {
                yield return s.Substring(i, Math.Min(width, s.Length - i));
            }
        }

        static string Scatter(string s, Random random, char[] spaces)
        {
            var o = new StringBuilder();
            foreach (char c in s)
            {
                while (random.Next(4) == 0)
                {
                    o.Append(spaces[random.Next(spaces.Length)]);
                }

                o.Append(c);
            }

            return o.Append('\n').ToString();
        }
    }

    /// <summary>
    /// Malformed blocks are refused (-1), never misread (2: parsers MUST handle non-conforming data
    /// gracefully): hyphen-minuses other than five, labels breaking the ABNF (spaces or hyphens
    /// doubled or at an end, characters outside it), a mismatched END label (2 lets a parser
    /// disregard the mismatch: this one refuses it), no END line, a character that is neither
    /// base64 nor whitespace (2 says SHOULD ignore it: this parser refuses it, as OpenSSL, Go and
    /// .NET do), base64 after a pad, three pads or the wrong number, a lone final character, and a
    /// final quantum whose pad bits are not zero.
    /// </summary>
    /// <param name="text">The text, "\n" for line ends.</param>
    [Theory]
    [InlineData("-----BEGIN TEST------\nAAAA\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST----\nAAAA\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END TEST----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END TEST------\n")]
    [InlineData("-----BEGIN TE  ST-----\nAAAA\n-----END TE  ST-----\n")]
    [InlineData("-----BEGIN  TEST-----\nAAAA\n-----END  TEST-----\n")]
    [InlineData("-----BEGIN TEST -----\nAAAA\n-----END TEST -----\n")]
    [InlineData("-----BEGIN TE--ST-----\nAAAA\n-----END TE--ST-----\n")]
    [InlineData("-----BEGIN -TEST-----\nAAAA\n-----END -TEST-----\n")]
    [InlineData("-----BEGIN TE -ST-----\nAAAA\n-----END TE -ST-----\n")]
    [InlineData("-----BEGIN TE\u0001ST-----\nAAAA\n-----END TE\u0001ST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END OTHER-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END TES-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n")]
    [InlineData("-----BEGIN TEST-----")]
    [InlineData("-----BEGIN TEST")]
    [InlineData("-----BEGIN TEST------END TEST-----")]
    [InlineData("-----BEGIN TEST-----\nAA*A\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAA.A\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAA\u0000A\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAA=A\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAA===\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAA==\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAA=\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA=\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nA\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAAA\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAB==\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAB=\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAB\nAA-A\n-----END TEST-----\n")]
    [InlineData("-----BEGIN TE\u007FST-----\nAAAA\n-----END TE\u007FST-----\n")]
    [InlineData("-----BEGIN TEÀST-----\nAAAA\n-----END TEÀST-----\n")]
    [InlineData("-----BEGIN TE \u007FST-----\nAAAA\n-----END TE \u007FST-----\n")]
    [InlineData("-----BEGIN TE \u0001ST-----\nAAAA\n-----END TE \u0001ST-----\n")]
    [InlineData("-----BEGIN TE -\n")]
    [InlineData("-----BEGIN TEST------")]
    [InlineData("-----BEGIN TEST----------END-TEST-----")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END TEST------ and some text after it\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END TEST----------BEGIX TEST-----\n")]
    [InlineData("-----BEGIN TEST-----\nAAAA\n-----END TEST----------BEGINxTEST-----\n")]
    [Requirement("RFC7468-2-p4#1", "RFC7468-2-p2#2")]
    public void RefusesMalformedBlocks(string text)
    {
        Platform.RequireLinuxX64();
        Assert.Equal(-1, Read(text).Status);
    }

    /// <summary>Labels the ABNF allows: empty, one character, single spaces and hyphen-minuses
    /// between characters, every printable character but "-" itself.</summary>
    /// <param name="label">The label.</param>
    [Theory]
    [InlineData("")]
    [InlineData("X")]
    [InlineData("RSA PRIVATE KEY")]
    [InlineData("X509 CRL")]
    [InlineData("A-B C-D")]
    [InlineData("!\"#$%&'()*+,./0123456789:;<=>?@[\\]^_`{|}~")]
    public void ReadsEveryLabelTheGrammarAllows(string label)
    {
        Platform.RequireLinuxX64();
        Decoded d = Read($"-----BEGIN {label}-----\nAQID\n-----END {label}-----\n");
        Assert.Equal((0, label), (d.Status, d.Label));
        Assert.Equal([1, 2, 3], d.Der);
    }

    /// <summary>
    /// A BEGIN line must start the text or a line: one inside a line of text is not a boundary,
    /// so a text holding only such a line has no block (1). A text with no BEGIN line at all,
    /// or an empty one, has none either.
    /// </summary>
    /// <param name="text">The text.</param>
    [Theory]
    [InlineData("see -----BEGIN TEST-----\nAAAA\n-----END TEST-----\n")]
    [InlineData("no block here\n")]
    [InlineData("")]
    [InlineData("-----BEGIN")]
    [InlineData("x-----BEGIN TEST-----\nAAAA\n-----END TEST-----\n")]
    public void FindsNoBlockWhereNoneStartsALine(string text)
    {
        Platform.RequireLinuxX64();
        Assert.Equal(1, Read(text).Status);
    }

    /// <summary>
    /// Files may hold several blocks (2: MAY), with text between them: each read starts where the
    /// last block ended (its end), and the last one is followed by 1.
    /// </summary>
    [Fact]
    [Requirement("RFC7468-2-p9", "RFC7468-2-p1#1")]
    public void ReadsEveryBlockOfAFile()
    {
        Platform.RequireLinuxX64();
        string file = "# a chain\n" + Figure6 + "between the two\r\n" +
                      "-----BEGIN CERTIFICATE-----\r\nAQIDBA==\r\n-----END CERTIFICATE-----\r\n" +
                      "-----BEGIN PRIVATE KEY-----\nBQYH\n-----END PRIVATE KEY-----" + "\ntrailing text\n";
        byte[] all = Encoding.ASCII.GetBytes(file);
        var labels = new List<string>();
        var octets = new List<byte[]>();
        int at = 0;
        while (true)
        {
            Decoded d = Read(all[at..]);
            if (d.Status == 1)
            {
                break;
            }

            Assert.Equal(0, d.Status);
            labels.Add(d.Label);
            octets.Add(d.Der);
            at += (int)d.End;
        }

        Assert.Equal(["CERTIFICATE", "CERTIFICATE", "PRIVATE KEY"], labels);
        Assert.Equal(Body(Figure6), octets[0]);
        Assert.Equal([1, 2, 3, 4], octets[1]);
        Assert.Equal([5, 6, 7], octets[2]);
    }

    /// <summary>
    /// A block's END line directly followed by the next BEGIN line, with no line break between:
    /// the ten hyphen-minuses are two boundaries' fives, so the first block reads, and the second
    /// reads too when the next call starts where the first ended (its BEGIN line then starts the
    /// text given); so does an empty base64 text whose END line follows its BEGIN line at once
    /// (RFC 7468's Figure 2 needs no line break).
    /// </summary>
    [Fact]
    public void ReadsBoundariesThatTouch()
    {
        Platform.RequireLinuxX64();
        string text = "-----BEGIN A-----\nAQID\n-----END A----------BEGIN B-----\nBAUG\n-----END B-----\n";
        Decoded d = Read(text);
        Assert.Equal((0, "A"), (d.Status, d.Label));
        Assert.Equal([1, 2, 3], d.Der);
        Decoded next = Read(Encoding.ASCII.GetBytes(text)[(int)d.End..]);
        Assert.Equal((0, "B"), (next.Status, next.Label));
        Assert.Equal([4, 5, 6], next.Der);
        d = Read("-----BEGIN A----------END A-----");
        Assert.Equal((0, "A", 0), (d.Status, d.Label, d.Der.Length));
    }

    /// <summary>
    /// When the octets do not fit, the answer is -2 with the room they need, and the buffer is
    /// not touched (the block was checked first, so a caller can retry with that room); with that
    /// room exactly it reads.
    /// </summary>
    [Fact]
    public void AnswersTooSmallWithTheRoomNeeded()
    {
        Platform.RequireLinuxX64();
        byte[] text = Encoding.ASCII.GetBytes(Figure6);
        int needed = Body(Figure6).Length;
        Decoded d = Read(text, needed - 1);
        Assert.Equal((-2, (long)needed), (d.Status, d.DerLength));

        byte[] der = new byte[needed - 1];
        Array.Fill(der, (byte)0xEE);
        fixed (byte* t = text)
        fixed (byte* p = der)
        {
            PemBlock b;
            Assert.Equal(-2, Native.PemRead(&b, t, (nuint)text.Length, p, (nuint)der.Length));
        }

        Assert.All(der, x => Assert.Equal(0xEE, x));
        Assert.Equal(0, Read(text, needed).Status);
        Assert.Equal(-2, Read(Encoding.ASCII.GetBytes("-----BEGIN X-----\nAA==\n-----END X-----"), 0).Status);
        Assert.Equal(0, Read(Encoding.ASCII.GetBytes("-----BEGIN X-----\n\n-----END X-----"), 0).Status);
    }

    /// <summary>Every prefix of a block is refused or finds no block, without reading past it:
    /// each is placed at the end of a page before a guard page.</summary>
    [Fact]
    public void NeverReadsPastTheText()
    {
        Platform.RequireLinuxX64();
        byte[] text = Encoding.ASCII.GetBytes("intro\n" + Figure6.TrimEnd('\n'));
        Assert.Equal(0, Read(text).Status);
        for (int n = 0; n < text.Length; n++)
        {
            Assert.NotEqual(0, Read(text[..n]).Status);
        }
    }

    /// <summary>
    /// The differential test: .NET's PemEncoding.TryFind reads RFC 7468's lax form too. Random
    /// texts (blocks .NET writes, then mutated: a character changed, inserted or removed, a line
    /// end changed, the text cut) are read by both; they must agree on whether a block is there,
    /// its label and its octets, but for the classes where the two read the RFC differently on
    /// purpose, each counted and printed: a final quantum without its pads (RFC 7468's ABNF allows
    /// it; .NET's base64 does not), VT and FF in the base64 (RFC 7468's W has them; .NET's reader
    /// does not), pad bits that are not zero (should .NET take them: both refuse them today), a
    /// BEGIN line preceded by whitespace in the same line (.NET takes it; this parser wants a
    /// line's start), and a sixth hyphen-minus after the END line's five (RFC 7468 2 says exactly
    /// five; .NET stops reading at the fifth).
    /// </summary>
    [Fact]
    public void AgreesWithDotNetsPemEncoding()
    {
        Platform.RequireLinuxX64();
        var random = new Random(20261128);
        var triaged = new SortedDictionary<string, int>(StringComparer.Ordinal);
        int compared = 0, agreedOnBlocks = 0;
        for (int round = 0; round < 4000; round++)
        {
            byte[] data = new byte[random.Next(0, 200)];
            random.NextBytes(data);
            string text = new(PemEncoding.Write(random.Next(3) switch { 0 => "CERTIFICATE", 1 => "PRIVATE KEY", _ => "A B-C" }, data));
            if (random.Next(3) == 0)
            {
                text = "explanation\n" + text;
            }

            for (int m = 0; m < 3; m++)
            {
                string t = m == 0 ? text : Mutate(random, text);
                compared++;
                Decoded ours = Read(Encoding.Latin1.GetBytes(t));
                bool theirs = PemEncoding.TryFind(t, out PemFields fields);
                byte[]? theirData = null;
                if (theirs)
                {
                    theirData = Convert.FromBase64String(new string(t.AsSpan(fields.Base64Data)).Replace("\r", "").Replace("\n", "").Replace(" ", "").Replace("\t", "").Replace("\v", "").Replace("\f", ""));
                }

                if (ours.Status == 0 && theirs && ours.Label == t[fields.Label] && ours.Der.AsSpan().SequenceEqual(theirData))
                {
                    agreedOnBlocks++;
                    continue;
                }

                if (ours.Status != 0 && !theirs)
                {
                    continue;
                }

                string? cls = Triage(t, ours, theirs);
                Assert.True(cls is not null, $"disagreement: ours {ours.Status}, .NET {theirs} on {Escape(t)}");
                triaged[cls!] = triaged.GetValueOrDefault(cls!) + 1;
            }
        }

        output.WriteLine($"{compared:N0} texts compared, {agreedOnBlocks:N0} blocks read alike");
        foreach ((string cls, int count) in triaged)
        {
            output.WriteLine($"  triaged: {cls}: {count}");
        }

        Assert.True(agreedOnBlocks > 3000, $"only {agreedOnBlocks} blocks read alike");

        static string? Triage(string t, Decoded ours, bool theirs)
        {
            int begin = t.IndexOf("-----BEGIN ", StringComparison.Ordinal);
            if (theirs && ours.Status == 1 && begin > 0 && t[begin - 1] is ' ' or '\t' or '\v' or '\f')
            {
                return "a BEGIN line after whitespace in its line";
            }

            int end = begin < 0 ? -1 : t.IndexOf("-----END ", begin, StringComparison.Ordinal);
            if (begin >= 0 && end > begin)
            {
                int start = t.IndexOf("-----", begin + 11, StringComparison.Ordinal) + 5;
                string b64 = new(t[start..end].Where(c => !char.IsWhiteSpace(c)).ToArray());
                if (!theirs && ours.Status == 0 && b64.Length % 4 != 0 && !b64.Contains('='))
                {
                    return "a final quantum without its pads";
                }

                if (!theirs && ours.Status == 0 && t[start..end].IndexOfAny(['\v', '\f']) >= 0)
                {
                    return "VT or FF in the base64 (RFC 7468's W has them; .NET's PEM reader does not)";
                }

                if (theirs && ours.Status == -1 && PadBitsSet(b64))
                {
                    return "pad bits that are not zero";
                }
            }

            if (theirs && ours.Status == -1 && end > begin)
            {
                int dashes = t.IndexOf("-----", end + 9, StringComparison.Ordinal);
                if (dashes > 0 && dashes + 5 < t.Length && t[dashes + 5] == '-')
                {
                    return "a sixth hyphen-minus after the END line's five (RFC 7468 2: exactly five; .NET stops at five)";
                }
            }

            return null;
        }

        static bool PadBitsSet(string b64)
        {
            string s = b64.TrimEnd('=');
            if (s.Length % 4 is 0 or 1 || s.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/')))
            {
                return false;
            }

            int v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".IndexOf(s[^1]);
            return s.Length % 4 == 2 ? (v & 0xF) != 0 : (v & 0x3) != 0;
        }
    }

    /// <summary>A text with its control characters spelled out, for a failure's message.</summary>
    /// <param name="t">The text.</param>
    /// <returns>The text with CR, LF, HT, VT, FF and NUL written as escapes.</returns>
    private static string Escape(string t) =>
        t.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").Replace("\v", "\\v").Replace("\f", "\\f").Replace("\0", "\\0");

    /// <summary>A text with one random change.</summary>
    /// <param name="random">The source.</param>
    /// <param name="text">The original.</param>
    /// <returns>The mutated copy.</returns>
    private static string Mutate(Random random, string text)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=- \t\r\n\v\f*.!";
        var o = new StringBuilder(text);
        int at = random.Next(o.Length);
        switch (random.Next(5))
        {
            case 0: o[at] = alphabet[random.Next(alphabet.Length)]; break;
            case 1: o.Insert(at, alphabet[random.Next(alphabet.Length)]); break;
            case 2: o.Remove(at, 1); break;
            case 3: o.Replace("\n", "\r\n"); break;
            default: o.Length = at; break;
        }

        return o.ToString();
    }
}
