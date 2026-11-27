using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_sha3_* and httpasm_shake*: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and
/// SHAKE256 (FIPS 202) through the C ABI, held to NIST's byte-oriented CAVP files (SHA3VS: every
/// ShortMsg, LongMsg and Monte Carlo record of the six, and SHAKE's VariableOut), to .NET's
/// SHA3_* and Shake* (the platform's OpenSSL) on random messages fed in random pieces, and to the
/// sponge's own contract: a copy forks it, a final wipes it, squeezing in pieces of any sizes
/// gives one stream. tests/run-linux.sh runs the suite at every CPU tier, so both versions of the
/// permutation answer: rorx and andn (v3) and plain rotates (v1).
/// </summary>
public sealed unsafe class Sha3Tests
{
    /// <summary>The six functions of FIPS 202 the library has.</summary>
    public enum Kind
    {
        /// <summary>SHA3-224: rate 144, a 28-octet digest.</summary>
        Sha3_224,

        /// <summary>SHA3-256: rate 136, a 32-octet digest (ML-KEM's H).</summary>
        Sha3_256,

        /// <summary>SHA3-384: rate 104, a 48-octet digest.</summary>
        Sha3_384,

        /// <summary>SHA3-512: rate 72, a 64-octet digest (ML-KEM's G).</summary>
        Sha3_512,

        /// <summary>SHAKE128: rate 168, any output (ML-KEM's matrix sampling).</summary>
        Shake128,

        /// <summary>SHAKE256: rate 136, any output (ML-KEM's PRF and J).</summary>
        Shake256,
    }

    /// <summary>
    /// The .NET copy of httpasm_sha3_ctx has the library's size (216 octets, struct size 20, the
    /// last id: 21 answers 0), and each init writes its kind's rate and suffix into a context
    /// filled with garbage, the rest zero.
    /// </summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(216, Unsafe.SizeOf<Sha3Context>());
        Assert.Equal((uint)Unsafe.SizeOf<Sha3Context>(), Native.StructSize(20));
        Assert.Equal(0u, Native.StructSize(21));
        foreach (Kind kind in Enum.GetValues<Kind>())
        {
            Sha3Context h;
            new Span<byte>(&h, sizeof(Sha3Context)).Fill(0xA5);
            Init(&h, kind);
            Assert.Equal((uint)Rate(kind), h.Rate);
            Assert.Equal(kind >= Kind.Shake128 ? 0x1F : 0x06, h.Suffix);
            Assert.Equal(0u, h.Position);
            Assert.Equal(0, h.Squeezing);
            Assert.True(new ReadOnlySpan<byte>(h.State, 200).IndexOfAnyExcept((byte)0) < 0);
            Assert.True(new ReadOnlySpan<byte>(h.Reserved, 6).IndexOfAnyExcept((byte)0) < 0);
        }
    }

    /// <summary>
    /// Every record of NIST's byte-oriented ShortMsg and LongMsg files (ShortMsg: every length
    /// from 0 to the rate, or twice the rate for SHAKE, so the padding lands at every place of a
    /// block; LongMsg: 100 longer ones), each computed at once and fed in random pieces (and, for
    /// SHAKE, squeezed in random pieces), equal to the file's digest or output.
    /// </summary>
    /// <param name="file">The CAVP response file, under cavp/sha3 or cavp/shake.</param>
    /// <param name="kind">Its function.</param>
    /// <param name="records">How many records it holds.</param>
    [Theory]
    [InlineData("SHA3_224ShortMsg.rsp", Kind.Sha3_224, 145)]
    [InlineData("SHA3_224LongMsg.rsp", Kind.Sha3_224, 100)]
    [InlineData("SHA3_256ShortMsg.rsp", Kind.Sha3_256, 137)]
    [InlineData("SHA3_256LongMsg.rsp", Kind.Sha3_256, 100)]
    [InlineData("SHA3_384ShortMsg.rsp", Kind.Sha3_384, 105)]
    [InlineData("SHA3_384LongMsg.rsp", Kind.Sha3_384, 100)]
    [InlineData("SHA3_512ShortMsg.rsp", Kind.Sha3_512, 73)]
    [InlineData("SHA3_512LongMsg.rsp", Kind.Sha3_512, 100)]
    [InlineData("SHAKE128ShortMsg.rsp", Kind.Shake128, 337)]
    [InlineData("SHAKE128LongMsg.rsp", Kind.Shake128, 100)]
    [InlineData("SHAKE256ShortMsg.rsp", Kind.Shake256, 273)]
    [InlineData("SHAKE256LongMsg.rsp", Kind.Shake256, 100)]
    public void HashesNistsMessages(string file, Kind kind, int records)
    {
        Platform.RequireLinuxX64();
        bool shake = kind >= Kind.Shake128;
        string path = Vectors.Path((shake ? "cavp/shake/" : "cavp/sha3/") + file);
        var random = new Random(202);
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path))
        {
            int bits = int.Parse(record["Len"], CultureInfo.InvariantCulture);
            byte[] message = Convert.FromHexString(record["Msg"])[..(bits / 8)];   // Len 0 carries "Msg = 00"
            string expected = record[shake ? "Output" : "MD"];
            int length = expected.Length / 2;
            Assert.Equal(expected, Convert.ToHexStringLower(OneShot(kind, message, length)));
            Assert.Equal(expected, Convert.ToHexStringLower(InPieces(kind, message, length, random)));
            count++;
        }

        Assert.Equal(records, count);
    }

    /// <summary>
    /// SHAKE's VariableOut files: fixed-length messages (16 octets for SHAKE128, 32 for SHAKE256)
    /// each with its own output length, every one from the minimum to the maximum the file sets
    /// (16 to 140 octets, 2 to 250), at once and squeezed in pieces.
    /// </summary>
    /// <param name="file">The CAVP response file.</param>
    /// <param name="kind">SHAKE128 or SHAKE256.</param>
    /// <param name="records">How many records it holds.</param>
    [Theory]
    [InlineData("SHAKE128VariableOut.rsp", Kind.Shake128, 1126)]
    [InlineData("SHAKE256VariableOut.rsp", Kind.Shake256, 1246)]
    public void SqueezesNistsVariableOutputs(string file, Kind kind, int records)
    {
        Platform.RequireLinuxX64();
        var random = new Random(1246);
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/shake/" + file)))
        {
            int bits = int.Parse(record["Outputlen"], CultureInfo.InvariantCulture);
            Assert.Equal(0, bits % 8);
            byte[] message = Convert.FromHexString(record["Msg"]);
            Assert.Equal(record["Output"], Convert.ToHexStringLower(OneShot(kind, message, bits / 8)));
            Assert.Equal(record["Output"], Convert.ToHexStringLower(InPieces(kind, message, bits / 8, random)));
            count++;
        }

        Assert.Equal(records, count);
    }

    /// <summary>
    /// SHA3VS's Monte Carlo test for the SHA-3 hashes: from the seed, 100 checkpoints of 1,000
    /// chained hashes, each message the digest before it (100,000 hashes a function).
    /// </summary>
    /// <param name="file">The CAVP response file.</param>
    /// <param name="kind">The hash.</param>
    [Theory]
    [InlineData("SHA3_224Monte.rsp", Kind.Sha3_224)]
    [InlineData("SHA3_256Monte.rsp", Kind.Sha3_256)]
    [InlineData("SHA3_384Monte.rsp", Kind.Sha3_384)]
    [InlineData("SHA3_512Monte.rsp", Kind.Sha3_512)]
    public void PassesNistsMonteCarloTest(string file, Kind kind)
    {
        Platform.RequireLinuxX64();
        Dictionary<string, string>[] records = Vectors.CavpRecords(Vectors.Path("cavp/sha3/" + file)).ToArray();
        byte[] md = Convert.FromHexString(records[0]["Seed"]);
        Assert.Equal(DigestLength(kind), md.Length);
        var checkpoints = records.Where(r => r.ContainsKey("COUNT")).ToArray();
        Assert.Equal(100, checkpoints.Length);
        foreach (Dictionary<string, string> checkpoint in checkpoints)
        {
            for (int i = 0; i < 1000; i++)
            {
                md = OneShot(kind, md, md.Length);
            }

            Assert.Equal(checkpoint["MD"], Convert.ToHexStringLower(md));
        }
    }

    /// <summary>
    /// SHA3VS's Monte Carlo test for SHAKE: each message the leftmost 128 bits of the output
    /// before it (zero-padded when that output was shorter), each output's length drawn from the
    /// previous output's rightmost 16 bits within the file's range (16 to 140 octets for SHAKE128,
    /// 2 to 250 for SHAKE256), starting at the maximum: 100 checkpoints of 1,000, each
    /// checkpoint's length and output equal to the file's.
    /// </summary>
    /// <param name="file">The CAVP response file.</param>
    /// <param name="kind">SHAKE128 or SHAKE256.</param>
    [Theory]
    [InlineData("SHAKE128Monte.rsp", Kind.Shake128)]
    [InlineData("SHAKE256Monte.rsp", Kind.Shake256)]
    public void PassesNistsShakeMonteCarloTest(string file, Kind kind)
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/shake/" + file);
        Dictionary<string, string>[] records = Vectors.CavpRecords(path).ToArray();
        int minimum = 0, maximum = 0;
        foreach (string line in File.ReadLines(path))
        {
            if (line.StartsWith("[Minimum Output Length (bits) = ", StringComparison.Ordinal))
            {
                minimum = int.Parse(line["[Minimum Output Length (bits) = ".Length..^1], CultureInfo.InvariantCulture) / 8;
            }
            else if (line.StartsWith("[Maximum Output Length (bits) = ", StringComparison.Ordinal))
            {
                maximum = int.Parse(line["[Maximum Output Length (bits) = ".Length..^1], CultureInfo.InvariantCulture) / 8;
            }
        }

        Assert.True(minimum > 0 && maximum > minimum);
        byte[] output = Convert.FromHexString(records.First(r => r.ContainsKey("Msg"))["Msg"]);
        Assert.Equal(16, output.Length);
        int length = maximum;
        var checkpoints = records.Where(r => r.ContainsKey("COUNT")).ToArray();
        Assert.Equal(100, checkpoints.Length);
        foreach (Dictionary<string, string> checkpoint in checkpoints)
        {
            int checkpointLength = 0;
            for (int i = 1; i <= 1000; i++)
            {
                byte[] message = new byte[16];
                output.AsSpan(0, Math.Min(16, output.Length)).CopyTo(message);
                output = OneShot(kind, message, length);
                if (i == 1000)
                {
                    checkpointLength = length;
                }

                int rightmost = (output[^2] << 8) | output[^1];
                length = minimum + rightmost % (maximum - minimum + 1);
            }

            Assert.Equal(checkpoint["Outputlen"], (checkpointLength * 8).ToString(CultureInfo.InvariantCulture));
            Assert.Equal(checkpoint["Output"], Convert.ToHexStringLower(output));
        }
    }

    /// <summary>
    /// Random messages, every length to 700 octets (the padding at every place of the rates'
    /// blocks, one to ten blocks) and some long ones, fed in random pieces (empty ones included),
    /// equal to .NET's SHA3_256, SHA3_384, SHA3_512, Shake128 and Shake256 (SHAKE at 1 to 600
    /// octets of output, squeezed in random pieces). .NET has no SHA3-224: NIST's files are its
    /// only outside reference.
    /// </summary>
    /// <param name="kind">The function.</param>
    [Theory]
    [InlineData(Kind.Sha3_256)]
    [InlineData(Kind.Sha3_384)]
    [InlineData(Kind.Sha3_512)]
    [InlineData(Kind.Shake128)]
    [InlineData(Kind.Shake256)]
    public void MatchesDotNetOnRandomMessages(Kind kind)
    {
        Platform.RequireLinuxX64();
        Assert.True(SHA3_256.IsSupported && Shake128.IsSupported, ".NET's SHA-3 needs OpenSSL 1.1.1 or newer");
        var random = new Random((int)kind + 202);
        foreach (int size in Enumerable.Range(0, 701).Concat([4096, 65_536, (1 << 20) + 135, (1 << 20) + 136]))
        {
            byte[] message = new byte[size];
            random.NextBytes(message);
            int length = kind >= Kind.Shake128 ? 1 + random.Next(600) : DigestLength(kind);
            byte[] expected = DotNet(kind, message, length);
            Assert.Equal(expected, OneShot(kind, message, length));
            Assert.Equal(expected, InPieces(kind, message, length, random));
        }
    }

    /// <summary>
    /// A context's octets are its whole state: a copy taken midway goes on as a hash of its own,
    /// with the same result as the original fed the same rest. A final wipes the context to zeros
    /// (it held the message's last octets); a squeeze does not (the stream may go on), and marks
    /// it squeezing.
    /// </summary>
    /// <param name="kind">The function.</param>
    [Theory]
    [InlineData(Kind.Sha3_256)]
    [InlineData(Kind.Sha3_512)]
    [InlineData(Kind.Shake128)]
    [InlineData(Kind.Shake256)]
    public void ForksByCopyAndWipesOnFinal(Kind kind)
    {
        Platform.RequireLinuxX64();
        var random = new Random(55);
        byte[] first = new byte[300], second = new byte[77];
        random.NextBytes(first);
        random.NextBytes(second);
        Sha3Context a;
        Init(&a, kind);
        fixed (byte* f = first, s = second)
        {
            Native.Sha3Update(&a, f, (nuint)first.Length);
            Sha3Context b = a;
            Native.Sha3Update(&a, s, (nuint)second.Length);
            Native.Sha3Update(&b, s, (nuint)second.Length);
            byte[] fromA = new byte[64], fromB = new byte[64];
            fixed (byte* x = fromA, y = fromB)
            {
                if (kind >= Kind.Shake128)
                {
                    Native.ShakeSqueeze(&a, x, 64);
                    Native.ShakeSqueeze(&b, y, 64);
                    Assert.Equal(1, a.Squeezing);
                    Assert.True(new ReadOnlySpan<byte>(a.State, 200).IndexOfAnyExcept((byte)0) >= 0);
                }
                else
                {
                    Native.Sha3Final(&a, x);
                    Native.Sha3Final(&b, y);
                    Assert.True(new ReadOnlySpan<byte>(&a, sizeof(Sha3Context)).IndexOfAnyExcept((byte)0) < 0);
                }
            }

            Assert.Equal(fromA, fromB);
            Assert.Equal(DotNet(kind, [.. first, .. second], kind >= Kind.Shake128 ? 64 : DigestLength(kind)), fromA[..(kind >= Kind.Shake128 ? 64 : DigestLength(kind))]);
        }
    }

    /// <summary>
    /// A SHAKE context finished by httpasm_sha3_final gives its stream's first (200 - rate) / 2
    /// octets (SHAKE128's 16, SHAKE256's 32), as the header says, and is wiped.
    /// </summary>
    /// <param name="kind">SHAKE128 or SHAKE256.</param>
    /// <param name="octets">The octets the final writes.</param>
    [Theory]
    [InlineData(Kind.Shake128, 16)]
    [InlineData(Kind.Shake256, 32)]
    public void FinishesAShakeWithItsStreamsFirstOctets(Kind kind, int octets)
    {
        Platform.RequireLinuxX64();
        byte[] message = "abc"u8.ToArray();
        Sha3Context h;
        Init(&h, kind);
        byte[] digest = new byte[64];
        digest.AsSpan().Fill(0xEE);
        fixed (byte* m = message, d = digest)
        {
            Native.Sha3Update(&h, m, (nuint)message.Length);
            Native.Sha3Final(&h, d);
        }

        Assert.Equal(DotNet(kind, message, octets), digest[..octets]);
        Assert.True(digest[octets..].All(o => o == 0xEE));
        Assert.True(new ReadOnlySpan<byte>(&h, sizeof(Sha3Context)).IndexOfAnyExcept((byte)0) < 0);
    }

    /// <summary>The rate of a kind, in octets.</summary>
    /// <param name="kind">The function.</param>
    /// <returns>144, 136, 104, 72, 168 or 136.</returns>
    private static int Rate(Kind kind) => kind switch
    {
        Kind.Sha3_224 => 144,
        Kind.Sha3_256 => 136,
        Kind.Sha3_384 => 104,
        Kind.Sha3_512 => 72,
        Kind.Shake128 => 168,
        _ => 136,
    };

    /// <summary>A SHA-3 hash's digest length: (200 - rate) / 2.</summary>
    /// <param name="kind">The function.</param>
    /// <returns>28, 32, 48 or 64.</returns>
    private static int DigestLength(Kind kind) => (200 - Rate(kind)) / 2;

    /// <summary>The kind's init.</summary>
    /// <param name="h">The context.</param>
    /// <param name="kind">The function.</param>
    private static void Init(Sha3Context* h, Kind kind)
    {
        switch (kind)
        {
            case Kind.Sha3_224: Native.Sha3_224Init(h); break;
            case Kind.Sha3_256: Native.Sha3_256Init(h); break;
            case Kind.Sha3_384: Native.Sha3_384Init(h); break;
            case Kind.Sha3_512: Native.Sha3_512Init(h); break;
            case Kind.Shake128: Native.Shake128Init(h); break;
            default: Native.Shake256Init(h); break;
        }
    }

    /// <summary>The one-shot function (the output pre-filled with 0xEE and checked untouched past it).</summary>
    /// <param name="kind">The function.</param>
    /// <param name="message">The message.</param>
    /// <param name="length">The output's length (a SHA-3 hash's digest length).</param>
    /// <returns>The output.</returns>
    private static byte[] OneShot(Kind kind, byte[] message, int length)
    {
        byte[] output = new byte[length + 16];
        output.AsSpan().Fill(0xEE);
        fixed (byte* m = message, o = output)
        {
            switch (kind)
            {
                case Kind.Sha3_224: Native.Sha3_224(m, (nuint)message.Length, o); break;
                case Kind.Sha3_256: Native.Sha3_256(m, (nuint)message.Length, o); break;
                case Kind.Sha3_384: Native.Sha3_384(m, (nuint)message.Length, o); break;
                case Kind.Sha3_512: Native.Sha3_512(m, (nuint)message.Length, o); break;
                case Kind.Shake128: Native.Shake128(m, (nuint)message.Length, o, (nuint)length); break;
                default: Native.Shake256(m, (nuint)message.Length, o, (nuint)length); break;
            }
        }

        Assert.True(output[length..].All(x => x == 0xEE), "wrote past its output");
        return output[..length];
    }

    /// <summary>The running form: random pieces fed (empty ones too), then the final, or for SHAKE
    /// random pieces squeezed.</summary>
    /// <param name="kind">The function.</param>
    /// <param name="message">The message.</param>
    /// <param name="length">The output's length.</param>
    /// <param name="random">Where the piece sizes come from.</param>
    /// <returns>The output.</returns>
    private static byte[] InPieces(Kind kind, byte[] message, int length, Random random)
    {
        Sha3Context h;
        Init(&h, kind);
        byte[] output = new byte[length];
        fixed (byte* m = message, o = output)
        {
            int at = 0;
            while (at < message.Length)
            {
                int piece = Math.Min(message.Length - at, random.Next(4) == 0 ? 0 : random.Next(1, 400));
                Native.Sha3Update(&h, m + at, (nuint)piece);
                at += piece;
            }

            Native.Sha3Update(&h, m, 0);
            if (kind < Kind.Shake128)
            {
                Native.Sha3Final(&h, o);
            }
            else
            {
                int got = 0;
                while (got < length)
                {
                    int piece = Math.Min(length - got, random.Next(4) == 0 ? 0 : random.Next(1, 300));
                    Native.ShakeSqueeze(&h, o + got, (nuint)piece);
                    got += piece;
                }
            }
        }

        return output;
    }

    /// <summary>.NET's function of the same kind (no SHA3-224: .NET has none).</summary>
    /// <param name="kind">The function.</param>
    /// <param name="message">The message.</param>
    /// <param name="length">The output's length (SHAKE's; a hash's is its own).</param>
    /// <returns>The digest or output.</returns>
    /// <exception cref="NotSupportedException">SHA3-224, which .NET does not implement (NIST's
    /// files are its outside reference).</exception>
    private static byte[] DotNet(Kind kind, byte[] message, int length) => kind switch
    {
        Kind.Sha3_224 => throw new NotSupportedException(".NET has no SHA3-224: the CAVP files cover it"),
        Kind.Sha3_256 => SHA3_256.HashData(message),
        Kind.Sha3_384 => SHA3_384.HashData(message),
        Kind.Sha3_512 => SHA3_512.HashData(message),
        Kind.Shake128 => Shake128.HashData(message, length),
        _ => Shake256.HashData(message, length),
    };
}
