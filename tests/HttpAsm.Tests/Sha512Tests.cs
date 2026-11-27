using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_sha512_* and httpasm_sha384_*: SHA-512 and SHA-384 (FIPS 180-4) through the C ABI, held
/// to NIST's CAVP response files (the byte-oriented ShortMsg, LongMsg and Monte Carlo tests of
/// both) and to .NET's own SHA512 and SHA384 on random messages fed in random pieces.
/// tests/run-linux.sh runs the suite at every CPU tier, so both versions of the compression
/// answer: the scalar one (v1) and the AVX2 one (v3), whose two-block schedule takes a lone last
/// block, pairs of blocks and every mix of the two here.
/// </summary>
public sealed unsafe class Sha512Tests
{
    /// <summary>The .NET copy of httpasm_sha512_ctx has the library's size: 208 octets.</summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(208, Unsafe.SizeOf<Sha512Context>());
        Assert.Equal((uint)Unsafe.SizeOf<Sha512Context>(), Native.StructSize(12));
    }

    /// <summary>
    /// Every message of NIST's byte-oriented files: 129 short ones (0 to 128 octets, every length
    /// that pads into one block or two) and 128 long ones (to 12,800 octets), each hashed at once
    /// and fed in pieces whose sizes cross the 128-octet blocks.
    /// </summary>
    /// <param name="file">The CAVP response file.</param>
    /// <param name="sha384">Whether the file is SHA-384's (else SHA-512's).</param>
    [Theory]
    [InlineData("SHA512ShortMsg.rsp", false)]
    [InlineData("SHA512LongMsg.rsp", false)]
    [InlineData("SHA384ShortMsg.rsp", true)]
    [InlineData("SHA384LongMsg.rsp", true)]
    public void HashesNistsMessages(string file, bool sha384)
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/shabytetestvectors/" + file);
        var random = new Random(180_4);
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path))
        {
            int bits = int.Parse(record["Len"], System.Globalization.CultureInfo.InvariantCulture);
            byte[] message = Convert.FromHexString(record["Msg"])[..(bits / 8)];   // Len 0 carries "Msg = 00"
            string expected = record["MD"];
            Assert.Equal(expected, Convert.ToHexStringLower(OneShot(message, sha384)));
            Assert.Equal(expected, Convert.ToHexStringLower(InPieces(message, sha384, random)));
            count++;
        }

        Assert.Equal(file.Contains("Short", StringComparison.Ordinal) ? 129 : 128, count);
    }

    /// <summary>
    /// NIST's Monte Carlo test (SHAVS 6.4): from the seed, 100 checkpoints of 1,000 chained
    /// hashes each, every message the three digests before it: 100,000 hashes of 192 octets
    /// (SHA-512) or 144 (SHA-384), each two blocks once padded.
    /// </summary>
    /// <param name="file">The CAVP response file.</param>
    /// <param name="sha384">Whether the file is SHA-384's (else SHA-512's).</param>
    [Theory]
    [InlineData("SHA512Monte.rsp", false)]
    [InlineData("SHA384Monte.rsp", true)]
    public void PassesNistsMonteCarloTest(string file, bool sha384)
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/shabytetestvectors/" + file);
        Dictionary<string, string>[] records = Vectors.CavpRecords(path).ToArray();
        byte[] seed = Convert.FromHexString(records[0]["Seed"]);
        int size = sha384 ? 48 : 64;
        Assert.Equal(size, seed.Length);
        var checkpoints = records.Where(r => r.ContainsKey("COUNT")).ToArray();
        Assert.Equal(100, checkpoints.Length);
        foreach (Dictionary<string, string> checkpoint in checkpoints)
        {
            byte[] md0 = seed, md1 = seed, md2 = seed;
            byte[] message = new byte[3 * size];
            for (int i = 3; i <= 1002; i++)
            {
                md0.CopyTo(message, 0);
                md1.CopyTo(message, size);
                md2.CopyTo(message, 2 * size);
                (md0, md1, md2) = (md1, md2, OneShot(message, sha384));
            }

            seed = md2;
            Assert.Equal(checkpoint["MD"], Convert.ToHexStringLower(seed));
        }
    }

    /// <summary>
    /// Random messages, every length to 1,100 octets (one to nine blocks with the padding: lone
    /// and paired blocks for v3, the padding in one block or two) and some long ones, each fed in
    /// random pieces (empty ones included), equal to .NET's SHA512 or SHA384 of the same octets.
    /// </summary>
    /// <param name="sha384">SHA-384 (else SHA-512).</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MatchesDotNetOnRandomMessages(bool sha384)
    {
        Platform.RequireLinuxX64();
        var random = new Random(sha384 ? 384 : 512);
        for (int length = 0; length <= 1100; length++)
        {
            byte[] message = new byte[length];
            random.NextBytes(message);
            byte[] expected = sha384 ? SHA384.HashData(message) : SHA512.HashData(message);
            Assert.Equal(expected, OneShot(message, sha384));
            Assert.Equal(expected, InPieces(message, sha384, random));
        }

        foreach (int length in new[] { 4096, 65_536, (1 << 20) + 111, (1 << 20) + 112, 3 << 20 })
        {
            byte[] message = new byte[length];
            random.NextBytes(message);
            byte[] expected = sha384 ? SHA384.HashData(message) : SHA512.HashData(message);
            Assert.Equal(expected, OneShot(message, sha384));
            Assert.Equal(expected, InPieces(message, sha384, random));
        }
    }

    /// <summary>
    /// A running hash's octets are its whole state: a copy taken halfway goes on as a hash of its
    /// own (TLS hashes a transcript up to a message, then on). And a final wipes the context to
    /// zeros, since it held the message's last octets.
    /// </summary>
    /// <param name="sha384">SHA-384 (else SHA-512).</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ForksByCopyAndWipesOnFinal(bool sha384)
    {
        Platform.RequireLinuxX64();
        byte[] start = "the transcript so far, "u8.ToArray(), first = "then this"u8.ToArray();
        byte[] second = new byte[300];
        new Random(208).NextBytes(second);                  // past two blocks
        int size = sha384 ? 48 : 64;
        Sha512Context running;
        byte[] digest = new byte[size], forked = new byte[size];
        fixed (byte* s = start, f = first, t = second, d = digest, k = forked)
        {
            Init(&running, sha384);
            Native.Sha512Update(&running, s, (nuint)start.Length);
            Sha512Context copy = running;
            Native.Sha512Update(&running, f, (nuint)first.Length);
            Native.Sha512Update(&copy, t, (nuint)second.Length);
            Final(&running, d, sha384);
            Final(&copy, k, sha384);
            Assert.True(IsZero(&running) && IsZero(&copy), "final left octets of the hash in its context");
        }

        Assert.Equal(sha384 ? SHA384.HashData([.. start, .. first]) : SHA512.HashData([.. start, .. first]), digest);
        Assert.Equal(sha384 ? SHA384.HashData([.. start, .. second]) : SHA512.HashData([.. start, .. second]), forked);
    }

    /// <summary>
    /// SHA-384 is SHA-512 from another H(0), cut to 48 octets (FIPS 180-4 6.5): a SHA-384 context
    /// finished by httpasm_sha512_final gives SHA-384's digest and two more state words, never
    /// SHA-512's digest. This is the footgun httpasm.h warns of, pinned down: which final runs
    /// decides only the length.
    /// </summary>
    [Fact]
    public void SharesTheContextBetweenSha512AndSha384()
    {
        Platform.RequireLinuxX64();
        byte[] message = new byte[777];
        new Random(6).NextBytes(message);
        byte[] crossed = new byte[64];
        Sha512Context h;
        fixed (byte* m = message, d = crossed)
        {
            Native.Sha384Init(&h);
            Native.Sha512Update(&h, m, (nuint)message.Length);
            Native.Sha512Final(&h, d);
        }

        Assert.Equal(SHA384.HashData(message), crossed[..48]);
        Assert.NotEqual(SHA512.HashData(message), crossed);
    }

    /// <summary>The one-shot digest.</summary>
    /// <param name="message">The octets.</param>
    /// <param name="sha384">SHA-384 (else SHA-512).</param>
    /// <returns>Their digest: 48 or 64 octets.</returns>
    private static byte[] OneShot(byte[] message, bool sha384)
    {
        byte[] digest = new byte[sha384 ? 48 : 64];
        fixed (byte* m = message, d = digest)
        {
            if (sha384)
            {
                Native.Sha384(m, (nuint)message.Length, d);
            }
            else
            {
                Native.Sha512(m, (nuint)message.Length, d);
            }
        }

        return digest;
    }

    /// <summary>The digest through init, updates of random sizes (some empty, some past a block or two) and final.</summary>
    /// <param name="message">The octets.</param>
    /// <param name="sha384">SHA-384 (else SHA-512).</param>
    /// <param name="random">Chooses the pieces.</param>
    /// <returns>Their digest: 48 or 64 octets.</returns>
    private static byte[] InPieces(byte[] message, bool sha384, Random random)
    {
        byte[] digest = new byte[sha384 ? 48 : 64];
        Sha512Context h;
        fixed (byte* m = message, d = digest)
        {
            Init(&h, sha384);
            int at = 0;
            while (at < message.Length)
            {
                int piece = Math.Min(message.Length - at, random.Next(4) == 0 ? random.Next(0, 600) : random.Next(0, 140));
                Native.Sha512Update(&h, m + at, (nuint)piece);
                at += piece;
            }

            Final(&h, d, sha384);
        }

        return digest;
    }

    /// <summary>Starts a SHA-512 or SHA-384 hash.</summary>
    /// <param name="h">The context.</param>
    /// <param name="sha384">SHA-384 (else SHA-512).</param>
    private static void Init(Sha512Context* h, bool sha384)
    {
        if (sha384)
        {
            Native.Sha384Init(h);
        }
        else
        {
            Native.Sha512Init(h);
        }
    }

    /// <summary>Finishes a hash with the final of its own kind.</summary>
    /// <param name="h">The context; all zeros afterwards.</param>
    /// <param name="digest">Receives 48 or 64 octets.</param>
    /// <param name="sha384">SHA-384 (else SHA-512).</param>
    private static void Final(Sha512Context* h, byte* digest, bool sha384)
    {
        if (sha384)
        {
            Native.Sha384Final(h, digest);
        }
        else
        {
            Native.Sha512Final(h, digest);
        }
    }

    /// <summary>Whether every octet of a context is zero.</summary>
    /// <param name="h">The context.</param>
    /// <returns>True when all 208 are.</returns>
    private static bool IsZero(Sha512Context* h) => new ReadOnlySpan<byte>(h, sizeof(Sha512Context)).IndexOfAnyExcept((byte)0) < 0;
}
