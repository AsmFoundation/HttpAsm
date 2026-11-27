using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_sha256_*: SHA-256 (FIPS 180-4) through the C ABI, held to NIST's CAVP response files
/// (the byte-oriented ShortMsg, LongMsg and Monte Carlo tests) and to .NET's own SHA256 on
/// random messages fed in random pieces. tests/run-linux.sh runs the suite at every CPU tier,
/// so both versions of the compression answer: the scalar one (v1) and the SHA extensions'.
/// </summary>
public sealed unsafe class Sha256Tests
{
    /// <summary>The .NET copy of httpasm_sha256_ctx has the library's size: 112 octets.</summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(112, Unsafe.SizeOf<Sha256Context>());
        Assert.Equal((uint)Unsafe.SizeOf<Sha256Context>(), Native.StructSize(10));
    }

    /// <summary>
    /// Every message of NIST's byte-oriented SHA-256 files: 65 short ones (0 to 64 octets, every
    /// length that pads into one block or two) and 64 long ones (to 6,400 octets), each hashed at
    /// once and fed in pieces whose sizes cross the 64-octet blocks.
    /// </summary>
    /// <param name="file">The CAVP response file.</param>
    [Theory]
    [InlineData("SHA256ShortMsg.rsp")]
    [InlineData("SHA256LongMsg.rsp")]
    public void HashesNistsMessages(string file)
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
            Assert.Equal(expected, Convert.ToHexStringLower(OneShot(message)));
            Assert.Equal(expected, Convert.ToHexStringLower(InPieces(message, random)));
            count++;
        }

        Assert.Equal(file.Contains("Short", StringComparison.Ordinal) ? 65 : 64, count);
    }

    /// <summary>
    /// NIST's Monte Carlo test (SHAVS 6.4): from the seed, 100 checkpoints of 1,000 chained
    /// hashes each, every message the three digests before it: 100,000 hashes of 96 octets.
    /// </summary>
    [Fact]
    public void PassesNistsMonteCarloTest()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/shabytetestvectors/SHA256Monte.rsp");
        Dictionary<string, string>[] records = Vectors.CavpRecords(path).ToArray();
        byte[] seed = Convert.FromHexString(records[0]["Seed"]);
        var checkpoints = records.Where(r => r.ContainsKey("COUNT")).ToArray();
        Assert.Equal(100, checkpoints.Length);
        foreach (Dictionary<string, string> checkpoint in checkpoints)
        {
            byte[] md0 = seed, md1 = seed, md2 = seed;
            byte[] message = new byte[96];
            for (int i = 3; i <= 1002; i++)
            {
                md0.CopyTo(message, 0);
                md1.CopyTo(message, 32);
                md2.CopyTo(message, 64);
                (md0, md1, md2) = (md1, md2, OneShot(message));
            }

            seed = md2;
            Assert.Equal(checkpoint["MD"], Convert.ToHexStringLower(seed));
        }
    }

    /// <summary>
    /// Random messages, every length to 1,000 octets and some long ones, each fed in random
    /// pieces (empty ones included), equal to .NET's SHA256 of the same octets.
    /// </summary>
    [Fact]
    public void MatchesDotNetOnRandomMessages()
    {
        Platform.RequireLinuxX64();
        var random = new Random(256);
        for (int length = 0; length <= 1000; length++)
        {
            byte[] message = new byte[length];
            random.NextBytes(message);
            byte[] expected = SHA256.HashData(message);
            Assert.Equal(expected, OneShot(message));
            Assert.Equal(expected, InPieces(message, random));
        }

        foreach (int length in new[] { 4096, 65_536, 1 << 20, (1 << 20) + 55 })
        {
            byte[] message = new byte[length];
            random.NextBytes(message);
            byte[] expected = SHA256.HashData(message);
            Assert.Equal(expected, OneShot(message));
            Assert.Equal(expected, InPieces(message, random));
        }
    }

    /// <summary>
    /// A running hash's octets are its whole state: a copy taken halfway goes on as a hash of its
    /// own (TLS hashes a transcript up to a message, then on). And final wipes the context to
    /// zeros, since it held the message's last octets.
    /// </summary>
    [Fact]
    public void ForksByCopyAndWipesOnFinal()
    {
        Platform.RequireLinuxX64();
        byte[] start = "the transcript so far, "u8.ToArray(), first = "then this"u8.ToArray(), second = "or that, longer than a block: ................................................"u8.ToArray();
        Sha256Context running;
        byte[] digest = new byte[32], forked = new byte[32];
        fixed (byte* s = start, f = first, t = second, d = digest, k = forked)
        {
            Native.Sha256Init(&running);
            Native.Sha256Update(&running, s, (nuint)start.Length);
            Sha256Context copy = running;
            Native.Sha256Update(&running, f, (nuint)first.Length);
            Native.Sha256Update(&copy, t, (nuint)second.Length);
            Native.Sha256Final(&running, d);
            Native.Sha256Final(&copy, k);
            Assert.True(IsZero(&running) && IsZero(&copy), "final left octets of the hash in its context");
        }

        Assert.Equal(SHA256.HashData([.. start, .. first]), digest);
        Assert.Equal(SHA256.HashData([.. start, .. second]), forked);
    }

    /// <summary>The one-shot digest.</summary>
    /// <param name="message">The octets.</param>
    /// <returns>Their SHA-256 digest.</returns>
    private static byte[] OneShot(byte[] message)
    {
        byte[] digest = new byte[32];
        fixed (byte* m = message, d = digest)
        {
            Native.Sha256(m, (nuint)message.Length, d);
        }

        return digest;
    }

    /// <summary>The digest through init, updates of random sizes (some empty, some past a block) and final.</summary>
    /// <param name="message">The octets.</param>
    /// <param name="random">Chooses the pieces.</param>
    /// <returns>Their SHA-256 digest.</returns>
    private static byte[] InPieces(byte[] message, Random random)
    {
        byte[] digest = new byte[32];
        Sha256Context h;
        fixed (byte* m = message, d = digest)
        {
            Native.Sha256Init(&h);
            int at = 0;
            while (at < message.Length)
            {
                int piece = Math.Min(message.Length - at, random.Next(4) == 0 ? random.Next(0, 300) : random.Next(0, 70));
                Native.Sha256Update(&h, m + at, (nuint)piece);
                at += piece;
            }

            Native.Sha256Final(&h, d);
        }

        return digest;
    }

    /// <summary>Whether every octet of a context is zero.</summary>
    /// <param name="h">The context.</param>
    /// <returns>True when all 112 are.</returns>
    private static bool IsZero(Sha256Context* h) => new ReadOnlySpan<byte>(h, sizeof(Sha256Context)).IndexOfAnyExcept((byte)0) < 0;
}
