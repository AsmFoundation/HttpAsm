using System.Globalization;
using System.Numerics;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_ffdhe_size, httpasm_ffdhe_public_key and httpasm_ffdhe_shared (RFC 7919's five groups
/// for TLS 1.3's ffdhe2048 .. ffdhe8192) through the C ABI, held to BigInteger's ModPow over the
/// primes read from the pinned RFC text (specs/rfc/rfc7919.txt: Appendix A's hexadecimal p; the
/// library's own copies come from specs/ffdhe.cs, which proves them against the formula): public
/// keys 2^x mod p and shared secrets Y^x mod p for exponents of every allowed kind of length (the
/// advised minimum, a few octets over, 64 octets, p's whole size) at every group, both parties of
/// an exchange agreeing; RFC 7919 5.1's check on the peer's key at both ends of its range and
/// outside it; and the refusals (unknown groups, lengths outside the range) writing nothing.
/// tests/run-linux.sh runs the suite at every CPU tier, so both versions of the Montgomery
/// arithmetic under it answer (mulx with adcx/adox at v3, mul at v1).
/// </summary>
public sealed unsafe class FfdheTests
{
    /// <summary>The groups as TLS names them (NamedGroup 0x0100 .. 0x0104) and p's size in bits.</summary>
    private static readonly (int Group, int Bits, int MinimumOctets)[] Groups =
    {
        (0x0100, 2048, 29), (0x0101, 3072, 35), (0x0102, 4096, 41), (0x0103, 6144, 47), (0x0104, 8192, 50),
    };

    /// <summary>
    /// httpasm_ffdhe_size gives p's size in octets for each group and 0 for every other value
    /// (the codes around and between them, 0, negatives).
    /// </summary>
    [Fact]
    public void SizesEachGroupAndNothingElse()
    {
        Platform.RequireLinuxX64();
        foreach ((int group, int bits, _) in Groups)
        {
            Assert.Equal((nuint)(bits / 8), Native.FfdheSize(group));
        }

        foreach (int other in new[] { 0, 0x00FF, 0x0105, 0x01FF, 0x0200, -1, int.MinValue, 23, 29 })
        {
            Assert.Equal((nuint)0, Native.FfdheSize(other));
        }
    }

    /// <summary>
    /// Public keys and shared secrets against ModPow at every group: exponents of the advised
    /// minimum length, a few octets over it, 64 octets and p's whole size (random octets, the
    /// first sometimes zero: its leading zeros change nothing), and an exchange between two
    /// parties whose shared secrets agree; each output exactly p's size, left-padded.
    /// </summary>
    [Fact]
    public void MatchesModPowAtEveryGroup()
    {
        Platform.RequireLinuxX64();
        var random = new Random(7919);
        foreach ((int group, int bits, int minimum) in Groups)
        {
            BigInteger p = Prime(bits);
            int size = bits / 8;
            foreach (int length in new[] { minimum, minimum + 3, 64, size })
            {
                byte[] a = RandomBytes(random, length), b = RandomBytes(random, length);
                if (length == 64)
                {
                    a[0] = 0;                   // a leading zero octet: the same number as one shorter
                }

                byte[] publicA = PublicKey(group, a, size);
                byte[] publicB = PublicKey(group, b, size);
                Assert.Equal(Hex(BigInteger.ModPow(2, Unsigned(a), p), size), Convert.ToHexString(publicA));
                Assert.Equal(Hex(BigInteger.ModPow(2, Unsigned(b), p), size), Convert.ToHexString(publicB));
                (int resultA, byte[] sharedA) = Shared(group, a, publicB, size);
                (int resultB, byte[] sharedB) = Shared(group, b, publicA, size);
                Assert.Equal(0, resultA);
                Assert.Equal(0, resultB);
                Assert.Equal(Hex(BigInteger.ModPow(Unsigned(publicB), Unsigned(a), p), size), Convert.ToHexString(sharedA));
                Assert.Equal(Convert.ToHexString(sharedA), Convert.ToHexString(sharedB));
            }
        }
    }

    /// <summary>
    /// Shared secrets with peer keys drawn at random below p (not only powers of 2: the
    /// arithmetic must hold for any base the check admits) against ModPow, ffdhe2048 and
    /// ffdhe3072, 40 rounds each.
    /// </summary>
    [Fact]
    public void MatchesModPowWithRandomPeerKeys()
    {
        Platform.RequireLinuxX64();
        var random = new Random(9846);
        foreach ((int group, int bits, int minimum) in Groups.Take(2))
        {
            BigInteger p = Prime(bits);
            int size = bits / 8;
            for (int round = 0; round < 40; round++)
            {
                byte[] x = RandomBytes(random, minimum + random.Next(32));
                BigInteger y = (Unsigned(RandomBytes(random, size)) % (p - 3)) + 2;   // in [2, p - 2]
                byte[] peer = Convert.FromHexString(Hex(y, size));
                (int result, byte[] shared) = Shared(group, x, peer, size);
                Assert.Equal(0, result);
                Assert.Equal(Hex(BigInteger.ModPow(y, Unsigned(x), p), size), Convert.ToHexString(shared));
            }
        }
    }

    /// <summary>
    /// RFC 7919 5.1: the peer's key must satisfy 1 &lt; Y &lt; p - 1. 2 and p - 2 pass (and give
    /// ModPow's values); 0, 1, p - 1, p, p + 1 and all ones are refused with -1 and nothing written,
    /// at every group.
    /// </summary>
    [Fact]
    [Requirement("RFC7919-5.1-p1")]
    public void ChecksThePeersKeyRange()
    {
        Platform.RequireLinuxX64();
        foreach ((int group, int bits, int minimum) in Groups)
        {
            BigInteger p = Prime(bits);
            int size = bits / 8;
            byte[] x = RandomBytes(new Random(bits), minimum);
            foreach (BigInteger good in new[] { new BigInteger(2), p - 2 })
            {
                (int result, byte[] shared) = Shared(group, x, Convert.FromHexString(Hex(good, size)), size);
                Assert.Equal(0, result);
                Assert.Equal(Hex(BigInteger.ModPow(good, Unsigned(x), p), size), Convert.ToHexString(shared));
            }

            foreach (BigInteger bad in new[] { BigInteger.Zero, BigInteger.One, p - 1, p, p + 1, (BigInteger.One << bits) - 1 })
            {
                (int result, byte[] shared) = Shared(group, x, Convert.FromHexString(Hex(bad, size)), size);
                Assert.Equal(-1, result);
                Assert.All(shared, octet => Assert.Equal(0xA5, octet));
            }
        }
    }

    /// <summary>
    /// The refusals: an unknown group, and exponent lengths outside [the advised minimum, p's
    /// size] (0, one short of the minimum, one past the size), each -1 with nothing written, for
    /// both functions.
    /// </summary>
    [Fact]
    public void RefusesUnknownGroupsAndLengths()
    {
        Platform.RequireLinuxX64();
        byte[] x = new byte[2048];
        new Random(5).NextBytes(x);
        byte[] output = new byte[2048], peer = new byte[1024];
        peer[^1] = 2;                           // a valid peer key at every size (2)
        fixed (byte* o = output, k = x, y = peer)
        {
            foreach (int other in new[] { 0, 0x00FF, 0x0105, -1 })
            {
                Array.Fill(output, (byte)0xA5);
                Assert.Equal(-1, Native.FfdhePublicKey(other, o, k, 64));
                Assert.Equal(-1, Native.FfdheShared(other, o, k, 64, y));
                Assert.All(output, octet => Assert.Equal(0xA5, octet));
            }

            foreach ((int group, int bits, int minimum) in Groups)
            {
                byte* peerKey = y + (1024 - bits / 8);
                foreach (int length in new[] { 0, minimum - 1, bits / 8 + 1 })
                {
                    Array.Fill(output, (byte)0xA5);
                    Assert.Equal(-1, Native.FfdhePublicKey(group, o, k, (nuint)length));
                    Assert.Equal(-1, Native.FfdheShared(group, o, k, (nuint)length, peerKey));
                    Assert.All(output, octet => Assert.Equal(0xA5, octet));
                }
            }
        }
    }

    /// <summary>
    /// The outputs are exactly p's size: the octet after each is never touched (a canary), and the
    /// same exponent gives the same octets every time (no state between calls).
    /// </summary>
    [Fact]
    public void WritesOnlyItsOutputs()
    {
        Platform.RequireLinuxX64();
        foreach ((int group, int bits, int minimum) in Groups)
        {
            int size = bits / 8;
            byte[] x = RandomBytes(new Random(bits + 1), minimum + 7);
            byte[] first = PublicKey(group, x, size);
            byte[] output = new byte[size + 16];
            Array.Fill(output, (byte)0x5A);
            fixed (byte* o = output, k = x)
            {
                Assert.Equal(0, Native.FfdhePublicKey(group, o, k, (nuint)x.Length));
            }

            Assert.Equal(Convert.ToHexString(first), Convert.ToHexString(output[..size]));
            Assert.All(output[size..], octet => Assert.Equal(0x5A, octet));
            Array.Fill(output, (byte)0x5A);
            fixed (byte* o = output, k = x, y = first)
            {
                Assert.Equal(0, Native.FfdheShared(group, o, k, (nuint)x.Length, y));
            }

            Assert.All(output[size..], octet => Assert.Equal(0x5A, octet));
        }
    }

    /// <summary>One public key, p's size in octets; asserts the call succeeded.</summary>
    /// <param name="group">The group.</param>
    /// <param name="x">The private exponent's octets.</param>
    /// <param name="size">p's size in octets.</param>
    /// <returns>The public key.</returns>
    private static byte[] PublicKey(int group, byte[] x, int size)
    {
        byte[] output = new byte[size];
        fixed (byte* o = output, k = x)
        {
            Assert.Equal(0, Native.FfdhePublicKey(group, o, k, (nuint)x.Length));
        }

        return output;
    }

    /// <summary>One shared secret into an output pre-filled with 0xA5 (what a refusal must leave).</summary>
    /// <param name="group">The group.</param>
    /// <param name="x">The private exponent's octets.</param>
    /// <param name="peer">The peer's public key, p's size in octets.</param>
    /// <param name="size">p's size in octets.</param>
    /// <returns>The call's result and the output.</returns>
    private static (int Result, byte[] Shared) Shared(int group, byte[] x, byte[] peer, int size)
    {
        byte[] output = new byte[size];
        Array.Fill(output, (byte)0xA5);
        fixed (byte* o = output, k = x, y = peer)
        {
            int result = Native.FfdheShared(group, o, k, (nuint)x.Length, y);
            return (result, output);
        }
    }

    /// <summary>A group's p from the pinned RFC 7919 text: the hexadecimal digits after Appendix A's
    /// "The hexadecimal representation of p is:" in the group's section, page breaks skipped.</summary>
    /// <param name="bits">The group's size in bits.</param>
    /// <returns>p.</returns>
    /// <exception cref="InvalidDataException">The section or its digits were not found.</exception>
    internal static BigInteger Prime(int bits)
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc7919.txt"));
        int section = Array.FindIndex(lines, l => l.TrimEnd().EndsWith($"ffdhe{bits}", StringComparison.Ordinal) && l.StartsWith("A.", StringComparison.Ordinal));
        int heading = section < 0 ? -1 : Array.FindIndex(lines, section, l => l.Trim() == "The hexadecimal representation of p is:");
        if (heading < 0)
        {
            throw new InvalidDataException($"ffdhe{bits}'s p was not found in the pinned RFC 7919 text");
        }

        var digits = new StringBuilder();
        for (int i = heading + 1; i < lines.Length; i++)
        {
            string text = lines[i].Trim();
            if (text.StartsWith("The generator is", StringComparison.Ordinal))
            {
                break;
            }

            if (text.Length > 0 && text.Split(' ').All(group => group.Length == 8 && group.All(Uri.IsHexDigit)))
            {
                digits.Append(text.Replace(" ", "", StringComparison.Ordinal));
            }
        }

        BigInteger p = BigInteger.Parse("0" + digits, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        Assert.Equal(bits, (int)p.GetBitLength());
        return p;
    }

    /// <summary>A big-endian unsigned number.</summary>
    /// <param name="octets">Its octets.</param>
    /// <returns>The number.</returns>
    private static BigInteger Unsigned(byte[] octets) => new(octets, isUnsigned: true, isBigEndian: true);

    /// <summary>A number as size octets of upper-case hex, big-endian, left-padded.</summary>
    /// <param name="value">The number (below 2^(8 size)).</param>
    /// <param name="size">How many octets.</param>
    /// <returns>The hex.</returns>
    private static string Hex(BigInteger value, int size)
    {
        byte[] octets = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        Assert.True(octets.Length <= size);
        return Convert.ToHexString(new byte[size - octets.Length]) + Convert.ToHexString(octets);
    }

    /// <summary>n random octets.</summary>
    /// <param name="random">The source.</param>
    /// <param name="n">How many.</param>
    /// <returns>The octets.</returns>
    private static byte[] RandomBytes(Random random, int n)
    {
        byte[] octets = new byte[n];
        random.NextBytes(octets);
        return octets;
    }
}
