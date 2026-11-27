using System.Numerics;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_x25519 and httpasm_x25519_public_key (RFC 7748) through the C ABI, held to RFC 7748's
/// own vectors (read from the pinned text: section 5.2's two scalar multiplications and its
/// iterations, section 6.1's Diffie-Hellman example), to Project Wycheproof's 518 X25519 tests
/// (twist points, non-canonical and small-order public keys, edge-case scalars), and to the
/// ladder computed with BigInteger on random scalars and points; and the public key, which is
/// edwards25519's fixed base rather than the ladder, to the ladder at u = 9. tests/run-linux.sh
/// runs the suite at every CPU tier, so both versions answer: mulx with adcx/adox (v3 with ADX)
/// and mul on 51-bit limbs (v1).
/// </summary>
public sealed unsafe partial class X25519Tests
{
    /// <summary>2^255 - 19, the field's prime.</summary>
    private static readonly BigInteger Prime = (BigInteger.One << 255) - 19;

    /// <summary>
    /// RFC 7748 5.2's two X25519 vectors: each scalar and u-coordinate (the second with bit 255
    /// set, which must be ignored) to its output.
    /// </summary>
    [Fact]
    public void MatchesRfc7748sVectors()
    {
        Platform.RequireLinuxX64();
        List<(string Label, byte[] Value)> values = RfcValues("5.2.  Test Vectors", "   X25519:", "   X448:");
        var scalars = values.Where(v => v.Label == "input scalar").ToList();
        var points = values.Where(v => v.Label == "input u-coordinate").ToList();
        var outputs = values.Where(v => v.Label == "output u-coordinate").ToList();
        Assert.Equal(2, scalars.Count);
        for (int i = 0; i < 2; i++)
        {
            (int result, byte[] output) = X25519(scalars[i].Value, points[i].Value);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexStringLower(outputs[i].Value), Convert.ToHexStringLower(output));
        }
    }

    /// <summary>
    /// RFC 7748 5.2's iterations: from k = u = 9, k = X25519(k, u) and u = the old k, one and
    /// 1,000 times (the million-iteration value takes most of a minute per tier, and the thousand
    /// already chain every output into the next input).
    /// </summary>
    [Fact]
    public void MatchesRfc7748sIterations()
    {
        Platform.RequireLinuxX64();
        List<(string Label, byte[] Value)> values = RfcValues("   For each iteration", "   X25519:", "   X448:");
        byte[] afterOne = values.Single(v => v.Label == "after one iteration").Value;
        byte[] afterThousand = values.Single(v => v.Label == "after 1,000 iterations").Value;
        byte[] k = new byte[32], u = new byte[32];
        k[0] = 9;
        u[0] = 9;
        for (int i = 1; i <= 1000; i++)
        {
            byte[] next = X25519(k, u).Output;
            u = k;
            k = next;
            if (i == 1)
            {
                Assert.Equal(Convert.ToHexStringLower(afterOne), Convert.ToHexStringLower(k));
            }
        }

        Assert.Equal(Convert.ToHexStringLower(afterThousand), Convert.ToHexStringLower(k));
    }

    /// <summary>
    /// RFC 7748 6.1's Diffie-Hellman example: Alice's and Bob's public keys from their private
    /// keys (httpasm_x25519_public_key), and their shared secret K computed both ways.
    /// </summary>
    [Fact]
    public void MatchesRfc7748sDiffieHellmanExample()
    {
        Platform.RequireLinuxX64();
        List<(string Label, byte[] Value)> values = RfcValues("6.1.  Curve25519", "   Test vector:", "6.2.  Curve448");
        byte[] a = values.Single(v => v.Label == "alice's private key, a").Value;
        byte[] alicePublic = values.Single(v => v.Label == "alice's public key, x25519(a, 9)").Value;
        byte[] b = values.Single(v => v.Label == "bob's private key, b").Value;
        byte[] bobPublic = values.Single(v => v.Label == "bob's public key, x25519(b, 9)").Value;
        byte[] shared = values.Single(v => v.Label == "their shared secret, k").Value;
        Assert.Equal(alicePublic, PublicKey(a));
        Assert.Equal(bobPublic, PublicKey(b));
        (int aliceResult, byte[] aliceShared) = X25519(a, bobPublic);
        (int bobResult, byte[] bobShared) = X25519(b, alicePublic);
        Assert.Equal(0, aliceResult);
        Assert.Equal(0, bobResult);
        Assert.Equal(shared, aliceShared);
        Assert.Equal(shared, bobShared);
    }

    /// <summary>
    /// Project Wycheproof's X25519 tests (518, commit 65ca494): every shared secret must match,
    /// the twist points' and the non-canonical public keys' included (RFC 7748 accepts both), and
    /// the 31 small-order public keys must give all zeros with -1.
    /// </summary>
    [Fact]
    public void PassesWycheproofsTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, zeros = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/x25519_test.json")))
        {
            byte[] scalar = Convert.FromHexString(test.GetProperty("private").GetString()!);
            byte[] point = Convert.FromHexString(test.GetProperty("public").GetString()!);
            byte[] shared = Convert.FromHexString(test.GetProperty("shared").GetString()!);
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            Assert.NotEqual("invalid", test.GetProperty("result").GetString());
            bool zero = shared.AsSpan().IndexOfAnyExcept((byte)0) < 0;
            zeros += zero ? 1 : 0;
            (int result, byte[] output) = X25519(scalar, point);
            Assert.True(output.SequenceEqual(shared), id);
            Assert.True(result == (zero ? -1 : 0), id);
            count++;
        }

        Assert.Equal(518, count);
        Assert.Equal(31, zeros);
    }

    /// <summary>
    /// The ladder against RFC 7748 5's pseudocode computed with BigInteger, on 300 random
    /// scalars and u-coordinates: some with bit 255 set (ignored), some non-canonical (p to
    /// 2^255 - 1, taken modulo p), some scalars all ones or all zeros (clamping makes both valid).
    /// And the public key function against the ladder at u = 9.
    /// </summary>
    [Fact]
    public void MatchesABigIntegerLadder()
    {
        Platform.RequireLinuxX64();
        var random = new Random(7748);
        for (int i = 0; i < 300; i++)
        {
            byte[] scalar = new byte[32], point = new byte[32];
            random.NextBytes(scalar);
            random.NextBytes(point);
            switch (i % 6)
            {
                case 1:
                    point[31] |= 0x80;                              // bit 255: ignored
                    break;
                case 2:
                    (Prime + random.Next(19)).TryWriteBytes(point, out _, isUnsigned: true);   // non-canonical
                    break;
                case 3:
                    scalar.AsSpan().Fill(0xFF);
                    break;
                case 4:
                    scalar.AsSpan().Clear();
                    break;
            }

            byte[] expected = LadderReference(scalar, point);
            (int result, byte[] output) = X25519(scalar, point);
            Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(output));
            Assert.Equal(expected.AsSpan().IndexOfAnyExcept((byte)0) < 0 ? -1 : 0, result);
            if (i < 50)
            {
                byte[] nine = new byte[32];
                nine[0] = 9;
                Assert.Equal(LadderReference(scalar, nine), PublicKey(scalar));
            }
        }
    }

    /// <summary>
    /// The public key against the ladder at u = 9, since the two are separate code: the public
    /// key is edwards25519's fixed base (crypto/ed25519.asm's ha_x25519_base_v: k B from the
    /// precomputed table, then u = (1 + y) / (1 - y)), the shared secret the Montgomery ladder.
    /// 2,000 random scalars and the edges of the clamped range and of the table's signed 6-bit
    /// digits (all zeros and all ones, which clamp to 2^254 and 2^255 - 8; one bit set at each
    /// place; runs of ones and zeros that make every digit +32, -32 or 0; alternating patterns),
    /// each with httpasm_x25519(scalar, 9) and, for the edges and the first 100, the BigInteger
    /// ladder too.
    /// </summary>
    [Fact]
    public void PublicKeysAreTheLaddersAtNine()
    {
        Platform.RequireLinuxX64();
        byte[] nine = new byte[32];
        nine[0] = 9;
        var scalars = new List<byte[]>
        {
            new byte[32],
            Enumerable.Repeat((byte)0xFF, 32).ToArray(),
            Enumerable.Repeat((byte)0x55, 32).ToArray(),
            Enumerable.Repeat((byte)0xAA, 32).ToArray(),
            Enumerable.Repeat((byte)0x0F, 32).ToArray(),
            Enumerable.Repeat((byte)0xF0, 32).ToArray(),
        };
        for (int bit = 0; bit < 256; bit += 5)
        {
            byte[] one = new byte[32];
            one[bit / 8] = (byte)(1 << (bit % 8));
            scalars.Add(one);
        }

        foreach (int run in new[] { 5, 6, 7, 12 })
        {
            // ones in runs of `run` then zeros: windows whose 7 bits are 0111111 or 1000000 (digit
            // +32 or -32), or all zeros (digit 0), at many window offsets
            var bits = new BigInteger();
            for (int i = 0; i < 256; i++)
            {
                if (i / run % 2 == 0)
                {
                    bits |= BigInteger.One << i;
                }
            }

            byte[] pattern = new byte[32];
            (bits & ((BigInteger.One << 256) - 1)).TryWriteBytes(pattern, out _, isUnsigned: true);
            scalars.Add(pattern);
        }

        int edges = scalars.Count;
        var random = new Random(41);
        for (int i = 0; i < 2000; i++)
        {
            byte[] scalar = new byte[32];
            random.NextBytes(scalar);
            scalars.Add(scalar);
        }

        for (int i = 0; i < scalars.Count; i++)
        {
            byte[] publicKey = PublicKey(scalars[i]);
            (int result, byte[] ladder) = X25519(scalars[i], nine);
            Assert.Equal(0, result);
            Assert.True(ladder.SequenceEqual(publicKey), $"scalar {Convert.ToHexStringLower(scalars[i])}");
            if (i < edges + 100)
            {
                Assert.Equal(Convert.ToHexStringLower(LadderReference(scalars[i], nine)), Convert.ToHexStringLower(publicKey));
            }
        }
    }

    /// <summary>
    /// Points of small order give the all-zero secret, reported with -1 (TLS 1.3 aborts on it,
    /// RFC 9846 7.4.2): u = 0, u = 1 (order 4 and 1), and the order-8 points'
    /// u-coordinates, under any scalar.
    /// </summary>
    /// <param name="point">The small-order u-coordinate, little-endian hex.</param>
    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    [InlineData("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")]
    [InlineData("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")]
    public void ReportsSmallOrderPoints(string point)
    {
        Platform.RequireLinuxX64();
        var random = new Random(8);
        for (int i = 0; i < 8; i++)
        {
            byte[] scalar = new byte[32];
            random.NextBytes(scalar);
            (int result, byte[] output) = X25519(scalar, Convert.FromHexString(point));
            Assert.Equal(-1, result);
            Assert.True(output.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        }
    }

    /// <summary>One httpasm_x25519 call.</summary>
    /// <param name="scalar">32 octets.</param>
    /// <param name="point">32 octets.</param>
    /// <returns>The result and the output.</returns>
    private static (int Result, byte[] Output) X25519(byte[] scalar, byte[] point)
    {
        byte[] output = new byte[32];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, s = scalar, p = point)
        {
            result = Native.X25519(o, s, p);
        }

        return (result, output);
    }

    /// <summary>One httpasm_x25519_public_key call.</summary>
    /// <param name="scalar">32 octets.</param>
    /// <returns>X25519(scalar, 9).</returns>
    private static byte[] PublicKey(byte[] scalar)
    {
        byte[] output = new byte[32];
        fixed (byte* o = output, s = scalar)
        {
            Native.X25519PublicKey(o, s);
        }

        return output;
    }

    /// <summary>
    /// X25519 as RFC 7748 5's pseudocode writes it, with BigInteger: decodeScalar25519 (clamp),
    /// decodeUCoordinate (bit 255 masked, then modulo p), the ladder with cswap, x2 z2^(p - 2).
    /// </summary>
    /// <param name="scalar">32 octets.</param>
    /// <param name="point">32 octets.</param>
    /// <returns>The 32-octet result.</returns>
    private static byte[] LadderReference(byte[] scalar, byte[] point)
    {
        byte[] k = (byte[])scalar.Clone();
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        var kk = new BigInteger(k, isUnsigned: true);
        byte[] u = (byte[])point.Clone();
        u[31] &= 127;
        BigInteger x1 = new BigInteger(u, isUnsigned: true) % Prime, x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        int swap = 0;
        for (int t = 254; t >= 0; t--)
        {
            int kt = (int)((kk >> t) & 1);
            swap ^= kt;
            if (swap == 1)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }

            swap = kt;
            BigInteger a = (x2 + z2) % Prime, aa = a * a % Prime, b = (x2 - z2 + Prime) % Prime, bb = b * b % Prime;
            BigInteger e = (aa - bb + Prime) % Prime, c = (x3 + z3) % Prime, d = (x3 - z3 + Prime) % Prime;
            BigInteger da = d * a % Prime, cb = c * b % Prime;
            x3 = BigInteger.Pow(da + cb, 2) % Prime;
            z3 = x1 * BigInteger.Pow((da - cb + Prime) % Prime, 2) % Prime;
            x2 = aa * bb % Prime;
            z2 = e * ((aa + 121665 * e) % Prime) % Prime;
        }

        if (swap == 1)
        {
            (x2, x3) = (x3, x2);
            (z2, z3) = (z3, z2);
        }

        BigInteger result = x2 * BigInteger.ModPow(z2, Prime - 2, Prime) % Prime;
        byte[] output = new byte[32];
        Assert.True(result.TryWriteBytes(output, out _, isUnsigned: true));
        return output;
    }

    /// <summary>
    /// The labeled hex values of a part of the pinned RFC 7748 text (specs/rfc/rfc7748.txt), in
    /// order: from the first line starting with <paramref name="part"/>, between the first line
    /// after it starting with <paramref name="from"/> and the next starting with
    /// <paramref name="to"/>. A line ending with a colon names a value (lower case, the colon
    /// dropped); the lines of 56 or more hex digits under it are its octets (X25519's take one
    /// line, X448's two; the decimal renderings beside them are shorter and match no value).
    /// </summary>
    /// <param name="part">The part's heading, as the line starts.</param>
    /// <param name="from">The line that opens the range within the part.</param>
    /// <param name="to">The line that ends it.</param>
    /// <returns>The values in order.</returns>
    /// <exception cref="InvalidDataException">A heading was not found.</exception>
    /// <remarks>X448Tests reads its RFC 7748 vectors through this too (internal for that).</remarks>
    internal static List<(string Label, byte[] Value)> RfcValues(string part, string from, string to)
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc7748.txt"));
        int heading = Array.FindIndex(lines, l => l.StartsWith(part, StringComparison.Ordinal));
        int start = heading < 0 ? -1 : Array.FindIndex(lines, heading, l => l.StartsWith(from, StringComparison.Ordinal));
        int end = start < 0 ? -1 : Array.FindIndex(lines, start + 1, l => l.StartsWith(to, StringComparison.Ordinal));
        if (end < 0)
        {
            throw new InvalidDataException($"RFC 7748's '{part.Trim()}' range was not found in the pinned text");
        }

        var values = new List<(string, byte[])>();
        string? label = null;
        var octets = new List<byte>();
        foreach (string line in lines[(start + 1)..end])
        {
            string text = line.Trim();
            if (HexLine().IsMatch(text))
            {
                octets.AddRange(Convert.FromHexString(text));
            }
            else if (text.EndsWith(':'))
            {
                if (label is not null && octets.Count > 0)
                {
                    values.Add((label, [.. octets]));
                }

                label = text.TrimEnd(':').ToLowerInvariant();
                octets.Clear();
            }
        }

        if (label is not null && octets.Count > 0)
        {
            values.Add((label, [.. octets]));
        }

        return values;
    }

    /// <summary>A line of 56 or more lowercase hex digits (an RFC 7748 value's line).</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex("^[0-9a-f]{56,}$")]
    private static partial Regex HexLine();
}
