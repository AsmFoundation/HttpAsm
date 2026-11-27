using System.Numerics;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_x448 and httpasm_x448_public_key (RFC 7748) through the C ABI, held to RFC 7748's own
/// vectors (read from the pinned text: section 5.2's two scalar multiplications and its
/// iterations, section 6.2's Diffie-Hellman example), to Project Wycheproof's X448 tests (twist
/// points, non-canonical and small-order public keys, edge-case scalars and products), and to
/// the ladder computed with BigInteger on random scalars and points; the public key to the
/// ladder at u = 5; the zero results (small-order points, and the one clamped scalar, 4q, whose
/// public key is zero) to -1; the buffers to exactly 56 octets read and written. tests/run-linux.sh
/// runs the suite at every CPU tier, so both versions answer: mulx (v3) and mul (v1), each over
/// eight 56-bit limbs.
/// </summary>
public sealed unsafe class X448Tests
{
    /// <summary>2^448 - 2^224 - 1, the field's prime.</summary>
    private static readonly BigInteger Prime = (BigInteger.One << 448) - (BigInteger.One << 224) - 1;

    /// <summary>
    /// q, the prime order of the base point (u = 5): 2^446 minus RFC 7748 4.2's constant.
    /// </summary>
    private static readonly BigInteger Order = (BigInteger.One << 446) - BigInteger.Parse("13818066809895115352007386748515426880336692474882178609894547503885");

    /// <summary>RFC 7748 5.2's two X448 vectors: each scalar and u-coordinate to its output.</summary>
    [Fact]
    public void MatchesRfc7748sVectors()
    {
        Platform.RequireLinuxX64();
        List<(string Label, byte[] Value)> values = X25519Tests.RfcValues("5.2.  Test Vectors", "   X448:", "   The second type");
        var scalars = values.Where(v => v.Label == "input scalar").ToList();
        var points = values.Where(v => v.Label == "input u-coordinate").ToList();
        var outputs = values.Where(v => v.Label == "output u-coordinate").ToList();
        Assert.Equal(2, scalars.Count);
        for (int i = 0; i < 2; i++)
        {
            (int result, byte[] output) = X448(scalars[i].Value, points[i].Value);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexStringLower(outputs[i].Value), Convert.ToHexStringLower(output));
        }
    }

    /// <summary>
    /// RFC 7748 5.2's iterations: from k = u = 5, k = X448(k, u) and u = the old k, one and 1,000
    /// times (the million-iteration value takes two minutes per tier; the thousand already chain
    /// every output into the next input).
    /// </summary>
    [Fact]
    public void MatchesRfc7748sIterations()
    {
        Platform.RequireLinuxX64();
        List<(string Label, byte[] Value)> values = X25519Tests.RfcValues("   For each iteration", "   X448:", "6.  Diffie-Hellman");
        byte[] afterOne = values.Single(v => v.Label == "after one iteration").Value;
        byte[] afterThousand = values.Single(v => v.Label == "after 1,000 iterations").Value;
        byte[] k = new byte[56], u = new byte[56];
        k[0] = 5;
        u[0] = 5;
        for (int i = 1; i <= 1000; i++)
        {
            byte[] next = X448(k, u).Output;
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
    /// RFC 7748 6.2's Diffie-Hellman example: Alice's and Bob's public keys from their private
    /// keys (httpasm_x448_public_key, and the ladder at u = 5), and their shared secret K computed
    /// both ways.
    /// </summary>
    [Fact]
    public void MatchesRfc7748sDiffieHellmanExample()
    {
        Platform.RequireLinuxX64();
        List<(string Label, byte[] Value)> values = X25519Tests.RfcValues("6.2.  Curve448", "   Test vector:", "7.  Security");
        byte[] a = values.Single(v => v.Label == "alice's private key, a").Value;
        byte[] alicePublic = values.Single(v => v.Label == "alice's public key, x448(a, 5)").Value;
        byte[] b = values.Single(v => v.Label == "bob's private key, b").Value;
        byte[] bobPublic = values.Single(v => v.Label == "bob's public key, x448(b, 5)").Value;
        byte[] shared = values.Single(v => v.Label == "their shared secret, k").Value;
        Assert.Equal(alicePublic, PublicKey(a).Output);
        Assert.Equal(bobPublic, PublicKey(b).Output);
        Assert.Equal(alicePublic, X448(a, Five()).Output);
        (int aliceResult, byte[] aliceShared) = X448(a, bobPublic);
        (int bobResult, byte[] bobShared) = X448(b, alicePublic);
        Assert.Equal(0, aliceResult);
        Assert.Equal(0, bobResult);
        Assert.Equal(shared, aliceShared);
        Assert.Equal(shared, bobShared);
    }

    /// <summary>
    /// Project Wycheproof's X448 tests (510, commit 65ca494): every valid and acceptable test's
    /// shared secret must match - the twist points' and the non-canonical public keys' included
    /// (RFC 7748 accepts both) - and the 11 small-order public keys must give all zeros with -1.
    /// The 12 invalid tests are public keys of 57 octets, which a function taking 56 cannot be
    /// given: each is checked to be one, and counted.
    /// </summary>
    [Fact]
    public void PassesWycheproofsTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, zeros = 0, tooLong = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/x448_test.json")))
        {
            byte[] scalar = Convert.FromHexString(test.GetProperty("private").GetString()!);
            byte[] point = Convert.FromHexString(test.GetProperty("public").GetString()!);
            byte[] shared = Convert.FromHexString(test.GetProperty("shared").GetString()!);
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            if (test.GetProperty("result").GetString() == "invalid")
            {
                // The one kind of invalid test: a public key that is not 56 octets long.
                Assert.True(point.Length == 57, id);
                Assert.Contains(test.GetProperty("flags").EnumerateArray(), flag => flag.GetString() == "PublicKeyTooLong");
                tooLong++;
                continue;
            }

            bool zero = shared.AsSpan().IndexOfAnyExcept((byte)0) < 0;
            zeros += zero ? 1 : 0;
            (int result, byte[] output) = X448(scalar, point);
            Assert.True(output.SequenceEqual(shared), id);
            Assert.True(result == (zero ? -1 : 0), id);
            count++;
        }

        Assert.Equal(498, count);
        Assert.Equal(11, zeros);
        Assert.Equal(12, tooLong);
    }

    /// <summary>
    /// The ladder against RFC 7748 5's pseudocode computed with BigInteger, on 120 random scalars
    /// and u-coordinates: some non-canonical (p to 2^448 - 1, taken modulo p), some all ones (the
    /// largest non-canonical u), some scalars all ones or all zeros (clamping makes both valid).
    /// </summary>
    [Fact]
    public void MatchesABigIntegerLadder()
    {
        Platform.RequireLinuxX64();
        var random = new Random(7748);
        for (int i = 0; i < 120; i++)
        {
            byte[] scalar = new byte[56], point = new byte[56];
            random.NextBytes(scalar);
            random.NextBytes(point);
            switch (i % 6)
            {
                case 1:
                    (Prime + random.Next(1 << 30)).TryWriteBytes(point, out _, isUnsigned: true);   // non-canonical
                    break;
                case 2:
                    point.AsSpan().Fill(0xFF);                      // 2^448 - 1 = p + 2^224
                    break;
                case 3:
                    scalar.AsSpan().Fill(0xFF);
                    break;
                case 4:
                    scalar.AsSpan().Clear();
                    break;
            }

            byte[] expected = LadderReference(scalar, point);
            (int result, byte[] output) = X448(scalar, point);
            Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(output));
            Assert.Equal(expected.AsSpan().IndexOfAnyExcept((byte)0) < 0 ? -1 : 0, result);
        }
    }

    /// <summary>
    /// The public key function (the ladder with a product by 5 in place of one product a step)
    /// against the general ladder at u = 5 on 300 random scalars and the edges of the clamped range
    /// (all zeros and all ones; one bit set at each of many places; alternating patterns), and
    /// against the BigInteger ladder for the edges and the first 30.
    /// </summary>
    [Fact]
    public void PublicKeysAreTheLaddersAtFive()
    {
        Platform.RequireLinuxX64();
        var scalars = new List<byte[]>
        {
            new byte[56],
            Enumerable.Repeat((byte)0xFF, 56).ToArray(),
            Enumerable.Repeat((byte)0x55, 56).ToArray(),
            Enumerable.Repeat((byte)0xAA, 56).ToArray(),
        };
        for (int bit = 0; bit < 448; bit += 23)
        {
            byte[] one = new byte[56];
            one[bit / 8] = (byte)(1 << (bit % 8));
            scalars.Add(one);
        }

        int edges = scalars.Count;
        var random = new Random(41);
        for (int i = 0; i < 300; i++)
        {
            byte[] scalar = new byte[56];
            random.NextBytes(scalar);
            scalars.Add(scalar);
        }

        for (int i = 0; i < scalars.Count; i++)
        {
            (int result, byte[] publicKey) = PublicKey(scalars[i]);
            (int ladderResult, byte[] ladder) = X448(scalars[i], Five());
            Assert.Equal(0, result);
            Assert.Equal(0, ladderResult);
            Assert.True(ladder.SequenceEqual(publicKey), $"scalar {Convert.ToHexStringLower(scalars[i])}");
            if (i < edges + 30)
            {
                Assert.Equal(Convert.ToHexStringLower(LadderReference(scalars[i], Five())), Convert.ToHexStringLower(publicKey));
            }
        }
    }

    /// <summary>
    /// Points of small order give the all-zero secret, reported with -1 (TLS 1.3 aborts on it,
    /// RFC 9846 7.4.2): u = 0 (order 2), u = 1 and u = p - 1 (order 4, curve or twist), and the
    /// non-canonical p and p + 1 (the same points), under any scalar.
    /// </summary>
    /// <param name="offset">u as p's offset: -1 for p - 1, 0 for p; or, with <paramref name="canonical"/>, u itself.</param>
    /// <param name="canonical">True when <paramref name="offset"/> is u itself (0 or 1).</param>
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(-1, false)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public void ReportsSmallOrderPoints(int offset, bool canonical)
    {
        Platform.RequireLinuxX64();
        byte[] point = new byte[56];
        (canonical ? new BigInteger(offset) : Prime + offset).TryWriteBytes(point, out _, isUnsigned: true);
        var random = new Random(8 + offset);
        for (int i = 0; i < 6; i++)
        {
            byte[] scalar = new byte[56];
            random.NextBytes(scalar);
            (int result, byte[] output) = X448(scalar, point);
            Assert.Equal(-1, result);
            Assert.True(output.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        }
    }

    /// <summary>
    /// The one clamped scalar whose public key is zero: 4q (q the base point's order, below 2^446,
    /// so 4q lies in the clamped range [2^447, 2^448) with its two low bits clear), and the
    /// scalars that clamp to it (its two low bits set, which clamping clears). The public key and
    /// the ladder at u = 5 both write zeros and return -1; one more or less than 4q in bit 2 is an
    /// ordinary key.
    /// </summary>
    [Fact]
    public void ReportsTheZeroPublicKey()
    {
        Platform.RequireLinuxX64();
        BigInteger fourQ = 4 * Order;
        Assert.True(fourQ >= BigInteger.One << 447 && fourQ < BigInteger.One << 448);
        foreach (int low in new[] { 0, 1, 2, 3 })
        {
            byte[] scalar = new byte[56];
            (fourQ + low).TryWriteBytes(scalar, out _, isUnsigned: true);
            (int result, byte[] output) = PublicKey(scalar);
            Assert.Equal(-1, result);
            Assert.True(output.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            (int ladderResult, byte[] ladder) = X448(scalar, Five());
            Assert.Equal(-1, ladderResult);
            Assert.True(ladder.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        }

        foreach (int step in new[] { -4, 4 })
        {
            byte[] scalar = new byte[56];
            (fourQ + step).TryWriteBytes(scalar, out _, isUnsigned: true);
            (int result, byte[] output) = PublicKey(scalar);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexStringLower(LadderReference(scalar, Five())), Convert.ToHexStringLower(output));
        }
    }

    /// <summary>
    /// The buffers: each input read only within its 56 octets (the scalar and the point placed
    /// against an inaccessible page, so a read past them faults), the output written in exactly
    /// 56 octets (the octets after it keep their canary), and the output allowed to be the scalar
    /// or the point (both functions read everything before writing).
    /// </summary>
    [Fact]
    public void KeepsToItsBuffers()
    {
        Platform.RequireLinuxX64();
        var random = new Random(56);
        byte[] scalar = new byte[56], point = new byte[56];
        random.NextBytes(scalar);
        random.NextBytes(point);
        byte[] expected = X448(scalar, point).Output;
        byte[] expectedPublic = PublicKey(scalar).Output;
        using (var scalarPage = new GuardedBuffer())
        using (var pointPage = new GuardedBuffer())
        {
            byte* s = scalarPage.AtPageEnd(scalar);
            byte* p = pointPage.AtPageEnd(point);
            byte[] output = new byte[72];
            output.AsSpan().Fill(0xC3);
            fixed (byte* o = output)
            {
                Assert.Equal(0, Native.X448(o, s, p));
                Assert.Equal(expected, output[..56]);
                Assert.All(output[56..], octet => Assert.Equal(0xC3, octet));
                output.AsSpan().Fill(0xC3);
                Assert.Equal(0, Native.X448PublicKey(o, s));
                Assert.Equal(expectedPublic, output[..56]);
                Assert.All(output[56..], octet => Assert.Equal(0xC3, octet));
            }
        }

        byte[] inPlace = (byte[])point.Clone();
        fixed (byte* o = inPlace, s = scalar)
        {
            Assert.Equal(0, Native.X448(o, s, o));                 // out = point
        }

        Assert.Equal(expected, inPlace);
        inPlace = (byte[])scalar.Clone();
        fixed (byte* o = inPlace, p = point)
        {
            Assert.Equal(0, Native.X448(o, o, p));                 // out = scalar
        }

        Assert.Equal(expected, inPlace);
        inPlace = (byte[])scalar.Clone();
        fixed (byte* o = inPlace)
        {
            Assert.Equal(0, Native.X448PublicKey(o, o));          // the public key over its scalar
        }

        Assert.Equal(expectedPublic, inPlace);
    }

    /// <summary>One httpasm_x448 call, its output first filled with 0xEE (every octet must change
    /// or be confirmed).</summary>
    /// <param name="scalar">56 octets.</param>
    /// <param name="point">56 octets.</param>
    /// <returns>The result and the output.</returns>
    private static (int Result, byte[] Output) X448(byte[] scalar, byte[] point)
    {
        byte[] output = new byte[56];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, s = scalar, p = point)
        {
            result = Native.X448(o, s, p);
        }

        return (result, output);
    }

    /// <summary>One httpasm_x448_public_key call.</summary>
    /// <param name="scalar">56 octets.</param>
    /// <returns>The result and X448(scalar, 5).</returns>
    private static (int Result, byte[] Output) PublicKey(byte[] scalar)
    {
        byte[] output = new byte[56];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, s = scalar)
        {
            result = Native.X448PublicKey(o, s);
        }

        return (result, output);
    }

    /// <summary>The base point's u-coordinate, 5, as 56 octets.</summary>
    /// <returns>05 00 .. 00.</returns>
    private static byte[] Five()
    {
        byte[] five = new byte[56];
        five[0] = 5;
        return five;
    }

    /// <summary>
    /// X448 as RFC 7748 5's pseudocode writes it, with BigInteger: decodeScalar448 (clamp: the low
    /// two bits cleared, bit 447 set), decodeUCoordinate (all 448 bits, then modulo p), the
    /// ladder with cswap and a24 = 39081, x2 z2^(p - 2).
    /// </summary>
    /// <param name="scalar">56 octets.</param>
    /// <param name="point">56 octets.</param>
    /// <returns>The 56-octet result.</returns>
    private static byte[] LadderReference(byte[] scalar, byte[] point)
    {
        byte[] k = (byte[])scalar.Clone();
        k[0] &= 252;
        k[55] |= 128;
        var kk = new BigInteger(k, isUnsigned: true);
        BigInteger x1 = new BigInteger(point, isUnsigned: true) % Prime, x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        int swap = 0;
        for (int t = 447; t >= 0; t--)
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
            z2 = e * ((aa + 39081 * e) % Prime) % Prime;
        }

        if (swap == 1)
        {
            (x2, x3) = (x3, x2);
            (z2, z3) = (z3, z2);
        }

        BigInteger result = x2 * BigInteger.ModPow(z2, Prime - 2, Prime) % Prime;
        byte[] output = new byte[56];
        Assert.True(result.TryWriteBytes(output, out _, isUnsigned: true));
        return output;
    }
}
