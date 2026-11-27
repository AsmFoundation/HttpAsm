using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_ed448_public_key, httpasm_ed448_private_key_init, httpasm_ed448_sign and
/// httpasm_ed448_verify (RFC 8032 5.2, pure Ed448 with SHAKE256 and dom4) through the C ABI, held
/// to RFC 8032 7.4's nine Ed448 vectors (read from the pinned text; one with a context), Project
/// Wycheproof's 87 verifications, and a BigInteger model of RFC 8032 5.2 (its Appendix A's
/// arithmetic, in C#, hashing with .NET's SHAKE256) on random and edge seeds, message lengths,
/// contexts and signatures. Verification is held to the model's cofactorless equation everywhere,
/// the small-order public keys included. tests/run-linux.sh runs the suite at every CPU tier, so
/// both versions answer: v3 (mulx, AVX2 table scans) and v1 (mul, SSE2), both on X448's eight
/// 56-bit limbs. .NET has no Ed448 of its own: the model is the second implementation (and the
/// scratchpad's Python model, which designed the assembly, passed the same RFC vectors and every
/// Wycheproof case first).
/// </summary>
public sealed unsafe partial class Ed448Tests
{
    /// <summary>The field's prime p = 2^448 - 2^224 - 1.</summary>
    private static readonly BigInteger P = (BigInteger.One << 448) - (BigInteger.One << 224) - 1;

    /// <summary>L, the prime order of the base point: 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.</summary>
    private static readonly BigInteger L = (BigInteger.One << 446) - BigInteger.Parse("13818066809895115352007386748515426880336692474882178609894547503885");

    /// <summary>The curve's d = -39081 modulo p (edwards448: x^2 + y^2 = 1 + d x^2 y^2).</summary>
    private static readonly BigInteger D = P - 39081;

    /// <summary>The base point B (RFC 8032 5.2), in extended coordinates (Z = 1).</summary>
    private static readonly (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Base = BasePoint();

    /// <summary>The neutral point (0 : 1 : 1 : 0).</summary>
    private static readonly (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Neutral = (0, 1, 1, 0);

    /// <summary>
    /// The prepared key's layout, as the library reports it (struct size 21, the last id: 22
    /// answers 0, as any id past the registry does).
    /// </summary>
    [Fact]
    public void HasThePrivateKeysLayout()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(176, sizeof(Ed448PrivateKey));
        Assert.Equal((uint)sizeof(Ed448PrivateKey), Native.StructSize(21));
        Assert.Equal(0u, Native.StructSize(22));
    }

    /// <summary>
    /// RFC 8032 7.4's nine Ed448 vectors (Blank, 1 octet, 1 octet with the context "foo", 11, 12,
    /// 13, 64, 256 and 1023 octets), read from the pinned text: each secret key's public key, from
    /// httpasm_ed448_public_key and inside the prepared key; the signature exactly; its
    /// verification; and a flipped bit of the signature, of the message or of the context refused,
    /// as is the signature under another context (an added one, or the context dropped).
    /// </summary>
    [Fact]
    public void PassesRfc8032sVectors()
    {
        Platform.RequireLinuxX64();
        List<(string Name, byte[] Secret, byte[] Public, byte[] Message, byte[] Context, byte[] Signature)> tests = Rfc8032();
        Assert.Equal(new[] { "Blank", "1 octet", "1 octet (with context)", "11 octets", "12 octets", "13 octets", "64 octets", "256 octets", "1023 octets" }, tests.Select(t => t.Name).ToArray());
        foreach ((string name, byte[] secret, byte[] expectedPublic, byte[] message, byte[] context, byte[] expectedSignature) in tests)
        {
            Assert.True(expectedPublic.SequenceEqual(PublicKey(secret)), $"{name}: public key");
            Ed448PrivateKey key = Prepare(secret);
            Assert.True(expectedPublic.SequenceEqual(new ReadOnlySpan<byte>(key.Public, 57).ToArray()), $"{name}: the prepared key's public key");
            Assert.True(expectedSignature.SequenceEqual(Sign(key, message, context)), $"{name}: signature");
            Assert.True(Verify(expectedPublic, message, context, expectedSignature) == 0, $"{name}: verification");
            byte[] flipped = (byte[])expectedSignature.Clone();
            flipped[17] ^= 0x10;
            Assert.True(Verify(expectedPublic, message, context, flipped) == -1, $"{name}: a flipped signature bit");
            if (message.Length > 0)
            {
                byte[] changed = (byte[])message.Clone();
                changed[^1] ^= 1;
                Assert.True(Verify(expectedPublic, changed, context, expectedSignature) == -1, $"{name}: a changed message");
            }

            byte[] otherContext = context.Length > 0 ? [] : "foo"u8.ToArray();
            Assert.True(Verify(expectedPublic, message, otherContext, expectedSignature) == -1, $"{name}: another context");
            if (context.Length > 0)
            {
                byte[] changedContext = (byte[])context.Clone();
                changedContext[0] ^= 1;
                Assert.True(Verify(expectedPublic, message, changedContext, expectedSignature) == -1, $"{name}: a changed context");
            }
        }
    }

    /// <summary>
    /// Project Wycheproof's Ed448 verifications (ed448_test.json, 87, commit 65ca494, all with an
    /// empty context): the 17 valid ones pass (RFC 8032's among them), the 70 invalid ones fail
    /// (special values of R and S, S of L or more, invalid encodings of R and A, and truncated,
    /// compressed or padded signatures, whose 12 lengths other than 114 this function cannot even
    /// take: each is checked to be invalid, and counted).
    /// </summary>
    [Fact]
    public void PassesWycheproofsTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0, invalid = 0, otherLength = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/ed448_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] key = Convert.FromHexString(group.GetProperty("publicKey").GetProperty("pk").GetString()!);
            byte[] message = Convert.FromHexString(test.GetProperty("msg").GetString()!);
            byte[] signature = Convert.FromHexString(test.GetProperty("sig").GetString()!);
            count++;
            if (signature.Length != 114 || key.Length != 57)
            {
                Assert.True(expected == "invalid", id);
                invalid++;
                otherLength++;
                continue;
            }

            int result = Verify(key, message, [], signature);
            Assert.True(result == (ModelVerify(key, message, [], signature) ? 0 : -1), id + ": the model");
            switch (expected)
            {
                case "valid":
                    Assert.True(result == 0, id);
                    valid++;
                    break;
                default:
                    Assert.Equal("invalid", expected);
                    Assert.True(result == -1, id);
                    invalid++;
                    break;
            }
        }

        Assert.Equal(87, count);
        Assert.Equal(17, valid);
        Assert.Equal(70, invalid);
        Assert.Equal(12, otherLength);
    }

    /// <summary>
    /// Against the BigInteger model on 40 seeds (all zeros, all ones and other patterns first,
    /// then random ones), each with a message and a context whose lengths move SHAKE256's padding
    /// across its 136-octet block (r hashes dom4's 10 octets, the context and the 57-octet prefix
    /// before the message; k the same with R and A, 114 octets): the public key, the prepared key's
    /// three parts (s, the prefix, A), the signature octet for octet, its verification, and the
    /// model's verdict on a signature with one bit flipped.
    /// </summary>
    [Fact]
    public void MatchesABigIntegerModel()
    {
        Platform.RequireLinuxX64();
        var random = new Random(8032);
        int[] lengths = [0, 1, 2, 56, 57, 58, 68, 69, 70, 71, 135, 136, 137, 211, 212, 213, 255, 256, 1000, 4096, 65537];
        int[] contextLengths = [0, 0, 1, 3, 17, 64, 200, 255];
        byte[][] seeds =
        [
            new byte[57],
            Enumerable.Repeat((byte)0xFF, 57).ToArray(),
            [1, .. new byte[56]],
            [.. new byte[56], 0x80],
            Enumerable.Range(0, 57).Select(i => (byte)i).ToArray(),
            Enumerable.Repeat((byte)0x55, 57).ToArray(),
        ];
        for (int i = 0; i < 40; i++)
        {
            byte[] seed = i < seeds.Length ? seeds[i] : RandomBytes(random, 57);
            byte[] message = RandomBytes(random, lengths[i % lengths.Length]);
            byte[] context = RandomBytes(random, contextLengths[i % contextLengths.Length]);
            (BigInteger s, byte[] prefix) = Expand(seed);
            byte[] expectedPublic = Compress(Multiply(s, Base));
            Assert.Equal(Convert.ToHexString(expectedPublic), Convert.ToHexString(PublicKey(seed)));
            Ed448PrivateKey key = Prepare(seed);
            Assert.Equal(s, Limbs(new ReadOnlySpan<byte>(key.Scalar, 56)));
            Assert.Equal(Convert.ToHexString(prefix), Convert.ToHexString(new ReadOnlySpan<byte>(key.Prefix, 57)));
            Assert.Equal(Convert.ToHexString(expectedPublic), Convert.ToHexString(new ReadOnlySpan<byte>(key.Public, 57)));
            Assert.True(new ReadOnlySpan<byte>(key.Pad, 6).IndexOfAnyExcept((byte)0) < 0, "the padding is zeros");
            byte[] signature = Sign(key, message, context);
            Assert.Equal(Convert.ToHexString(ModelSign(seed, message, context)), Convert.ToHexString(signature));
            Assert.Equal(0, Verify(expectedPublic, message, context, signature));
            byte[] flipped = (byte[])signature.Clone();
            flipped[random.Next(114)] ^= (byte)(1 << random.Next(8));
            Assert.Equal(ModelVerify(expectedPublic, message, context, flipped) ? 0 : -1, Verify(expectedPublic, message, context, flipped));
            Assert.Equal(-1, Verify(expectedPublic, message, context, flipped));
        }
    }

    /// <summary>
    /// The verification's S side at its edges, where k cannot be chosen (it is a hash): under the
    /// neutral point as the public key (01 00 .. 00, which RFC 8032 decodes), [k]A is the neutral
    /// point for every k, so R = [S]B makes the equation hold for any S. S = 0, 1, 2, 15, 16, 17,
    /// 31, 32, 33, 2^445, L - 2, L - 1, (L - 1) / 2 and patterns and random ones (the wNAF's digit
    /// edges, zero runs, the longest expansions) each verify, as the model says; S = L, its twin,
    /// does not. The same under the order-2 point (0, -1) and the two order-4 points (1, 0) and
    /// (-1, 0), where [k]A is k's residue's multiple and the model decides each case.
    /// </summary>
    [Fact]
    public void VerifiesByTheCofactorlessEquationAtSsEdges()
    {
        Platform.RequireLinuxX64();
        var random = new Random(448);
        BigInteger[] edges =
        [
            0, 1, 2, 15, 16, 17, 31, 32, 33, BigInteger.One << 445, L - 2, L - 1, (L - 1) / 2,
            ((BigInteger.One << 445) - 1) / 3,                                    // 0101..: alternating digits
            ((BigInteger.One << 445) - 1) / 31 * 15,                              // runs of four ones
            (BigInteger.One << 444) + 1,
        ];
        byte[][] keys =
        [
            [1, .. new byte[56]],                                                 // the neutral point
            Octets(P - 1, 57),                                                    // (0, -1): order 2
            [.. new byte[56], 0x80],                                              // (1, 0): order 4
            new byte[57],                                                         // (-1, 0): order 4
        ];
        int verified = 0;
        foreach (byte[] key in keys)
        {
            for (int i = 0; i < edges.Length + 6; i++)
            {
                BigInteger s = i < edges.Length ? edges[i] : RandomScalar(random);
                byte[] message = RandomBytes(random, i);
                byte[] signature = [.. Compress(Multiply(s, Base)), .. Octets(s, 57)];
                bool model = ModelVerify(key, message, [], signature);
                Assert.True(Verify(key, message, [], signature) == (model ? 0 : -1), $"key {Convert.ToHexString(key)[..8]}, S {s}");
                Assert.True(model || key[0] != 1, "the neutral key takes every S");
                verified += model ? 1 : 0;
                byte[] twin = [.. signature.AsSpan(0, 57), .. Octets(s + L, 57)];    // the same point, S not below L
                Assert.Equal(-1, Verify(key, message, [], twin));
            }
        }

        Assert.True(verified >= edges.Length + 6, $"{verified}");
    }

    /// <summary>
    /// What must be refused, each where a lenient implementation would accept:
    /// - public keys that are no canonical encoding: y of p up to p + 20 and 2^448 - 1 (p + 1
    ///   would be the neutral point, which takes any S, if y were taken modulo p), any of the last
    ///   octet's low seven bits set (bits 448 to 454, outside every y below p), x = 0 with the sign
    ///   bit set (y = 1 and y = p - 1); y values with no x at all;
    /// - S of L or more (L, L + 1, S + L, 2^446, 2^448 - 1, and any octet past S's 56th set);
    /// - R in a non-canonical encoding of the right point: R = (p + 1) for [0]B under the neutral
    ///   key (R is compared octet for octet, never decoded);
    /// - one flipped bit anywhere in a valid signature, the message or the public key.
    /// </summary>
    [Fact]
    public void RefusesInvalidKeysAndSignatures()
    {
        Platform.RequireLinuxX64();
        var random = new Random(8410);
        byte[] seed = RandomBytes(random, 57);
        byte[] publicKey = PublicKey(seed);
        byte[] message = "refuse"u8.ToArray();
        byte[] valid = Sign(Prepare(seed), message, []);
        Assert.Equal(0, Verify(publicKey, message, [], valid));

        // Public keys: non-canonical y (both signs), stray bits in the last octet, x = 0 with the
        // sign bit, y with no x.
        var badKeys = new List<byte[]>();
        for (BigInteger y = P; y <= P + 20; y++)
        {
            badKeys.Add(Octets(y, 57));
            badKeys.Add(Octets(y | (BigInteger.One << 455), 57));
        }

        badKeys.Add(Octets((BigInteger.One << 448) - 1, 57));
        for (int bit = 448; bit < 455; bit++)
        {
            byte[] stray = (byte[])publicKey.Clone();
            stray[56] |= (byte)(1 << (bit - 448));
            badKeys.Add(stray);
        }

        badKeys.Add(Octets(BigInteger.One | (BigInteger.One << 455), 57));
        badKeys.Add(Octets((P - 1) | (BigInteger.One << 455), 57));
        int offCurve = 0;
        for (BigInteger y = 2; offCurve < 8; y++)
        {
            if (RecoverX(y, 0) is null)
            {
                badKeys.Add(Octets(y, 57));
                badKeys.Add(Octets(y | (BigInteger.One << 455), 57));
                offCurve++;
            }
        }

        BigInteger s0 = RandomScalar(random);
        byte[] anySignature = [.. Compress(Multiply(s0, Base)), .. Octets(s0, 57)];
        foreach (byte[] key in badKeys)
        {
            Assert.False(ModelVerify(key, message, [], anySignature));
            Assert.True(Verify(key, message, [], anySignature) == -1, Convert.ToHexString(key));
            Assert.True(Verify(key, message, [], valid) == -1, Convert.ToHexString(key));
        }

        // S of L or more, R intact.
        BigInteger s = Limbs(valid.AsSpan(57));
        foreach (BigInteger bad in new[] { L, L + 1, s + L, BigInteger.One << 446, (BigInteger.One << 448) - 1, s + (BigInteger.One << 448), s + (BigInteger.One << 455) })
        {
            Assert.Equal(-1, Verify(publicKey, message, [], [.. valid.AsSpan(0, 57), .. Octets(bad, 57)]));
        }

        // R non-canonical: (p + 1) is the neutral point's y, [0]B's, under the neutral key.
        byte[] neutralKey = [1, .. new byte[56]];
        Assert.Equal(0, Verify(neutralKey, message, [], [.. Octets(1, 57), .. Octets(0, 57)]));
        Assert.Equal(-1, Verify(neutralKey, message, [], [.. Octets(P + 1, 57), .. Octets(0, 57)]));
        Assert.Equal(-1, Verify(neutralKey, message, [], [.. Octets(BigInteger.One | (BigInteger.One << 455), 57), .. Octets(0, 57)]));

        // One flipped bit: signature, message, public key.
        for (int bit = 0; bit < 912; bit += 3)
        {
            byte[] flipped = (byte[])valid.Clone();
            flipped[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(publicKey, message, [], flipped));
        }

        for (int bit = 0; bit < message.Length * 8; bit++)
        {
            byte[] changed = (byte[])message.Clone();
            changed[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(publicKey, changed, [], valid));
        }

        for (int bit = 0; bit < 456; bit++)
        {
            byte[] otherKey = (byte[])publicKey.Clone();
            otherKey[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(otherKey, message, [], valid));
        }
    }

    /// <summary>
    /// The context: every length up to 255 signs and verifies (dom4 carries its length, so "a"
    /// with message "bc" and "ab" with message "c" differ), and the same message under two
    /// contexts signs differently, each signature verifying under its own only; 256 octets are
    /// refused by both functions, the signature buffer left untouched.
    /// </summary>
    [Fact]
    public void SeparatesContextsAndRefusesLongOnes()
    {
        Platform.RequireLinuxX64();
        var random = new Random(255);
        byte[] seed = RandomBytes(random, 57);
        Ed448PrivateKey key = Prepare(seed);
        byte[] publicKey = PublicKey(seed);
        foreach (int length in new[] { 0, 1, 2, 127, 128, 254, 255 })
        {
            byte[] context = RandomBytes(random, length);
            byte[] signature = Sign(key, "message"u8.ToArray(), context);
            Assert.Equal(Convert.ToHexString(ModelSign(seed, "message"u8.ToArray(), context)), Convert.ToHexString(signature));
            Assert.Equal(0, Verify(publicKey, "message"u8.ToArray(), context, signature));
        }

        byte[] ab = Sign(key, "c"u8.ToArray(), "ab"u8.ToArray());
        byte[] a = Sign(key, "bc"u8.ToArray(), "a"u8.ToArray());
        Assert.NotEqual(Convert.ToHexString(ab), Convert.ToHexString(a));
        Assert.Equal(-1, Verify(publicKey, "bc"u8.ToArray(), "a"u8.ToArray(), ab));
        Assert.Equal(-1, Verify(publicKey, "c"u8.ToArray(), "ab"u8.ToArray(), a));

        byte[] longContext = RandomBytes(random, 256);
        byte[] output = new byte[114];
        output.AsSpan().Fill(0x77);
        fixed (byte* o = output, m = "m"u8, c = longContext)
        {
            Assert.Equal(-1, Native.Ed448Sign(o, &key, m, 1, c, 256));
        }

        Assert.All(output, octet => Assert.Equal(0x77, octet));
        byte[] valid = Sign(key, "m"u8.ToArray(), longContext[..255]);
        Assert.Equal(0, Verify(publicKey, "m"u8.ToArray(), longContext[..255], valid));
        Assert.Equal(-1, Verify(publicKey, "m"u8.ToArray(), longContext, valid));
    }

    /// <summary>
    /// The signature buffer may overlap the message (the function keeps R in its own memory until
    /// both hashes are done): signing in place over the message's first 114 octets, and into a
    /// buffer that starts inside the message, gives the same signature as a separate buffer.
    /// </summary>
    [Fact]
    public void SignsIntoABufferOverTheMessage()
    {
        Platform.RequireLinuxX64();
        var random = new Random(9846);
        byte[] seed = RandomBytes(random, 57);
        Ed448PrivateKey key = Prepare(seed);
        foreach (int length in new[] { 114, 115, 200, 300 })
        {
            byte[] message = RandomBytes(random, length);
            byte[] expected = Sign(key, message, []);
            foreach (int at in new[] { 0, (length - 114) / 2, length - 114 })    // (114 octets from at stay inside)
            {
                byte[] buffer = (byte[])message.Clone();
                fixed (byte* b = buffer)
                {
                    Assert.Equal(0, Native.Ed448Sign(b + at, &key, b, (nuint)length, null, 0));
                }

                Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(buffer.AsSpan(at, 114)));
            }
        }
    }

    /// <summary>
    /// Why httpasm_ed448_sign takes no public key from its caller (the "double public key oracle"):
    /// r = SHAKE256(dom4 || prefix || M) does not depend on A, so one message signed under two
    /// different public keys gives the same R with two different k, and the private scalar falls
    /// out as s = (S1 - S2) / (k1 - k2) mod L. Shown here by planting another key's A in a prepared
    /// key: the recovered scalar equals the key's s modulo L, and it signs a new message that
    /// verifies under the real public key. Only the init writes that field, from the seed itself.
    /// </summary>
    [Fact]
    public void PreparedKeysCarryTheirOwnPublicKey()
    {
        Platform.RequireLinuxX64();
        var random = new Random(1);
        byte[] seed = RandomBytes(random, 57);
        Ed448PrivateKey key = Prepare(seed);
        byte[] publicKey = new ReadOnlySpan<byte>(key.Public, 57).ToArray();
        byte[] message = "one message, two public keys"u8.ToArray();
        byte[] honest = Sign(key, message, []);
        Ed448PrivateKey planted = key;
        byte[] otherKey = PublicKey(RandomBytes(random, 57));
        otherKey.CopyTo(new Span<byte>(planted.Public, 57));
        byte[] tricked = Sign(planted, message, []);
        Assert.Equal(Convert.ToHexString(honest.AsSpan(0, 57)), Convert.ToHexString(tricked.AsSpan(0, 57)));
        BigInteger k1 = HashModL([], honest.AsSpan(0, 57).ToArray(), publicKey, message);
        BigInteger k2 = HashModL([], tricked.AsSpan(0, 57).ToArray(), otherKey, message);
        BigInteger s = Mod((Limbs(honest.AsSpan(57)) - Limbs(tricked.AsSpan(57))) * BigInteger.ModPow(Mod(k1 - k2, L), L - 2, L), L);
        Assert.Equal(Limbs(new ReadOnlySpan<byte>(key.Scalar, 56)) % L, s);

        byte[] forgedMessage = "signed without the seed"u8.ToArray();
        BigInteger r = RandomScalar(random);
        byte[] forgedR = Compress(Multiply(r, Base));
        BigInteger k = HashModL([], forgedR, publicKey, forgedMessage);
        Assert.Equal(0, Verify(publicKey, forgedMessage, [], [.. forgedR, .. Octets((r + k * s) % L, 57)]));
    }

    /// <summary>One httpasm_ed448_public_key call (the output pre-filled with 0xEE).</summary>
    /// <param name="seed">57 octets.</param>
    /// <returns>The 57-octet public key.</returns>
    private static byte[] PublicKey(byte[] seed)
    {
        byte[] output = new byte[57];
        output.AsSpan().Fill(0xEE);
        fixed (byte* o = output, s = seed)
        {
            Native.Ed448PublicKey(o, s);
        }

        return output;
    }

    /// <summary>One httpasm_ed448_private_key_init call (the key pre-filled with 0xEE).</summary>
    /// <param name="seed">57 octets.</param>
    /// <returns>The prepared key.</returns>
    private static Ed448PrivateKey Prepare(byte[] seed)
    {
        Ed448PrivateKey key;
        new Span<byte>(&key, sizeof(Ed448PrivateKey)).Fill(0xEE);
        fixed (byte* s = seed)
        {
            Native.Ed448PrivateKeyInit(&key, s);
        }

        return key;
    }

    /// <summary>One httpasm_ed448_sign call into a separate buffer (pre-filled with 0xEE).</summary>
    /// <param name="key">A prepared key (a copy: the call takes its address).</param>
    /// <param name="message">The message.</param>
    /// <param name="context">The context (at most 255 octets here).</param>
    /// <returns>The 114-octet signature.</returns>
    private static byte[] Sign(Ed448PrivateKey key, byte[] message, byte[] context)
    {
        byte[] output = new byte[114];
        output.AsSpan().Fill(0xEE);
        fixed (byte* o = output, m = message, c = context)
        {
            Assert.Equal(0, Native.Ed448Sign(o, &key, m, (nuint)message.Length, c, (nuint)context.Length));
        }

        return output;
    }

    /// <summary>One httpasm_ed448_verify call.</summary>
    /// <param name="key">57 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="context">The context.</param>
    /// <param name="signature">114 octets.</param>
    /// <returns>0 or -1.</returns>
    private static int Verify(byte[] key, byte[] message, byte[] context, byte[] signature)
    {
        Assert.Equal(57, key.Length);
        Assert.Equal(114, signature.Length);
        fixed (byte* k = key, m = message, c = context, s = signature)
        {
            return Native.Ed448Verify(k, m, (nuint)message.Length, c, (nuint)context.Length, s);
        }
    }

    /// <summary>Random octets from a seeded source.</summary>
    /// <param name="random">The source.</param>
    /// <param name="count">How many.</param>
    /// <returns>The octets.</returns>
    private static byte[] RandomBytes(Random random, int count)
    {
        byte[] octets = new byte[count];
        random.NextBytes(octets);
        return octets;
    }

    /// <summary>A uniform scalar in [0, L).</summary>
    /// <param name="random">The source.</param>
    /// <returns>The scalar.</returns>
    private static BigInteger RandomScalar(Random random) => new BigInteger(RandomBytes(random, 64), isUnsigned: true) % L;

    /// <summary>A little-endian octet string's value (RFC 8032's encodings, S, the key's scalar).</summary>
    /// <param name="octets">The octets.</param>
    /// <returns>The nonnegative integer.</returns>
    private static BigInteger Limbs(ReadOnlySpan<byte> octets) => new(octets, isUnsigned: true, isBigEndian: false);

    /// <summary>A nonnegative integer as <paramref name="count"/> little-endian octets.</summary>
    /// <param name="x">The integer (below 2^(8 count)).</param>
    /// <param name="count">How many octets.</param>
    /// <returns>The octets.</returns>
    private static byte[] Octets(BigInteger x, int count)
    {
        byte[] octets = new byte[count];
        Assert.True(x.Sign >= 0 && x.TryWriteBytes(octets, out _, isUnsigned: true, isBigEndian: false));
        return octets;
    }

    /// <summary>x modulo m in [0, m).</summary>
    /// <param name="x">The value.</param>
    /// <param name="m">The modulus.</param>
    /// <returns>The residue.</returns>
    private static BigInteger Mod(BigInteger x, BigInteger m)
    {
        BigInteger r = x % m;
        return r.Sign < 0 ? r + m : r;
    }

    /// <summary>The base point from RFC 8032 5.2's coordinates.</summary>
    /// <returns>B in extended coordinates (Z = 1).</returns>
    private static (BigInteger, BigInteger, BigInteger, BigInteger) BasePoint()
    {
        BigInteger x = BigInteger.Parse("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710");
        BigInteger y = BigInteger.Parse("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660");
        return (x, y, 1, x * y % P);
    }

    /// <summary>
    /// The model's addition, add-2008-hwcd for a = 1 (A = X1 X2, B = Y1 Y2, C = d T1 T2,
    /// D = Z1 Z2, E = (X1 + Y1)(X2 + Y2) - A - B, F = D - C, G = D + C, H = B - A): complete on
    /// edwards448, so it doubles too.
    /// </summary>
    /// <param name="a">A point.</param>
    /// <param name="b">A point.</param>
    /// <returns>a + b.</returns>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Add((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) a, (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) b)
    {
        BigInteger ma = a.X * b.X % P, mb = a.Y * b.Y % P;
        BigInteger mc = a.T * b.T % P * D % P, md = a.Z * b.Z % P;
        BigInteger e = (a.X + a.Y) * (b.X + b.Y) - ma - mb, f = md - mc, g = md + mc, h = mb - ma;
        return (Mod(e * f, P), Mod(g * h, P), Mod(f * g, P), Mod(e * h, P));
    }

    /// <summary>s q by double-and-add from the low bit.</summary>
    /// <param name="s">A nonnegative scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>s q.</returns>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Multiply(BigInteger s, (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) q)
    {
        (BigInteger, BigInteger, BigInteger, BigInteger) acc = Neutral;
        for (; s > 0; s >>= 1)
        {
            if (!s.IsEven)
            {
                acc = Add(acc, q);
            }

            q = Add(q, q);
        }

        return acc;
    }

    /// <summary>Projective equality: x1 z2 = x2 z1 and y1 z2 = y2 z1.</summary>
    /// <param name="a">A point.</param>
    /// <param name="b">A point.</param>
    /// <returns>Whether they are the same point.</returns>
    private static bool Same((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) a, (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) b)
        => Mod(a.X * b.Z - b.X * a.Z, P).IsZero && Mod(a.Y * b.Z - b.Y * a.Z, P).IsZero;

    /// <summary>
    /// RFC 8032 5.2.3's x from y and the sign bit, or null when there is none: x = u^3 v (u^5
    /// v^3)^((p - 3) / 4) with u = y^2 - 1, v = d y^2 - 1, kept only when v x^2 = u.
    /// </summary>
    /// <param name="y">y (refused from p up).</param>
    /// <param name="sign">x's wanted parity.</param>
    /// <returns>x, or null: y not below p, no root, or x = 0 with sign 1.</returns>
    private static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y >= P)
        {
            return null;
        }

        BigInteger u = Mod(y * y - 1, P), v = Mod(D * y * y - 1, P);
        BigInteger x = u * u % P * u % P * v % P * BigInteger.ModPow(BigInteger.ModPow(u, 5, P) * BigInteger.ModPow(v, 3, P) % P, (P - 3) / 4, P) % P;
        if (!Mod(v * x * x - u, P).IsZero)
        {
            return null;
        }

        if (x.IsZero && sign == 1)
        {
            return null;
        }

        return (int)(x & 1) == sign ? x : Mod(-x, P);
    }

    /// <summary>RFC 8032 5.2.2's encoding: y with x's parity in bit 455.</summary>
    /// <param name="q">The point.</param>
    /// <returns>57 octets.</returns>
    private static byte[] Compress((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) q)
    {
        BigInteger zi = BigInteger.ModPow(q.Z, P - 2, P);
        BigInteger x = q.X * zi % P, y = q.Y * zi % P;
        return Octets(y | ((x & 1) << 455), 57);
    }

    /// <summary>RFC 8032 5.2.3's decoding.</summary>
    /// <param name="octets">57 octets.</param>
    /// <returns>The point, or null when refused.</returns>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T)? Decompress(byte[] octets)
    {
        BigInteger y = Limbs(octets);
        int sign = (int)(y >> 455);
        y &= (BigInteger.One << 455) - 1;
        return RecoverX(y, sign) is BigInteger x ? (x, y, 1, x * y % P) : null;
    }

    /// <summary>RFC 8032 5.2.5's expansion: s (clamped) and the prefix from SHAKE256(seed, 114).</summary>
    /// <param name="seed">57 octets.</param>
    /// <returns>(s, prefix).</returns>
    private static (BigInteger S, byte[] Prefix) Expand(byte[] seed)
    {
        byte[] h = Shake256.HashData(seed, 114);
        byte[] a = h[..57];
        a[0] &= 0xFC;
        a[56] = 0;
        a[55] |= 0x80;
        return (Limbs(a), h[57..]);
    }

    /// <summary>SHAKE256(dom4(0, context) || parts, 114), read little-endian, modulo L.</summary>
    /// <param name="context">The context.</param>
    /// <param name="parts">The hashed octet strings, in order.</param>
    /// <returns>The scalar.</returns>
    private static BigInteger HashModL(byte[] context, params byte[][] parts)
    {
        byte[] dom4 = [.. "SigEd448"u8, 0, (byte)context.Length, .. context];
        return Limbs(Shake256.HashData([.. dom4, .. parts.SelectMany(p => p)], 114)) % L;
    }

    /// <summary>RFC 8032 5.2.6's signature: r = H(dom4 || prefix || M), R = r B, k = H(dom4 || R || A || M), S = r + k s.</summary>
    /// <param name="seed">57 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="context">The context.</param>
    /// <returns>R || S.</returns>
    private static byte[] ModelSign(byte[] seed, byte[] message, byte[] context)
    {
        (BigInteger s, byte[] prefix) = Expand(seed);
        byte[] publicKey = Compress(Multiply(s, Base));
        BigInteger r = HashModL(context, prefix, message);
        byte[] rEncoded = Compress(Multiply(r, Base));
        BigInteger k = HashModL(context, rEncoded, publicKey, message);
        return [.. rEncoded, .. Octets((r + k * s) % L, 57)];
    }

    /// <summary>
    /// RFC 8032 5.2.7's verification: A and R decoded (refused as <see cref="RecoverX"/> refuses),
    /// S below L, then [S]B = R + [k]A as points (cofactorless).
    /// </summary>
    /// <param name="publicKey">57 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="context">The context.</param>
    /// <param name="signature">114 octets.</param>
    /// <returns>Whether the signature is valid.</returns>
    private static bool ModelVerify(byte[] publicKey, byte[] message, byte[] context, byte[] signature)
    {
        if (context.Length > 255 || Decompress(publicKey) is not { } a || Decompress(signature[..57]) is not { } r)
        {
            return false;
        }

        BigInteger s = Limbs(signature.AsSpan(57));
        if (s >= L)
        {
            return false;
        }

        BigInteger k = HashModL(context, signature[..57], publicKey, message);
        return Same(Multiply(s, Base), Add(r, Multiply(k, a)));
    }

    /// <summary>
    /// RFC 8032 7.4 from the pinned text (specs/rfc/rfc8032.txt): each "-----name" block's SECRET
    /// KEY, PUBLIC KEY, MESSAGE (its stated length checked), CONTEXT (when present) and SIGNATURE,
    /// every value hex on indented lines under its heading; page breaks match no hex line.
    /// </summary>
    /// <returns>The nine tests, in the RFC's order.</returns>
    /// <exception cref="InvalidDataException">The section was not found, or a message's length
    /// differs from its heading's.</exception>
    private static List<(string Name, byte[] Secret, byte[] Public, byte[] Message, byte[] Context, byte[] Signature)> Rfc8032()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc8032.txt"));
        int start = Array.FindIndex(lines, l => l.StartsWith("7.4.  Test Vectors for Ed448", StringComparison.Ordinal));
        int end = start < 0 ? -1 : Array.FindIndex(lines, start + 1, l => l.StartsWith("7.5.", StringComparison.Ordinal));
        if (end < 0)
        {
            throw new InvalidDataException("RFC 8032's 7.4 was not found in the pinned text");
        }

        var tests = new List<(string, byte[], byte[], byte[], byte[], byte[])>();
        string? name = null, field = null;
        int length = -1;
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = start; i <= end; i++)
        {
            string line = i < end ? lines[i] : "   -----";
            Match m;
            if (line.StartsWith("   -----", StringComparison.Ordinal))
            {
                if (name is not null)
                {
                    byte[] message = Convert.FromHexString(fields.GetValueOrDefault("MESSAGE", ""));
                    if (message.Length != length)
                    {
                        throw new InvalidDataException($"RFC 8032 {name}: {message.Length} message octets, {length} stated");
                    }

                    tests.Add((name, Convert.FromHexString(fields["SECRET KEY"]), Convert.FromHexString(fields["PUBLIC KEY"]), message,
                        Convert.FromHexString(fields.GetValueOrDefault("CONTEXT", "")), Convert.FromHexString(fields["SIGNATURE"])));
                }

                name = line.Length > 8 ? line["   -----".Length..] : null;
                fields.Clear();
                field = null;
            }
            else if ((m = MessageHeading().Match(line)).Success)
            {
                field = "MESSAGE";
                length = int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
            }
            else if ((m = FieldHeading().Match(line)).Success)
            {
                field = m.Groups[1].Value;
            }
            else if (field is not null && (m = HexLine().Match(line)).Success)
            {
                fields[field] = fields.GetValueOrDefault(field, "") + m.Groups[1].Value;
            }
        }

        return tests;
    }

    /// <summary>A value's heading: "   SECRET KEY:", "   PUBLIC KEY:", "   CONTEXT:", "   SIGNATURE:", "   ALGORITHM:".</summary>
    /// <returns>The pattern (the field's name).</returns>
    [GeneratedRegex("^   ([A-Z][A-Z ]+):$")]
    private static partial Regex FieldHeading();

    /// <summary>The message's heading: "   MESSAGE (length 1023 bytes):" (or "1 byte").</summary>
    /// <returns>The pattern (the length).</returns>
    [GeneratedRegex(@"^   MESSAGE \(length ([0-9]+) bytes?\):$")]
    private static partial Regex MessageHeading();

    /// <summary>A line of a value: lowercase hex digits, indented three spaces.</summary>
    /// <returns>The pattern (the digits).</returns>
    [GeneratedRegex("^   ([0-9a-f]+)$")]
    private static partial Regex HexLine();
}
