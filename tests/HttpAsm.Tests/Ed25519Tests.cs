using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_ed25519_public_key, httpasm_ed25519_private_key_init, httpasm_ed25519_sign and
/// httpasm_ed25519_verify (RFC 8032 5.1, pure Ed25519) through the C ABI, held to RFC 8032 7.1's
/// five test vectors (read from the pinned text), Project Wycheproof's 210 verifications, and a
/// BigInteger model of RFC 8032 5.1 (section 6's Python, in C#) on random and edge seeds, message
/// lengths and signatures. Verification is held to the model's cofactorless equation everywhere,
/// the small- and mixed-order public keys included. tests/run-linux.sh runs the suite at every
/// CPU tier, so both versions answer: v3 (mulx with adcx/adox, AVX2 table scans) and v1 (mul on
/// 51-bit limbs, SSE2). .NET has no Ed25519 of its own: the model is the second implementation
/// (a scratch run against Python's cryptography package agreed octet for octet at both tiers).
/// </summary>
public sealed unsafe partial class Ed25519Tests
{
    /// <summary>The field's prime p = 2^255 - 19.</summary>
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;

    /// <summary>L, the prime order of the base point: 2^252 + 27742317777372353535851937790883648493.</summary>
    private static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    /// <summary>The curve's d = -121665 / 121666 modulo p.</summary>
    private static readonly BigInteger D = Mod(-121665 * BigInteger.ModPow(121666, P - 2, P), P);

    /// <summary>sqrt(-1) = 2^((p - 1) / 4) modulo p (RFC 8032 5.1.3's fix for the other root).</summary>
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

    /// <summary>The base point B: y = 4/5, x even (RFC 8032 5.1).</summary>
    private static readonly (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Base = BasePoint();

    /// <summary>The neutral point (0 : 1 : 1 : 0).</summary>
    private static readonly (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Neutral = (0, 1, 1, 0);

    /// <summary>The prepared key's layout, as the library reports it (struct size 19).</summary>
    [Fact]
    public void HasThePrivateKeysLayout()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(96, sizeof(Ed25519PrivateKey));
        Assert.Equal((uint)sizeof(Ed25519PrivateKey), Native.StructSize(19));
        Assert.Equal(0u, Native.StructSize(20));
    }

    /// <summary>
    /// RFC 8032 7.1's five Ed25519 vectors (TEST 1, 2, 3, 1024 and SHA(abc)), read from the pinned
    /// text: each secret key's public key, from httpasm_ed25519_public_key and inside the prepared
    /// key; the signature exactly; its verification; and a flipped bit of the message or of the
    /// signature refused.
    /// </summary>
    [Fact]
    public void PassesRfc8032sVectors()
    {
        Platform.RequireLinuxX64();
        List<(string Name, byte[] Secret, byte[] Public, byte[] Message, byte[] Signature)> tests = Rfc8032();
        Assert.Equal(new[] { "1", "2", "3", "1024", "SHA(abc)" }, tests.Select(t => t.Name).ToArray());
        foreach ((string name, byte[] secret, byte[] expectedPublic, byte[] message, byte[] expectedSignature) in tests)
        {
            Assert.True(expectedPublic.SequenceEqual(PublicKey(secret)), $"TEST {name}: public key");
            Ed25519PrivateKey key = Prepare(secret);
            Assert.True(expectedPublic.SequenceEqual(new ReadOnlySpan<byte>(key.Public, 32).ToArray()), $"TEST {name}: the prepared key's public key");
            Assert.True(expectedSignature.SequenceEqual(Sign(key, message)), $"TEST {name}: signature");
            Assert.True(Verify(expectedPublic, message, expectedSignature) == 0, $"TEST {name}: verification");
            byte[] flipped = (byte[])expectedSignature.Clone();
            flipped[17] ^= 0x10;
            Assert.True(Verify(expectedPublic, message, flipped) == -1, $"TEST {name}: a flipped signature bit");
            if (message.Length > 0)
            {
                byte[] changed = (byte[])message.Clone();
                changed[^1] ^= 1;
                Assert.True(Verify(expectedPublic, changed, expectedSignature) == -1, $"TEST {name}: a changed message");
            }
        }
    }

    /// <summary>
    /// Project Wycheproof's Ed25519 verifications (ed25519_test.json, 210, commit 65ca494): the 117
    /// valid ones pass (RFC 8032's, Tink's arithmetic-overflow cases among them), the 64 invalid
    /// ones fail (S of L or more, non-canonical or invalid encodings of R and A, truncated,
    /// compressed or padded signatures, whose lengths other than 64 this function cannot even take,
    /// and sodium_compat's mixed-order regression), and the 29 "acceptable" ones (small- and
    /// mixed-order public keys: either policy may take them) get the model's cofactorless answer,
    /// which accepts every one of them.
    /// </summary>
    [Fact]
    public void PassesWycheproofsTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0, invalid = 0, acceptable = 0, accepted = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/ed25519_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] key = Convert.FromHexString(group.GetProperty("publicKey").GetProperty("pk").GetString()!);
            byte[] message = Convert.FromHexString(test.GetProperty("msg").GetString()!);
            byte[] signature = Convert.FromHexString(test.GetProperty("sig").GetString()!);
            count++;
            if (signature.Length != 64 || key.Length != 32)
            {
                Assert.True(expected == "invalid", id);
                invalid++;
                continue;
            }

            int result = Verify(key, message, signature);
            switch (expected)
            {
                case "valid":
                    Assert.True(result == 0, id);
                    valid++;
                    break;
                case "invalid":
                    Assert.True(result == -1, id);
                    invalid++;
                    break;
                default:
                    Assert.Equal("acceptable", expected);
                    bool model = ModelVerify(key, message, signature);
                    Assert.True(result == (model ? 0 : -1), id);
                    acceptable++;
                    accepted += model ? 1 : 0;
                    break;
            }
        }

        Assert.Equal(210, count);
        Assert.Equal(117, valid);
        Assert.Equal(64, invalid);
        Assert.Equal(29, acceptable);
        Assert.Equal(29, accepted);
    }

    /// <summary>
    /// Against the BigInteger model on 120 seeds (all zeros, all ones and other patterns first,
    /// then random ones), each with a message of a length that moves SHA-512's padding across a
    /// block (r hashes 32 octets of prefix before the message, k 64 of R and A: lengths 47, 48, 79,
    /// 80, 111, 112, 127, 128 and their neighbours, up to 1 MiB): the public key, the prepared key's
    /// three parts (a mod L, the prefix, A), the signature octet for octet, its verification, and
    /// the model's verdict on a signature with one bit flipped.
    /// </summary>
    [Fact]
    public void MatchesABigIntegerModel()
    {
        Platform.RequireLinuxX64();
        var random = new Random(8032);
        int[] lengths = [0, 1, 2, 31, 32, 33, 46, 47, 48, 49, 63, 64, 65, 78, 79, 80, 81, 95, 96, 110, 111, 112, 113, 127, 128, 129, 255, 256, 1000, 4096, 65537, 1 << 20];
        byte[][] seeds =
        [
            new byte[32],
            Enumerable.Repeat((byte)0xFF, 32).ToArray(),
            [1, .. new byte[31]],
            [.. new byte[31], 0x80],
            Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
            Enumerable.Repeat((byte)0x55, 32).ToArray(),
        ];
        for (int i = 0; i < 120; i++)
        {
            byte[] seed = i < seeds.Length ? seeds[i] : RandomBytes(random, 32);
            byte[] message = RandomBytes(random, lengths[i % lengths.Length]);
            (BigInteger a, byte[] prefix) = Expand(seed);
            byte[] expectedPublic = Compress(Multiply(a, Base));
            Assert.Equal(Convert.ToHexString(expectedPublic), Convert.ToHexString(PublicKey(seed)));
            Ed25519PrivateKey key = Prepare(seed);
            Assert.Equal(a % L, Limbs(key.Scalar));
            Assert.Equal(Convert.ToHexString(prefix), Convert.ToHexString(new ReadOnlySpan<byte>(key.Prefix, 32)));
            Assert.Equal(Convert.ToHexString(expectedPublic), Convert.ToHexString(new ReadOnlySpan<byte>(key.Public, 32)));
            byte[] signature = Sign(key, message);
            Assert.Equal(Convert.ToHexString(ModelSign(seed, message)), Convert.ToHexString(signature));
            Assert.Equal(0, Verify(expectedPublic, message, signature));
            byte[] flipped = (byte[])signature.Clone();
            flipped[random.Next(64)] ^= (byte)(1 << random.Next(8));
            Assert.Equal(ModelVerify(expectedPublic, message, flipped) ? 0 : -1, Verify(expectedPublic, message, flipped));
            Assert.Equal(-1, Verify(expectedPublic, message, flipped));
        }
    }

    /// <summary>
    /// The verification's S side at its edges, where k cannot be chosen (it is a hash): under the
    /// neutral point as the public key (01 00 .. 00, which RFC 8032 decodes; Wycheproof's
    /// "universal forgery" case), [k]A is the neutral point for every k, so R = [S]B makes the
    /// equation hold for any S. S = 0, 1, 2, 3, 31, 32, 33, 63, 64, 65, 2^252 - 1, 2^252, L - 2,
    /// L - 1, (L - 1) / 2 and random ones (S's width-6 digits at both ends of the table window,
    /// zero runs, the longest NAF) each verify, as the model says; S = L, its twin, does not. The
    /// same under the order-2 point (0, -1) and the two order-4 points (sqrt(-1), 0) and
    /// (-sqrt(-1), 0), where [k]A is k's residue's multiple and the model decides each case.
    /// </summary>
    [Fact]
    public void VerifiesByTheCofactorlessEquationAtSsEdges()
    {
        Platform.RequireLinuxX64();
        var random = new Random(25519);
        BigInteger[] edges =
        [
            0, 1, 2, 3, 31, 32, 33, 63, 64, 65, (BigInteger.One << 252) - 1, BigInteger.One << 252, L - 2, L - 1, (L - 1) / 2,
            Hex("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") % L,
            Hex("0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Hex("0842108421084210842108421084210842108421084210842108421084210842"),
        ];
        byte[][] keys =
        [
            [1, .. new byte[31]],                                                       // the neutral point
            [0xEC, .. Enumerable.Repeat((byte)0xFF, 30), 0x7F],                         // (0, -1): order 2
            new byte[32],                                                               // (sqrt(-1), 0): order 4
            [.. new byte[31], 0x80],                                                    // (-sqrt(-1), 0)
        ];
        int verified = 0;
        foreach (byte[] key in keys)
        {
            for (int i = 0; i < edges.Length + 12; i++)
            {
                BigInteger s = i < edges.Length ? edges[i] : RandomScalar(random);
                byte[] message = RandomBytes(random, i);
                byte[] signature = [.. Compress(Multiply(s, Base)), .. Octets(s)];
                bool model = ModelVerify(key, message, signature);
                Assert.True(Verify(key, message, signature) == (model ? 0 : -1), $"key {Convert.ToHexString(key)[..8]}, S {s}");
                Assert.True(model || key[0] != 1, "the neutral key takes every S");
                verified += model ? 1 : 0;
                byte[] twin = [.. signature.AsSpan(0, 32), .. Octets(s + L)];     // the same point, S not below L
                Assert.Equal(-1, Verify(key, message, twin));
            }
        }

        Assert.True(verified >= edges.Length + 12, $"{verified}");
    }

    /// <summary>
    /// What must be refused, each where a lenient implementation would accept:
    /// - public keys that are no canonical encoding: y of p up to 2^255 - 1 (p + 1 would be the
    ///   neutral point, which takes any S, if y were taken modulo p), and x = 0 with the sign bit
    ///   set (y = 1 and y = p - 1); y values with no x at all;
    /// - S of L or more (L, L + 1, S + L, 2^255 + S, 2^256 - 1), the signature's other half intact;
    /// - R in a non-canonical encoding of the right point: R = (p + 1) for [0]B under the neutral
    ///   key (R is compared octet for octet, never decoded);
    /// - one flipped bit anywhere in a valid signature, the message or the public key.
    /// </summary>
    [Fact]
    public void RefusesInvalidKeysAndSignatures()
    {
        Platform.RequireLinuxX64();
        var random = new Random(8410);
        byte[] seed = RandomBytes(random, 32);
        byte[] publicKey = PublicKey(seed);
        byte[] message = "refuse"u8.ToArray();
        byte[] valid = Sign(Prepare(seed), message);
        Assert.Equal(0, Verify(publicKey, message, valid));

        // Public keys: non-canonical y (both signs), x = 0 with the sign bit, y with no x.
        var badKeys = new List<byte[]>();
        for (BigInteger y = P; y < BigInteger.One << 255; y++)
        {
            badKeys.Add(Octets(y));
            badKeys.Add(Octets(y | (BigInteger.One << 255)));
        }

        badKeys.Add(Octets(BigInteger.One | (BigInteger.One << 255)));
        badKeys.Add(Octets((P - 1) | (BigInteger.One << 255)));
        int offCurve = 0;
        for (BigInteger y = 2; offCurve < 8; y++)
        {
            if (RecoverX(y, 0) is null)
            {
                badKeys.Add(Octets(y));
                badKeys.Add(Octets(y | (BigInteger.One << 255)));
                offCurve++;
            }
        }

        BigInteger s0 = RandomScalar(random);
        byte[] anySignature = [.. Compress(Multiply(s0, Base)), .. Octets(s0)];
        foreach (byte[] key in badKeys)
        {
            Assert.False(ModelVerify(key, message, anySignature));
            Assert.True(Verify(key, message, anySignature) == -1, Convert.ToHexString(key));
            Assert.True(Verify(key, message, valid) == -1, Convert.ToHexString(key));
        }

        // S of L or more, R intact.
        BigInteger s = Limbs(valid.AsSpan(32));
        foreach (BigInteger bad in new[] { L, L + 1, s + L, s + (BigInteger.One << 255), (BigInteger.One << 256) - 1 })
        {
            Assert.Equal(-1, Verify(publicKey, message, [.. valid.AsSpan(0, 32), .. Octets(bad)]));
        }

        // R non-canonical: (p + 1) is the neutral point's y, [0]B's, under the neutral key.
        byte[] neutralKey = [1, .. new byte[31]];
        Assert.Equal(0, Verify(neutralKey, message, [.. Octets(1), .. Octets(0)]));
        Assert.Equal(-1, Verify(neutralKey, message, [.. Octets(P + 1), .. Octets(0)]));
        Assert.Equal(-1, Verify(neutralKey, message, [.. Octets(BigInteger.One | (BigInteger.One << 255)), .. Octets(0)]));

        // One flipped bit: signature, message, public key.
        for (int bit = 0; bit < 512; bit += 3)
        {
            byte[] flipped = (byte[])valid.Clone();
            flipped[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(publicKey, message, flipped));
        }

        for (int bit = 0; bit < message.Length * 8; bit++)
        {
            byte[] changed = (byte[])message.Clone();
            changed[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(publicKey, changed, valid));
        }

        for (int bit = 0; bit < 256; bit++)
        {
            byte[] otherKey = (byte[])publicKey.Clone();
            otherKey[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(otherKey, message, valid));
        }
    }

    /// <summary>
    /// The signature buffer may overlap the message (the function keeps R in its own memory until
    /// both hashes are done): signing in place over the message's first 64 octets, and into a
    /// buffer that starts inside the message, gives the same signature as a separate buffer.
    /// </summary>
    [Fact]
    public void SignsIntoABufferOverTheMessage()
    {
        Platform.RequireLinuxX64();
        var random = new Random(9846);
        byte[] seed = RandomBytes(random, 32);
        Ed25519PrivateKey key = Prepare(seed);
        foreach (int length in new[] { 64, 65, 100, 200 })
        {
            byte[] message = RandomBytes(random, length);
            byte[] expected = Sign(key, message);
            foreach (int at in new[] { 0, (length - 64) / 2, length - 64 })    // (64 octets from at stay inside)
            {
                byte[] buffer = (byte[])message.Clone();
                fixed (byte* b = buffer)
                {
                    Native.Ed25519Sign(b + at, &key, b, (nuint)length);
                }

                Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(buffer.AsSpan(at, 64)));
            }
        }
    }

    /// <summary>
    /// Why httpasm_ed25519_sign takes no public key from its caller (the "double public key
    /// oracle"): r = SHA-512(prefix || M) does not depend on A, so one message signed under two
    /// different public keys gives the same R with two different k, and the private scalar falls
    /// out as a = (S1 - S2) / (k1 - k2) mod L. Shown here by planting another key's A in a
    /// prepared key: the recovered a equals the key's scalar, and it signs a new message that
    /// verifies under the real public key. Only the init writes that field, from the seed itself.
    /// </summary>
    [Fact]
    public void PreparedKeysCarryTheirOwnPublicKey()
    {
        Platform.RequireLinuxX64();
        var random = new Random(1);
        byte[] seed = RandomBytes(random, 32);
        Ed25519PrivateKey key = Prepare(seed);
        byte[] publicKey = new ReadOnlySpan<byte>(key.Public, 32).ToArray();
        byte[] message = "one message, two public keys"u8.ToArray();
        byte[] honest = Sign(key, message);
        Ed25519PrivateKey planted = key;
        byte[] otherKey = PublicKey(RandomBytes(random, 32));
        otherKey.CopyTo(new Span<byte>(planted.Public, 32));
        byte[] tricked = Sign(planted, message);
        Assert.Equal(Convert.ToHexString(honest.AsSpan(0, 32)), Convert.ToHexString(tricked.AsSpan(0, 32)));
        BigInteger k1 = HashModL(honest.AsSpan(0, 32).ToArray(), publicKey, message);
        BigInteger k2 = HashModL(tricked.AsSpan(0, 32).ToArray(), otherKey, message);
        BigInteger a = Mod((Limbs(honest.AsSpan(32)) - Limbs(tricked.AsSpan(32))) * BigInteger.ModPow(Mod(k1 - k2, L), L - 2, L), L);
        Assert.Equal(Limbs(key.Scalar), a);

        byte[] forgedMessage = "signed without the seed"u8.ToArray();
        BigInteger r = RandomScalar(random);
        byte[] forgedR = Compress(Multiply(r, Base));
        BigInteger k = HashModL(forgedR, publicKey, forgedMessage);
        Assert.Equal(0, Verify(publicKey, forgedMessage, [.. forgedR, .. Octets((r + k * a) % L)]));
    }

    /// <summary>One httpasm_ed25519_public_key call (the output pre-filled with 0xEE).</summary>
    /// <param name="seed">32 octets.</param>
    /// <returns>The 32-octet public key.</returns>
    private static byte[] PublicKey(byte[] seed)
    {
        byte[] output = new byte[32];
        output.AsSpan().Fill(0xEE);
        fixed (byte* o = output, s = seed)
        {
            Native.Ed25519PublicKey(o, s);
        }

        return output;
    }

    /// <summary>One httpasm_ed25519_private_key_init call (the key pre-filled with 0xEE).</summary>
    /// <param name="seed">32 octets.</param>
    /// <returns>The prepared key.</returns>
    private static Ed25519PrivateKey Prepare(byte[] seed)
    {
        Ed25519PrivateKey key;
        new Span<byte>(&key, sizeof(Ed25519PrivateKey)).Fill(0xEE);
        fixed (byte* s = seed)
        {
            Native.Ed25519PrivateKeyInit(&key, s);
        }

        return key;
    }

    /// <summary>One httpasm_ed25519_sign call into a separate buffer (pre-filled with 0xEE).</summary>
    /// <param name="key">A prepared key (a copy: the call takes its address).</param>
    /// <param name="message">The message.</param>
    /// <returns>The 64-octet signature.</returns>
    private static byte[] Sign(Ed25519PrivateKey key, byte[] message)
    {
        byte[] output = new byte[64];
        output.AsSpan().Fill(0xEE);
        fixed (byte* o = output, m = message)
        {
            Native.Ed25519Sign(o, &key, m, (nuint)message.Length);
        }

        return output;
    }

    /// <summary>One httpasm_ed25519_verify call.</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="signature">64 octets.</param>
    /// <returns>0 or -1.</returns>
    private static int Verify(byte[] key, byte[] message, byte[] signature)
    {
        Assert.Equal(32, key.Length);
        Assert.Equal(64, signature.Length);
        fixed (byte* k = key, m = message, s = signature)
        {
            return Native.Ed25519Verify(k, m, (nuint)message.Length, s);
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
    private static BigInteger RandomScalar(Random random) => new BigInteger(RandomBytes(random, 40), isUnsigned: true) % L;

    /// <summary>A big-endian hexadecimal integer (any count of digits: an odd count gets a leading zero).</summary>
    /// <param name="hex">The digits.</param>
    /// <returns>The nonnegative integer.</returns>
    private static BigInteger Hex(string hex) => new(Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex), isUnsigned: true, isBigEndian: true);

    /// <summary>A little-endian octet string's value (RFC 8032's encodings and S).</summary>
    /// <param name="octets">The octets.</param>
    /// <returns>The nonnegative integer.</returns>
    private static BigInteger Limbs(ReadOnlySpan<byte> octets) => new(octets, isUnsigned: true, isBigEndian: false);

    /// <summary>The prepared key's scalar: four little-endian 64-bit limbs.</summary>
    /// <param name="limbs">The key's Scalar field.</param>
    /// <returns>Its value.</returns>
    private static BigInteger Limbs(ulong* limbs) => Limbs(new ReadOnlySpan<byte>(limbs, 32));

    /// <summary>A nonnegative integer below 2^256 as 32 little-endian octets.</summary>
    /// <param name="x">The integer.</param>
    /// <returns>32 octets.</returns>
    private static byte[] Octets(BigInteger x)
    {
        byte[] octets = new byte[32];
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

    /// <summary>The base point from y = 4/5 and x even.</summary>
    /// <returns>B in extended coordinates (Z = 1).</returns>
    /// <exception cref="InvalidOperationException">y = 4/5 had no x (never: the curve's constants are right).</exception>
    private static (BigInteger, BigInteger, BigInteger, BigInteger) BasePoint()
    {
        BigInteger y = Mod(4 * BigInteger.ModPow(5, P - 2, P), P);
        BigInteger x = RecoverX(y, 0) ?? throw new InvalidOperationException("B's x");
        return (x, y, 1, x * y % P);
    }

    /// <summary>
    /// The model's addition, RFC 8032 6's point_add (add-2008-hwcd-3 for a = -1): complete on
    /// edwards25519, so it doubles too.
    /// </summary>
    /// <param name="a">A point.</param>
    /// <param name="b">A point.</param>
    /// <returns>a + b.</returns>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) Add((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) a, (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) b)
    {
        BigInteger ma = Mod((a.Y - a.X) * (b.Y - b.X), P);
        BigInteger mb = Mod((a.Y + a.X) * (b.Y + b.X), P);
        BigInteger mc = 2 * a.T * b.T % P * D % P;
        BigInteger md = 2 * a.Z * b.Z % P;
        BigInteger e = mb - ma, f = md - mc, g = md + mc, h = mb + ma;
        return (Mod(e * f, P), Mod(g * h, P), Mod(f * g, P), Mod(e * h, P));
    }

    /// <summary>s q by double-and-add from the low bit (RFC 8032 6's point_mul).</summary>
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

    /// <summary>RFC 8032 5.1.3's x from y and the sign bit, or null when there is none.</summary>
    /// <param name="y">y (refused from p up).</param>
    /// <param name="sign">x's wanted parity.</param>
    /// <returns>x, or null: y not below p, x^2 not a square, or x = 0 with sign 1.</returns>
    private static BigInteger? RecoverX(BigInteger y, int sign)
    {
        if (y >= P)
        {
            return null;
        }

        BigInteger x2 = Mod((y * y - 1) * BigInteger.ModPow(Mod(D * y * y + 1, P), P - 2, P), P);
        if (x2.IsZero)
        {
            return sign == 0 ? BigInteger.Zero : null;
        }

        BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (!Mod(x * x - x2, P).IsZero)
        {
            x = x * SqrtM1 % P;
        }

        if (!Mod(x * x - x2, P).IsZero)
        {
            return null;
        }

        return (int)(x & 1) == sign ? x : P - x;
    }

    /// <summary>RFC 8032 5.1.2's encoding: y with x's parity in bit 255.</summary>
    /// <param name="q">The point.</param>
    /// <returns>32 octets.</returns>
    private static byte[] Compress((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) q)
    {
        BigInteger zi = BigInteger.ModPow(q.Z, P - 2, P);
        BigInteger x = q.X * zi % P, y = q.Y * zi % P;
        return Octets(y | ((x & 1) << 255));
    }

    /// <summary>RFC 8032 5.1.3's decoding.</summary>
    /// <param name="octets">32 octets.</param>
    /// <returns>The point, or null when refused.</returns>
    private static (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T)? Decompress(byte[] octets)
    {
        BigInteger y = Limbs(octets);
        int sign = (int)(y >> 255);
        y &= (BigInteger.One << 255) - 1;
        return RecoverX(y, sign) is BigInteger x ? (x, y, 1, x * y % P) : null;
    }

    /// <summary>RFC 8032 5.1.5's expansion: a (clamped) and the prefix from SHA-512(seed).</summary>
    /// <param name="seed">32 octets.</param>
    /// <returns>(a, prefix).</returns>
    private static (BigInteger A, byte[] Prefix) Expand(byte[] seed)
    {
        byte[] h = SHA512.HashData(seed);
        BigInteger a = Limbs(h.AsSpan(0, 32));
        a &= (BigInteger.One << 254) - 8;
        a |= BigInteger.One << 254;
        return (a, h[32..]);
    }

    /// <summary>SHA-512 of the parts' concatenation, read little-endian, modulo L.</summary>
    /// <param name="parts">The hashed octet strings, in order.</param>
    /// <returns>The scalar.</returns>
    private static BigInteger HashModL(params byte[][] parts) => Limbs(SHA512.HashData(parts.SelectMany(p => p).ToArray())) % L;

    /// <summary>RFC 8032 5.1.6's signature: r = H(prefix || M), R = r B, k = H(R || A || M), S = r + k a.</summary>
    /// <param name="seed">32 octets.</param>
    /// <param name="message">The message.</param>
    /// <returns>R || S.</returns>
    private static byte[] ModelSign(byte[] seed, byte[] message)
    {
        (BigInteger a, byte[] prefix) = Expand(seed);
        byte[] publicKey = Compress(Multiply(a, Base));
        BigInteger r = HashModL(prefix, message);
        byte[] rEncoded = Compress(Multiply(r, Base));
        BigInteger k = HashModL(rEncoded, publicKey, message);
        return [.. rEncoded, .. Octets((r + k * a) % L)];
    }

    /// <summary>
    /// RFC 8032 5.1.7's verification as section 6's code does it: A and R decoded (refused as
    /// <see cref="RecoverX"/> refuses), S below L, then [S]B = R + [k]A as points (cofactorless).
    /// </summary>
    /// <param name="publicKey">32 octets.</param>
    /// <param name="message">The message.</param>
    /// <param name="signature">64 octets.</param>
    /// <returns>Whether the signature is valid.</returns>
    private static bool ModelVerify(byte[] publicKey, byte[] message, byte[] signature)
    {
        if (Decompress(publicKey) is not { } a || Decompress(signature[..32]) is not { } r)
        {
            return false;
        }

        BigInteger s = Limbs(signature.AsSpan(32));
        if (s >= L)
        {
            return false;
        }

        BigInteger k = HashModL(signature[..32], publicKey, message);
        return Same(Multiply(s, Base), Add(r, Multiply(k, a)));
    }

    /// <summary>
    /// RFC 8032 7.1 from the pinned text (specs/rfc/rfc8032.txt): each "-----TEST name" block's
    /// SECRET KEY, PUBLIC KEY, MESSAGE (its stated length checked) and SIGNATURE, every value hex
    /// on indented lines under its heading. The page breaks inside TEST 1024's message (form
    /// feeds, running headers) match no hex line and are passed.
    /// </summary>
    /// <returns>The five tests, in the RFC's order.</returns>
    /// <exception cref="InvalidDataException">The section was not found, or a message's length
    /// differs from its heading's.</exception>
    private static List<(string Name, byte[] Secret, byte[] Public, byte[] Message, byte[] Signature)> Rfc8032()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc8032.txt"));
        int start = Array.FindIndex(lines, l => l.StartsWith("7.1.  Test Vectors for Ed25519", StringComparison.Ordinal));
        int end = start < 0 ? -1 : Array.FindIndex(lines, start + 1, l => l.StartsWith("7.2.", StringComparison.Ordinal));
        if (end < 0)
        {
            throw new InvalidDataException("RFC 8032's 7.1 was not found in the pinned text");
        }

        var tests = new List<(string, byte[], byte[], byte[], byte[])>();
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
                        throw new InvalidDataException($"RFC 8032 TEST {name}: {message.Length} message octets, {length} stated");
                    }

                    tests.Add((name, Convert.FromHexString(fields["SECRET KEY"]), Convert.FromHexString(fields["PUBLIC KEY"]), message, Convert.FromHexString(fields["SIGNATURE"])));
                }

                name = line.Length > 12 && line.StartsWith("   -----TEST ", StringComparison.Ordinal) ? line["   -----TEST ".Length..] : null;
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

    /// <summary>A value's heading: "   SECRET KEY:", "   PUBLIC KEY:", "   SIGNATURE:", "   ALGORITHM:".</summary>
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
