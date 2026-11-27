using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using static HttpAsm.Tests.Digests;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_p521_public_key, httpasm_p521_ecdh, httpasm_p521_sign and httpasm_p521_verify (NIST
/// P-521) through the C ABI, held to RFC 6979 A.2.7's key pair and ten signatures (read from the
/// pinned text), every P-521 record of NIST's CAVP files (KAS ECC CDH, and FIPS 186-4's KeyPair,
/// PKV, SigGen and SigVer), Project Wycheproof's ECDH tests on raw points and its ECDSA tests in
/// IEEE P1363 form (SHA-512), .NET's ECDiffieHellman and ECDsa on random keys both ways, and a
/// BigInteger model of the curve and of RFC 6979 with HMAC-SHA512 (qlen 521: two HMAC blocks a
/// candidate). tests/run-linux.sh runs the suite at every CPU tier, so both versions answer: v3
/// (mulx with adcx/adox, AVX2 table scans) and v1 (mul, SSE2). P384Tests' twin, plus what P-521
/// alone has: the variable base's doubling case at k = n - 18 (crypto/p521.asm's header), the
/// 66-octet encodings whose first octet holds one bit, and bits2int's shift for digests of 66
/// octets or more. RFC 6979's retry of a nonce candidate of n or more has no test: P-521's n is
/// within 2^261 of 2^521 (the coverage gate lists that retry as a rare condition).
/// </summary>
public sealed unsafe partial class P521Tests
{
    /// <summary>The field's prime p = 2^521 - 1.</summary>
    private static readonly BigInteger P = (BigInteger.One << 521) - 1;

    /// <summary>The group order n.</summary>
    private static readonly BigInteger N = Hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");

    /// <summary>The curve's b (a = -3).</summary>
    private static readonly BigInteger B = Hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");

    /// <summary>The base point G.</summary>
    private static readonly (BigInteger X, BigInteger Y) G = (
        Hex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
        Hex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));

    /// <summary>
    /// The model's constants are the platform's: .NET's explicit nistP521 parameters (its OpenSSL)
    /// give the same p, a = -3, b, G and n, and a cofactor of 1. Everything else here is checked
    /// against them.
    /// </summary>
    [Fact]
    public void TheCurveIsThePlatforms()
    {
        Platform.RequireLinuxX64();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        ECParameters explicitParameters = key.ExportExplicitParameters(includePrivateParameters: false);
        ECCurve curve = explicitParameters.Curve;
        Assert.Equal(P, Unsigned(curve.Prime!));
        Assert.Equal(P - 3, Unsigned(curve.A!));
        Assert.Equal(B, Unsigned(curve.B!));
        Assert.Equal(G.X, Unsigned(curve.G.X!));
        Assert.Equal(G.Y, Unsigned(curve.G.Y!));
        Assert.Equal(N, Unsigned(curve.Order!));
        Assert.Equal(BigInteger.One, Unsigned(curve.Cofactor!));
        Assert.Equal(9, (int)(N % 32));         // the doubling case's cause (HandlesTheVariableBasesDoublingCase)
    }

    /// <summary>
    /// RFC 6979 A.2.7 (NIST P-521), read from the pinned text: the key pair from x; the two
    /// SHA-512 signatures exactly (this library's nonces are RFC 6979's HMAC-SHA512 ones); all ten
    /// signatures (SHA-1 to SHA-512 of "sample" and "test") verified, and each k's public key
    /// carrying r as its x (the fixed base at RFC 6979's own nonces).
    /// </summary>
    [Fact]
    public void MatchesRfc6979sVectors()
    {
        Platform.RequireLinuxX64();
        (Dictionary<string, BigInteger> keys, List<(string Hash, string Message, BigInteger K, BigInteger R, BigInteger S)> signatures) = Rfc6979();
        Assert.Equal(N, keys["q"]);
        BigInteger x = keys["x"];
        byte[] publicKey = Encode((keys["Ux"], keys["Uy"]));
        (int result, byte[] key) = PublicKey(Scalar(x));
        Assert.Equal(0, result);
        Assert.Equal(Convert.ToHexString(publicKey), Convert.ToHexString(key));
        Assert.Equal(10, signatures.Count);
        int exact = 0;
        foreach ((string hash, string message, BigInteger k, BigInteger r, BigInteger s) in signatures)
        {
            byte[] digest = Digest(hash, Encoding.ASCII.GetBytes(message));
            byte[] signature = [.. Scalar(r), .. Scalar(s)];
            Assert.True(Verify(publicKey, digest, signature) == 0, $"{hash} \"{message}\"");
            (int kResult, byte[] kPoint) = PublicKey(Scalar(k));
            Assert.Equal(0, kResult);
            Assert.Equal(r, new BigInteger(kPoint.AsSpan(1, 66), isUnsigned: true, isBigEndian: true) % N);
            if (hash == "SHA-512")
            {
                (int signed, byte[] ours) = Sign(Scalar(x), digest, null);
                Assert.Equal(0, signed);
                Assert.Equal(Convert.ToHexString(signature), Convert.ToHexString(ours));
                exact++;
            }
        }

        Assert.Equal(2, exact);
    }

    /// <summary>
    /// NIST's KAS ECC CDH primitive vectors (ecccdhtestvectors.zip), every [P-521] record: dIUT's
    /// public key is QIUT, and the shared secret of dIUT with QCAVS is ZIUT.
    /// </summary>
    [Fact]
    public void PassesNistsEcdhVectors()
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt")))
        {
            if (record.GetValueOrDefault("Section") != "P-521")
            {
                continue;
            }

            byte[] d = Scalar(Hex(record["dIUT"]));
            byte[] ours = Point(record["QIUTx"], record["QIUTy"]);
            byte[] theirs = Point(record["QCAVSx"], record["QCAVSy"]);
            Assert.Equal(Convert.ToHexString(ours), Convert.ToHexString(PublicKey(d).Key));
            (int result, byte[] shared) = Ecdh(d, theirs);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(Scalar(Hex(record["ZIUT"]))), Convert.ToHexString(shared));
            count++;
        }

        Assert.Equal(25, count);
    }

    /// <summary>
    /// FIPS 186-4's ECDSA vectors (186-4ecdsatestvectors.zip), every P-521 record: KeyPair's (d's
    /// public key is Q), PKV's (public key validation: a key marked P works for ECDH, one marked
    /// F, out of range or off the curve, is refused), SigGen's (SHA-224 to SHA-512: every (R, S)
    /// verifies under Q, and k's public key has R as its x) and SigVer's (SHA-1 to SHA-512: P
    /// verifies, F does not), the digest each record's hash gives (SHA-224 through
    /// <see cref="Digests.Sha224"/>). The files write P-521's numbers with or without the leading
    /// zero octet: each is read as an integer and written back in 66 octets.
    /// </summary>
    [Fact]
    public void PassesNistsEcdsaVectors()
    {
        Platform.RequireLinuxX64();
        int keyPairs = 0, validations = 0, generated = 0, verified = 0;
        foreach ((string d, string qx, string qy) in KeyPairs(Vectors.Path("cavp/ecdsa/KeyPair.rsp"), "P-521"))
        {
            Assert.Equal(Convert.ToHexString(Point(qx, qy)), Convert.ToHexString(PublicKey(Scalar(Hex(d))).Key));
            keyPairs++;
        }

        byte[] someKey = Scalar(12345);
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/PKV.rsp")))
        {
            if (record.GetValueOrDefault("Section") != "P-521")
            {
                continue;
            }

            bool pass = record["Result"].StartsWith('P');
            byte[]? point = TryPoint(record["Qx"], record["Qy"]);
            int result = point is null ? -1 : Ecdh(someKey, point).Result;
            Assert.True(result == (pass ? 0 : -1), $"PKV {record["Qx"]}: {record["Result"]}");
            validations++;
        }

        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/SigGen.txt")))
        {
            string section = record.GetValueOrDefault("Section") ?? "";
            if (!section.StartsWith("P-521,", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] digest = Digest(section["P-521,".Length..], Convert.FromHexString(record["Msg"]));
            byte[] key = Point(record["Qx"], record["Qy"]);
            Assert.Equal(Convert.ToHexString(key), Convert.ToHexString(PublicKey(Scalar(Hex(record["d"]))).Key));
            byte[] signature = [.. Scalar(Hex(record["R"])), .. Scalar(Hex(record["S"]))];
            Assert.Equal(0, Verify(key, digest, signature));
            byte[] kPoint = PublicKey(Scalar(Hex(record["k"]))).Key;
            Assert.Equal(Hex(record["R"]), new BigInteger(kPoint.AsSpan(1, 66), isUnsigned: true, isBigEndian: true) % N);
            generated++;
        }

        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/SigVer.rsp")))
        {
            string section = record.GetValueOrDefault("Section") ?? "";
            if (!section.StartsWith("P-521,", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] digest = Digest(section["P-521,".Length..], Convert.FromHexString(record["Msg"]));
            byte[] signature = [.. Scalar(Hex(record["R"])), .. Scalar(Hex(record["S"]))];
            bool pass = record["Result"].StartsWith('P');
            Assert.True(Verify(Point(record["Qx"], record["Qy"]), digest, signature) == (pass ? 0 : -1), $"SigVer {section}: {record["Result"]}");
            verified++;
        }

        Assert.Equal(10, keyPairs);
        Assert.Equal(12, validations);
        Assert.Equal(60, generated);
        Assert.Equal(75, verified);
    }

    /// <summary>
    /// Project Wycheproof's ECDH tests on raw points (ecdh_secp521r1_ecpoint_test.json, 661,
    /// commit 65ca494): every valid one's shared secret (632: the edge-case doublings, ephemeral
    /// keys and secrets included); the 16 invalid-curve-attack points refused with zeros; the
    /// compressed and empty encodings (13: one marked acceptable, twelve invalid), which this
    /// function does not take (TLS 1.3 uses the uncompressed form only), never marked valid.
    /// </summary>
    [Fact]
    public void PassesWycheproofsEcdhTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0, refused = 0, otherForms = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/ecdh_secp521r1_ecpoint_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] point = Convert.FromHexString(test.GetProperty("public").GetString()!);
            byte[] key = Scalar(Hex(test.GetProperty("private").GetString()!));
            byte[] shared = Convert.FromHexString(test.GetProperty("shared").GetString()!);
            count++;
            if (point.Length != 133)
            {
                Assert.True(expected != "valid", id);
                otherForms++;
                continue;
            }

            (int result, byte[] output) = Ecdh(key, point);
            if (expected == "valid")
            {
                Assert.True(result == 0, id);
                Assert.True(output.SequenceEqual(shared), id);
                valid++;
            }
            else
            {
                Assert.True(result == -1 && output.All(o => o == 0), id);
                refused++;
            }
        }

        Assert.Equal(661, count);
        Assert.Equal(632, valid);
        Assert.Equal(16, refused);
        Assert.Equal(13, otherForms);
    }

    /// <summary>
    /// Project Wycheproof's ECDSA tests in IEEE P1363 form (r || s) with SHA-512 (318): every
    /// valid signature verifies (231: arithmetic edge cases, special hashes, edge-case keys, the
    /// point-duplication and Shamir edge cases), every invalid one is refused (r or s zero or n or
    /// more, the duplicated points; the 14 of other sizes than 132 octets never passed).
    /// </summary>
    [Fact]
    public void PassesWycheproofsEcdsaTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0, otherSizes = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/ecdsa_secp521r1_sha512_p1363_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            Assert.NotEqual("acceptable", expected);
            byte[] key = Convert.FromHexString(group.GetProperty("publicKey").GetProperty("uncompressed").GetString()!);
            byte[] digest = Digest(group.GetProperty("sha").GetString()!, Convert.FromHexString(test.GetProperty("msg").GetString()!));
            byte[] signature = Convert.FromHexString(test.GetProperty("sig").GetString()!);
            count++;
            if (signature.Length != 132)
            {
                Assert.True(expected == "invalid", id);
                otherSizes++;
                continue;
            }

            Assert.True(Verify(key, digest, signature) == (expected == "valid" ? 0 : -1), id);
            valid += expected == "valid" ? 1 : 0;
        }

        Assert.Equal(318, count);
        Assert.Equal(231, valid);
        Assert.Equal(14, otherSizes);
    }

    /// <summary>
    /// .NET's ECDiffieHellman and ECDsa (the platform's OpenSSL) on 40 random key pairs: the
    /// public key of .NET's d; the shared secret both ways; our signatures (RFC 6979, and hedged
    /// with entropy) verified by .NET, .NET's signatures verified by us, and a changed digest
    /// refused by both.
    /// </summary>
    [Fact]
    public void AgreesWithDotNet()
    {
        Platform.RequireLinuxX64();
        var random = new Random(521);
        for (int i = 0; i < 40; i++)
        {
            using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
            using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
            ECParameters a = alice.ExportParameters(includePrivateParameters: true);
            ECParameters b = bob.ExportParameters(includePrivateParameters: false);
            byte[] alicePublic = [0x04, .. a.Q.X!, .. a.Q.Y!];
            byte[] bobPublic = [0x04, .. b.Q.X!, .. b.Q.Y!];
            Assert.Equal(66, a.D!.Length);
            Assert.Equal(Convert.ToHexString(alicePublic), Convert.ToHexString(PublicKey(a.D!).Key));
            (int result, byte[] shared) = Ecdh(a.D!, bobPublic);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(alice.DeriveRawSecretAgreement(bob.PublicKey)), Convert.ToHexString(shared));

            using var ecdsa = ECDsa.Create(a);
            byte[] digest = new byte[64];
            random.NextBytes(digest);
            byte[]? entropy = i % 2 == 0 ? null : RandomNumberGenerator.GetBytes(66);
            (int signed, byte[] signature) = Sign(a.D!, digest, entropy);
            Assert.Equal(0, signed);
            Assert.True(ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            byte[] theirs = ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.Equal(0, Verify(alicePublic, digest, theirs));
            digest[random.Next(64)] ^= (byte)(1 << random.Next(8));
            Assert.Equal(-1, Verify(alicePublic, digest, signature));
            Assert.Equal(-1, Verify(alicePublic, digest, theirs));
            Assert.False(ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
    }

    /// <summary>
    /// Against the BigInteger model on 100 scalars, the edges first (1, 2, 3, n - 1, n - 2, n - 3,
    /// the doubling case's n - 18 and its neighbours, 2^520, 2^260, n / 2, the small multiples the
    /// tables hold, ones that make Booth digits negative everywhere): public keys and shared
    /// secrets by Jacobian double-and-add, signatures by RFC 6979 3.2 in C# (HMACSHA512, two
    /// blocks a candidate) for digests of every length from 0 to 100 octets (the leftmost 521
    /// bits, or all of a shorter one: 66 octets is where the shift starts), with and without
    /// entropy, each verified.
    /// </summary>
    [Fact]
    public void MatchesABigIntegerModel()
    {
        Platform.RequireLinuxX64();
        var random = new Random(6979);
        BigInteger[] edges =
        [
            1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, N - 1, N - 2, N - 3, N - 17, N - 18, N - 19, N - 9,
            BigInteger.One << 520, BigInteger.One << 260, N / 2, (BigInteger.One << 521) - (BigInteger.One << 515),
            Hex("00F7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDE"),
            Hex("0108421084210842108421084210842108421084210842108421084210842108421084210842108421084210842108421084210842108421084210842108421084210"),
            Hex("00FBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBEFBE"),
        ];
        for (int i = 0; i < 100; i++)
        {
            BigInteger d = i < edges.Length ? edges[i] % N : RandomScalar(random);
            (BigInteger X, BigInteger Y) q = Multiply(d, G)!.Value;
            (int result, byte[] key) = PublicKey(Scalar(d));
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(Encode(q)), Convert.ToHexString(key));
            (BigInteger X, BigInteger Y) other = Multiply(RandomScalar(random), G)!.Value;
            (int agreed, byte[] shared) = Ecdh(Scalar(d), Encode(other));
            Assert.Equal(0, agreed);
            Assert.Equal(Convert.ToHexString(Scalar(Multiply(d, other)!.Value.X)), Convert.ToHexString(shared));

            byte[] digest = new byte[i % 101];
            random.NextBytes(digest);
            byte[]? entropy = i % 3 == 0 ? null : RandomNumberGenerator.GetBytes(66);
            (BigInteger r, BigInteger s) = Rfc6979Sign(d, digest, entropy);
            (int signed, byte[] signature) = Sign(Scalar(d), digest, entropy);
            Assert.Equal(0, signed);
            Assert.Equal(Convert.ToHexString([.. Scalar(r), .. Scalar(s)]), Convert.ToHexString(signature));
            Assert.Equal(0, Verify(key, digest, signature));
        }
    }

    /// <summary>
    /// The variable base's doubling case (crypto/p521.asm's header): with 5-bit Booth digits, the
    /// last addition adds d0 P to (k - d0) P, and for k = n - 18 the low digit is -9 (n is 9 mod
    /// 32) while k - d0 = n - 9 is -9 modulo n: equal points, where the addition's formulas give
    /// garbage and p521_add_last takes the doubling. The case is checked to be what the header
    /// says (the digit, the multiple of 32), then ECDH at k = n - 18 against the model and .NET on
    /// eight peers (and its neighbours, which meet nothing), and its public key (the fixed base,
    /// which no k can make double).
    /// </summary>
    [Fact]
    public void HandlesTheVariableBasesDoublingCase()
    {
        Platform.RequireLinuxX64();
        BigInteger k = N - 18;
        BigInteger low = k % 32;                // Booth's window 0: bits -1..4, the digit k mod 32 taken in [-16, 16)
        BigInteger d0 = low >= 16 ? low - 32 : low;
        Assert.Equal(-9, (int)d0);
        Assert.True(((k - d0) % 32).IsZero && Mod(k - d0, N) == Mod(d0, N), "n - 18's last addition does not add equal points");
        var random = new Random(18);
        foreach (BigInteger scalar in new[] { N - 18, N - 17, N - 19, N - 50, N - 82 })
        {
            (int result, byte[] key) = PublicKey(Scalar(scalar));
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(Encode(Multiply(scalar, G)!.Value)), Convert.ToHexString(key));
            for (int i = 0; i < 8; i++)
            {
                (BigInteger X, BigInteger Y) peer = i == 0 ? G : Multiply(RandomScalar(random), G)!.Value;
                (int agreed, byte[] shared) = Ecdh(Scalar(scalar), Encode(peer));
                Assert.Equal(0, agreed);
                Assert.Equal(Convert.ToHexString(Scalar(Multiply(scalar, peer)!.Value.X)), Convert.ToHexString(shared));
            }
        }

        // .NET (its own OpenSSL) agrees at n - 18 with a peer of its own.
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
        ECParameters b = bob.ExportParameters(includePrivateParameters: false);
        (BigInteger X, BigInteger Y) ours = Multiply(k, G)!.Value;
        using var alice = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP521,
            D = Scalar(k),
            Q = new ECPoint { X = Scalar(ours.X), Y = Scalar(ours.Y) },
        });
        (int done, byte[] secret) = Ecdh(Scalar(k), [0x04, .. b.Q.X!, .. b.Q.Y!]);
        Assert.Equal(0, done);
        Assert.Equal(Convert.ToHexString(alice.DeriveRawSecretAgreement(bob.PublicKey)), Convert.ToHexString(secret));
    }

    /// <summary>
    /// The verification's variable-time additions at their edges, as P256Tests reaches them: with a
    /// public key Q = c G and a signature built for chosen u1 and u2 (r = x(u1 G + u2 Q) mod n,
    /// s = r / u2, e = u1 s, which give back exactly u1 and u2):
    /// - the mixed addition doubling: c = (n + 1) / 2, u1 = 1, u2 = 2: R = 2G, valid;
    /// - the mixed addition cancelling: c = -(n + 1) / 2: R at infinity, refused;
    /// - the Jacobian addition doubling: Q = G, u1 = u2 = 1: R = 2G, valid;
    /// - the Jacobian addition cancelling: Q = -G, u1 = u2 = 1: R at infinity, refused.
    /// </summary>
    [Fact]
    public void HandlesTheVerificationsEqualAndOppositePoints()
    {
        Platform.RequireLinuxX64();
        BigInteger half = (N + 1) / 2;
        (BigInteger C, BigInteger U1, BigInteger U2, bool Valid)[] cases =
        [
            (half, 1, 2, true),
            (N - half, 1, 2, false),
            (1, 1, 1, true),
            (N - 1, 1, 1, false),
        ];
        foreach ((BigInteger c, BigInteger u1, BigInteger u2, bool valid) in cases)
        {
            (BigInteger X, BigInteger Y) q = Multiply(c, G)!.Value;
            (BigInteger X, BigInteger Y)? sum = Add(Multiply(u1, G), Multiply(u2, q));
            Assert.Equal(valid, sum is not null);
            BigInteger r = sum is null ? 1 : sum.Value.X % N;
            BigInteger s = r * BigInteger.ModPow(u2, N - 2, N) % N;
            BigInteger e = u1 * s % N;
            // e as a 66-octet digest is e << 7: bits2int takes a 66-octet digest's leftmost 521
            // bits (P384Tests' Scalar(e) is qlen's own 48 octets, which no shift touches)
            Assert.True(Verify(Encode(q), Scalar(e << 7), [.. Scalar(r), .. Scalar(s)]) == (valid ? 0 : -1), $"c {c}, u1 {u1}, u2 {u2}");
        }
    }

    /// <summary>
    /// What must be refused, with zeros written where there is an output: private keys 0, n, n + 1,
    /// 2^521 - 1, 2^521 and 2^528 - 1 (the 66 octets all ones: bits above 520 are n or more) in
    /// all three functions that take one; public keys with any first octet but 04, with x or y
    /// equal to p, p + 1, 2^521 or 2^528 - 1, or one off the curve; r or s 0, n or more; one
    /// flipped bit of a valid signature. And what must not be: n - s (ECDSA's twin signature).
    /// </summary>
    [Fact]
    public void RefusesInvalidKeysAndSignatures()
    {
        Platform.RequireLinuxX64();
        BigInteger d = Hex("0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538");
        byte[] key = Encode(Multiply(d, G)!.Value);
        byte[] digest = SHA512.HashData("refuse"u8);
        (int _, byte[] valid) = Sign(Scalar(d), digest, null);
        BigInteger top = (BigInteger.One << 528) - 1;
        foreach (BigInteger bad in new[] { BigInteger.Zero, N, N + 1, P, BigInteger.One << 521, top })
        {
            (int result, byte[] output) = PublicKey(Scalar(bad));
            Assert.True(result == -1 && output.All(o => o == 0));
            (result, output) = Ecdh(Scalar(bad), key);
            Assert.True(result == -1 && output.All(o => o == 0));
            (result, output) = Sign(Scalar(bad), digest, null);
            Assert.True(result == -1 && output.All(o => o == 0));
        }

        var points = new List<byte[]>();
        for (int first = 0; first < 256; first++)
        {
            if (first != 4)
            {
                points.Add([(byte)first, .. key.AsSpan(1)]);
            }
        }

        foreach (BigInteger coordinate in new[] { P, P + 1, BigInteger.One << 521, top })
        {
            points.Add([0x04, .. Scalar(coordinate), .. key.AsSpan(67)]);
            points.Add([.. key.AsSpan(0, 67), .. Scalar(coordinate)]);
        }

        byte[] offCurve = (byte[])key.Clone();
        offCurve[132] ^= 1;
        points.Add(offCurve);
        points.Add(new byte[133]);
        foreach (byte[] point in points)
        {
            (int result, byte[] output) = Ecdh(Scalar(d), point);
            Assert.True(result == -1 && output.All(o => o == 0), Convert.ToHexString(point));
            Assert.Equal(-1, Verify(point, digest, valid));
        }

        BigInteger r = new(valid.AsSpan(0, 66), isUnsigned: true, isBigEndian: true);
        BigInteger s = new(valid.AsSpan(66), isUnsigned: true, isBigEndian: true);
        foreach ((BigInteger rr, BigInteger ss) in new[] { (BigInteger.Zero, s), (r, BigInteger.Zero), (N, s), (r, N), (r + N, s), (top, s), (r, top), (r, s + N) })
        {
            if (rr <= top && ss <= top)
            {
                Assert.Equal(-1, Verify(key, digest, [.. Scalar(rr), .. Scalar(ss)]));
            }
        }

        Assert.Equal(0, Verify(key, digest, [.. Scalar(r), .. Scalar(N - s)]));
        for (int bit = 0; bit < 1056; bit += 7)
        {
            byte[] flipped = (byte[])valid.Clone();
            flipped[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(key, digest, flipped));
        }
    }

    /// <summary>One httpasm_p521_public_key call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">66 octets.</param>
    /// <returns>The result and the 133-octet public key.</returns>
    private static (int Result, byte[] Key) PublicKey(byte[] privateKey)
    {
        byte[] output = new byte[133];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey)
        {
            result = Native.P521PublicKey(o, k);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p521_ecdh call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">66 octets.</param>
    /// <param name="point">133 octets.</param>
    /// <returns>The result and the 66-octet shared secret.</returns>
    private static (int Result, byte[] Shared) Ecdh(byte[] privateKey, byte[] point)
    {
        byte[] output = new byte[66];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey, q = point)
        {
            result = Native.P521Ecdh(o, k, q);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p521_sign call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">66 octets.</param>
    /// <param name="digest">The digest (any length).</param>
    /// <param name="entropy">66 octets, or null.</param>
    /// <returns>The result and the 132-octet signature.</returns>
    private static (int Result, byte[] Signature) Sign(byte[] privateKey, byte[] digest, byte[]? entropy)
    {
        byte[] output = new byte[132];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey, h = digest, e = entropy)
        {
            result = Native.P521Sign(o, k, h, (nuint)digest.Length, e);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p521_verify call.</summary>
    /// <param name="key">133 octets.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="signature">132 octets.</param>
    /// <returns>0 or -1.</returns>
    private static int Verify(byte[] key, byte[] digest, byte[] signature)
    {
        fixed (byte* q = key, h = digest, s = signature)
        {
            return Native.P521Verify(q, h, (nuint)digest.Length, s);
        }
    }

    /// <summary>A big-endian hexadecimal integer (any length, leading zeros allowed).</summary>
    /// <param name="hex">The digits.</param>
    /// <returns>The nonnegative integer.</returns>
    private static BigInteger Hex(string hex) => new(Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex), isUnsigned: true, isBigEndian: true);

    /// <summary>A big-endian unsigned integer from .NET's parameter octets.</summary>
    /// <param name="octets">The octets.</param>
    /// <returns>The integer.</returns>
    private static BigInteger Unsigned(byte[] octets) => new(octets, isUnsigned: true, isBigEndian: true);

    /// <summary>A nonnegative integer below 2^528 as 66 big-endian octets.</summary>
    /// <param name="x">The integer.</param>
    /// <returns>66 octets.</returns>
    private static byte[] Scalar(BigInteger x)
    {
        byte[] octets = new byte[66];
        Assert.True(x.TryWriteBytes(octets.AsSpan(66 - x.GetByteCount(isUnsigned: true)), out _, isUnsigned: true, isBigEndian: true));
        return octets;
    }

    /// <summary>04 || x || y for a CAVP record's hex coordinates (each fits 66 octets).</summary>
    /// <param name="x">Qx.</param>
    /// <param name="y">Qy.</param>
    /// <returns>133 octets.</returns>
    /// <exception cref="InvalidDataException">A coordinate does not fit 66 octets (only PKV's
    /// out-of-range keys may not, and they go through <see cref="TryPoint"/>).</exception>
    private static byte[] Point(string x, string y) => TryPoint(x, y) ?? throw new InvalidDataException($"a coordinate past 66 octets: {x}, {y}");

    /// <summary>04 || x || y, or null when a coordinate does not fit 66 octets (PKV's out-of-range keys).</summary>
    /// <param name="x">Qx in hex.</param>
    /// <param name="y">Qy in hex.</param>
    /// <returns>133 octets or null.</returns>
    private static byte[]? TryPoint(string x, string y)
    {
        BigInteger qx = Hex(x), qy = Hex(y);
        return qx >= BigInteger.One << 528 || qy >= BigInteger.One << 528 ? null : [0x04, .. Scalar(qx), .. Scalar(qy)];
    }

    /// <summary>The 133-octet uncompressed encoding of an affine point.</summary>
    /// <param name="q">The point.</param>
    /// <returns>04 || x || y.</returns>
    private static byte[] Encode((BigInteger X, BigInteger Y) q) => [0x04, .. Scalar(q.X), .. Scalar(q.Y)];

    /// <summary>A uniform scalar in [1, n - 1].</summary>
    /// <param name="random">The source.</param>
    /// <returns>The scalar.</returns>
    private static BigInteger RandomScalar(Random random)
    {
        byte[] octets = new byte[70];
        random.NextBytes(octets);
        return new BigInteger(octets, isUnsigned: true) % (N - 1) + 1;
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

    /// <summary>The affine sum of two points (null is infinity), with the tangent for equal points.</summary>
    /// <param name="a">A point or null.</param>
    /// <param name="b">A point or null.</param>
    /// <returns>a + b or null.</returns>
    private static (BigInteger X, BigInteger Y)? Add((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b)
    {
        if (a is null)
        {
            return b;
        }

        if (b is null)
        {
            return a;
        }

        BigInteger slope;
        if (a.Value.X == b.Value.X)
        {
            if (Mod(a.Value.Y + b.Value.Y, P).IsZero)
            {
                return null;
            }

            slope = Mod((3 * a.Value.X * a.Value.X - 3) * BigInteger.ModPow(Mod(2 * a.Value.Y, P), P - 2, P), P);
        }
        else
        {
            slope = Mod((b.Value.Y - a.Value.Y) * BigInteger.ModPow(Mod(b.Value.X - a.Value.X, P), P - 2, P), P);
        }

        BigInteger x = Mod(slope * slope - a.Value.X - b.Value.X, P);
        return (x, Mod(slope * (a.Value.X - x) - a.Value.Y, P));
    }

    /// <summary>
    /// k q by double-and-add from the top bit in Jacobian coordinates (x = X / Z^2, y = Y / Z^3),
    /// the textbook formulas (doubling with M = 3 (X - Z^2)(X + Z^2) for a = -3; Cohen, Miyaji and
    /// Ono's addition, falling back to doubling or infinity when H = 0), one inversion at the end:
    /// the model, fast enough at 521 bits where an affine step's inversion each would not be.
    /// </summary>
    /// <param name="k">A nonnegative scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>k q, or null for infinity.</returns>
    private static (BigInteger X, BigInteger Y)? Multiply(BigInteger k, (BigInteger X, BigInteger Y) q)
    {
        (BigInteger X, BigInteger Y, BigInteger Z) acc = (1, 1, 0);
        for (int bit = (int)k.GetBitLength() - 1; bit >= 0; bit--)
        {
            acc = Double(acc);
            if (!(k >> bit).IsEven)
            {
                acc = Sum(acc, (q.X, q.Y, 1));
            }
        }

        if (acc.Z.IsZero)
        {
            return null;
        }

        BigInteger zi = BigInteger.ModPow(acc.Z, P - 2, P);
        return (Mod(acc.X * zi * zi, P), Mod(acc.Y * zi * zi * zi, P));

        static (BigInteger, BigInteger, BigInteger) Double((BigInteger X, BigInteger Y, BigInteger Z) a)
        {
            if (a.Z.IsZero || a.Y.IsZero)
            {
                return (1, 1, 0);
            }

            BigInteger zz = a.Z * a.Z % P;
            BigInteger m = Mod(3 * (a.X - zz) * (a.X + zz), P);
            BigInteger yy = a.Y * a.Y % P;
            BigInteger s = 4 * a.X * yy % P;
            BigInteger x3 = Mod(m * m - 2 * s, P);
            return (x3, Mod(m * (s - x3) - 8 * yy * yy, P), 2 * a.Y * a.Z % P);
        }

        static (BigInteger, BigInteger, BigInteger) Sum((BigInteger X, BigInteger Y, BigInteger Z) a, (BigInteger X, BigInteger Y, BigInteger Z) b)
        {
            if (a.Z.IsZero)
            {
                return b;
            }

            BigInteger z1z1 = a.Z * a.Z % P, z2z2 = b.Z * b.Z % P;
            BigInteger u1 = a.X * z2z2 % P, u2 = b.X * z1z1 % P;
            BigInteger s1 = a.Y * z2z2 % P * b.Z % P, s2 = b.Y * z1z1 % P * a.Z % P;
            BigInteger h = Mod(u2 - u1, P), r = Mod(s2 - s1, P);
            if (h.IsZero)
            {
                return r.IsZero ? Double(a) : (1, 1, 0);
            }

            BigInteger hh = h * h % P, hhh = hh * h % P;
            BigInteger x3 = Mod(r * r - hhh - 2 * u1 * hh, P);
            return (x3, Mod(r * (u1 * hh - x3) - s1 * hhh, P), a.Z * b.Z % P * h % P);
        }
    }

    /// <summary>
    /// ECDSA with RFC 6979 3.2's k from HMAC-SHA512 (and 3.6's extra input when entropy is given),
    /// as the library defines its nonces: e = bits2int(digest) mod n; candidates until 1 <= k < n
    /// and neither r nor s is 0, each refusal followed by step h.3 (K = HMAC_K(V || 0x00),
    /// V = HMAC_K(V)). qlen = 521 > hlen = 512: a candidate is T = V1 || V2 (two HMACs of V) and
    /// k = bits2int(T), its leftmost 521 bits.
    /// </summary>
    /// <param name="d">The private key.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="entropy">66 octets or null.</param>
    /// <returns>(r, s).</returns>
    private static (BigInteger R, BigInteger S) Rfc6979Sign(BigInteger d, byte[] digest, byte[]? entropy)
    {
        BigInteger e = Bits2Int(digest) % N;
        byte[] seed = [.. Scalar(d), .. Scalar(e), .. entropy ?? []];
        byte[] v = new byte[64], k = new byte[64];
        v.AsSpan().Fill(0x01);
        byte[] input = [.. v, 0x00, .. seed];
        k = HMACSHA512.HashData(k, input);
        v = HMACSHA512.HashData(k, v);
        input = [.. v, 0x01, .. seed];
        k = HMACSHA512.HashData(k, input);
        v = HMACSHA512.HashData(k, v);
        while (true)
        {
            v = HMACSHA512.HashData(k, v);
            byte[] t = v;
            v = HMACSHA512.HashData(k, v);
            t = [.. t, .. v];
            BigInteger candidate = new BigInteger(t, isUnsigned: true, isBigEndian: true) >> (1024 - 521);
            if (candidate >= 1 && candidate < N)
            {
                BigInteger r = Multiply(candidate, G)!.Value.X % N;
                BigInteger s = BigInteger.ModPow(candidate, N - 2, N) * (e + r * d) % N;
                if (!r.IsZero && !s.IsZero)
                {
                    return (r, s);
                }
            }

            byte[] rejected = [.. v, 0x00];
            k = HMACSHA512.HashData(k, rejected);
            v = HMACSHA512.HashData(k, v);
        }
    }

    /// <summary>
    /// RFC 6979 2.3.2's bits2int for qlen = 521: the leftmost 521 bits of the digest (its first 66
    /// octets shifted right 7, for a digest of 66 octets or more), or all of a shorter one.
    /// </summary>
    /// <param name="digest">The digest.</param>
    /// <returns>The integer.</returns>
    private static BigInteger Bits2Int(byte[] digest) => digest.Length >= 66
        ? new BigInteger(digest.AsSpan(0, 66), isUnsigned: true, isBigEndian: true) >> 7
        : new BigInteger(digest, isUnsigned: true, isBigEndian: true);

    /// <summary>
    /// RFC 6979 A.2.7 from the pinned text (specs/rfc/rfc6979.txt): its "name = HEX" values up to
    /// the signatures (q, x, Ux, Uy), and each "With SHA-..., message = "...":" block's k, r and s.
    /// Each value is 131 hex digits on three lines: 64 after "name = ", then 64 and 3 on the next
    /// two, indented; the continuation lines are taken while they are hex digits alone. The page
    /// breaks (form feeds, running headers) fall between blocks and match no pattern.
    /// </summary>
    /// <returns>The key values by name, and the ten signatures.</returns>
    /// <exception cref="InvalidDataException">The section was not found, or a value is not 131 digits.</exception>
    private static (Dictionary<string, BigInteger> Keys, List<(string Hash, string Message, BigInteger K, BigInteger R, BigInteger S)> Signatures) Rfc6979()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc6979.txt"));
        int start = Array.FindIndex(lines, l => l.StartsWith("A.2.7.  ECDSA, 521 Bits (Prime Field)", StringComparison.Ordinal));
        int end = start < 0 ? -1 : Array.FindIndex(lines, start + 1, l => l.StartsWith("A.2.8.", StringComparison.Ordinal));
        if (end < 0)
        {
            throw new InvalidDataException("RFC 6979's A.2.7 was not found in the pinned text");
        }

        var keys = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        var signatures = new List<(string, string, BigInteger, BigInteger, BigInteger)>();
        string? hash = null, message = null;
        var values = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        for (int i = start; i < end; i++)
        {
            Match m;
            if ((m = WithLine().Match(lines[i])).Success)
            {
                hash = m.Groups[1].Value;
                message = m.Groups[2].Value;
                values.Clear();
            }
            else if ((m = ValueLine().Match(lines[i])).Success)
            {
                var digits = new StringBuilder(m.Groups[2].Value);
                Match rest;
                while (i + 1 < end && (rest = ContinuationLine().Match(lines[i + 1])).Success)
                {
                    digits.Append(rest.Groups[1].Value);
                    i++;
                }

                if (digits.Length != 131)
                {
                    throw new InvalidDataException($"RFC 6979 A.2.7: {m.Groups[1].Value} has {digits.Length} digits, not 131");
                }

                BigInteger value = Hex(digits.ToString());
                if (hash is null)
                {
                    keys[m.Groups[1].Value] = value;
                }
                else
                {
                    values[m.Groups[1].Value] = value;
                    if (values.Count == 3)
                    {
                        signatures.Add((hash, message!, values["k"], values["r"], values["s"]));
                        values.Clear();
                    }
                }
            }
        }

        return (keys, signatures);
    }

    /// <summary>
    /// The key pairs of one curve in FIPS 186-4's KeyPair.rsp: its curve sections ("[P-521]") are
    /// each followed by a second bracketed line naming the generation method, which the generic
    /// <see cref="Vectors.CavpRecords"/> would take as the section; so the curve is tracked here
    /// from the lines that name one, and each d/Qx/Qy triple under the curve is returned.
    /// </summary>
    /// <param name="path">KeyPair.rsp.</param>
    /// <param name="wanted">The curve's section name ("P-521").</param>
    /// <returns>(d, Qx, Qy) in hex, file order.</returns>
    private static IEnumerable<(string D, string Qx, string Qy)> KeyPairs(string path, string wanted)
    {
        string? curve = null, d = null, qx = null;
        foreach (string raw in File.ReadLines(path))
        {
            string line = raw.Trim();
            if (CurveLine().IsMatch(line))
            {
                curve = line[1..^1];
            }
            else if (line.StartsWith("d = ", StringComparison.Ordinal))
            {
                d = line[4..];
            }
            else if (line.StartsWith("Qx = ", StringComparison.Ordinal))
            {
                qx = line[5..];
            }
            else if (line.StartsWith("Qy = ", StringComparison.Ordinal) && curve == wanted && d is not null && qx is not null)
            {
                yield return (d, qx, line[5..]);
            }
        }
    }

    /// <summary>A CAVP curve section line: "[P-521]", "[K-233]", "[B-571]".</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^\[[PKB]-[0-9]+\]$")]
    private static partial Regex CurveLine();

    /// <summary>A signature block's heading: "   With SHA-512, message = "sample":".</summary>
    /// <returns>The pattern (hash, message).</returns>
    [GeneratedRegex("^   With (SHA-[0-9]+), message = \"([a-z]+)\":$")]
    private static partial Regex WithLine();

    /// <summary>A value's first line: "   x = 0FAD..." (64 hex digits; 67 more follow on two lines).</summary>
    /// <returns>The pattern (name, digits).</returns>
    [GeneratedRegex("^   ([A-Za-z]+) = ([0-9A-F]{64})$")]
    private static partial Regex ValueLine();

    /// <summary>A value's continuation line: hex digits alone, indented.</summary>
    /// <returns>The pattern (digits).</returns>
    [GeneratedRegex("^ +([0-9A-F]+)$")]
    private static partial Regex ContinuationLine();
}
