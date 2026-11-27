using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

using static HttpAsm.Tests.Digests;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_p384_public_key, httpasm_p384_ecdh, httpasm_p384_sign and httpasm_p384_verify (NIST
/// P-384) through the C ABI, held to RFC 6979 A.2.6's key pair and ten signatures (read from the
/// pinned text), every P-384 record of NIST's CAVP files (KAS ECC CDH, and FIPS 186-4's KeyPair,
/// PKV, SigGen and SigVer), Project Wycheproof's ECDH tests on raw points and its ECDSA tests in
/// IEEE P1363 form (SHA-384 and SHA-512), .NET's ECDiffieHellman and ECDsa on random keys both
/// ways, and a BigInteger model of the curve and of RFC 6979 with HMAC-SHA384. tests/run-linux.sh
/// runs the suite at every CPU tier, so both versions answer: v3 (mulx with adcx/adox, AVX2 table
/// scans) and v1 (mul, SSE2). P256Tests' twin; its retry of a nonce candidate of n or more has no
/// twin here: P-384's n is within 2^190 of 2^384, so no search can find a seed whose candidate is
/// n or more (the coverage gate lists that retry as a rare condition).
/// </summary>
public sealed unsafe partial class P384Tests
{
    /// <summary>The field's prime p = 2^384 - 2^128 - 2^96 + 2^32 - 1.</summary>
    private static readonly BigInteger P = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");

    /// <summary>The group order n.</summary>
    private static readonly BigInteger N = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");

    /// <summary>The curve's b (a = -3).</summary>
    private static readonly BigInteger B = Hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");

    /// <summary>The base point G.</summary>
    private static readonly (BigInteger X, BigInteger Y) G = (
        Hex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
        Hex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));

    /// <summary>
    /// RFC 6979 A.2.6 (NIST P-384), read from the pinned text: the key pair from x; the two
    /// SHA-384 signatures exactly (this library's nonces are RFC 6979's HMAC-SHA384 ones); all ten
    /// signatures (SHA-1 to SHA-512 of "sample" and "test") verified, and each k's public key
    /// carrying r as its x (the fixed base at RFC 6979's own nonces).
    /// </summary>
    [Fact]
    public void MatchesRfc6979sVectors()
    {
        Platform.RequireLinuxX64();
        (Dictionary<string, BigInteger> keys, List<(string Hash, string Message, BigInteger K, BigInteger R, BigInteger S)> signatures) = Rfc6979();
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
            Assert.Equal(r, new BigInteger(kPoint.AsSpan(1, 48), isUnsigned: true, isBigEndian: true) % N);
            if (hash == "SHA-384")
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
    /// NIST's KAS ECC CDH primitive vectors (ecccdhtestvectors.zip), every [P-384] record: dIUT's
    /// public key is QIUT, and the shared secret of dIUT with QCAVS is ZIUT.
    /// </summary>
    [Fact]
    public void PassesNistsEcdhVectors()
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt")))
        {
            if (record.GetValueOrDefault("Section") != "P-384")
            {
                continue;
            }

            byte[] d = Convert.FromHexString(record["dIUT"]);
            byte[] ours = Point(record["QIUTx"], record["QIUTy"]);
            byte[] theirs = Point(record["QCAVSx"], record["QCAVSy"]);
            Assert.Equal(Convert.ToHexString(ours), Convert.ToHexString(PublicKey(d).Key));
            (int result, byte[] shared) = Ecdh(d, theirs);
            Assert.Equal(0, result);
            Assert.Equal(record["ZIUT"], Convert.ToHexStringLower(shared));
            count++;
        }

        Assert.Equal(25, count);
    }

    /// <summary>
    /// FIPS 186-4's ECDSA vectors (186-4ecdsatestvectors.zip), every P-384 record: KeyPair's (d's
    /// public key is Q), PKV's (public key validation: a key marked P works for ECDH, one marked
    /// F, out of range or off the curve, is refused), SigGen's (SHA-224 to SHA-512: every (R, S)
    /// verifies under Q, and k's public key has R as its x) and SigVer's (SHA-1 to SHA-512: P
    /// verifies, F does not), the digest each record's hash gives (SHA-224 through
    /// <see cref="Digests.Sha224"/>).
    /// </summary>
    [Fact]
    public void PassesNistsEcdsaVectors()
    {
        Platform.RequireLinuxX64();
        int keyPairs = 0, validations = 0, generated = 0, verified = 0;
        foreach ((string d, string qx, string qy) in KeyPairs(Vectors.Path("cavp/ecdsa/KeyPair.rsp"), "P-384"))
        {
            Assert.Equal(Convert.ToHexString(Point(qx, qy)), Convert.ToHexString(PublicKey(Convert.FromHexString(d)).Key));
            keyPairs++;
        }

        byte[] someKey = Scalar(12345);
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/PKV.rsp")))
        {
            if (record.GetValueOrDefault("Section") != "P-384")
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
            if (!section.StartsWith("P-384,", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] digest = Digest(section["P-384,".Length..], Convert.FromHexString(record["Msg"]));
            byte[] key = Point(record["Qx"], record["Qy"]);
            Assert.Equal(Convert.ToHexString(key), Convert.ToHexString(PublicKey(Convert.FromHexString(record["d"])).Key));
            byte[] signature = [.. Scalar(Hex(record["R"])), .. Scalar(Hex(record["S"]))];
            Assert.Equal(0, Verify(key, digest, signature));
            byte[] kPoint = PublicKey(Convert.FromHexString(record["k"])).Key;
            Assert.Equal(Hex(record["R"]), new BigInteger(kPoint.AsSpan(1, 48), isUnsigned: true, isBigEndian: true) % N);
            generated++;
        }

        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/SigVer.rsp")))
        {
            string section = record.GetValueOrDefault("Section") ?? "";
            if (!section.StartsWith("P-384,", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] digest = Digest(section["P-384,".Length..], Convert.FromHexString(record["Msg"]));
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
    /// Project Wycheproof's ECDH tests on raw points (ecdh_secp384r1_ecpoint_test.json, 790,
    /// commit 65ca494): every valid one's shared secret (771: the edge-case doublings, ephemeral
    /// keys and secrets included); the 16 invalid-curve-attack points refused with zeros; the
    /// compressed and empty encodings (3), which this function does not take (TLS 1.3 uses the
    /// uncompressed form only), never marked valid.
    /// </summary>
    [Fact]
    public void PassesWycheproofsEcdhTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0, refused = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/ecdh_secp384r1_ecpoint_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] point = Convert.FromHexString(test.GetProperty("public").GetString()!);
            byte[] key = Scalar(Hex(test.GetProperty("private").GetString()!));
            byte[] shared = Convert.FromHexString(test.GetProperty("shared").GetString()!);
            count++;
            if (point.Length != 97)
            {
                Assert.True(expected != "valid", id);
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

        Assert.Equal(790, count);
        Assert.Equal(771, valid);
        Assert.Equal(16, refused);
    }

    /// <summary>
    /// Project Wycheproof's ECDSA tests in IEEE P1363 form (r || s), SHA-384 (280) and SHA-512
    /// (318): every valid signature verifies (arithmetic edge cases, special hashes, edge-case
    /// keys, the point-duplication and Shamir edge cases), every invalid one is refused (r or s
    /// zero or n or more, the duplicated points, sizes other than 96 octets never passed).
    /// </summary>
    /// <param name="file">The file under wycheproof/.</param>
    /// <param name="tests">Its test count.</param>
    [Theory]
    [InlineData("ecdsa_secp384r1_sha384_p1363_test.json", 280)]
    [InlineData("ecdsa_secp384r1_sha512_p1363_test.json", 318)]
    public void PassesWycheproofsEcdsaTests(string file, int tests)
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/" + file)))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            Assert.NotEqual("acceptable", expected);
            byte[] key = Convert.FromHexString(group.GetProperty("publicKey").GetProperty("uncompressed").GetString()!);
            byte[] digest = Digest(group.GetProperty("sha").GetString()!, Convert.FromHexString(test.GetProperty("msg").GetString()!));
            byte[] signature = Convert.FromHexString(test.GetProperty("sig").GetString()!);
            count++;
            if (signature.Length != 96)
            {
                Assert.True(expected == "invalid", id);
                continue;
            }

            Assert.True(Verify(key, digest, signature) == (expected == "valid" ? 0 : -1), id);
        }

        Assert.Equal(tests, count);
    }

    /// <summary>
    /// .NET's ECDiffieHellman and ECDsa (the platform's OpenSSL) on 60 random key pairs: the
    /// public key of .NET's d; the shared secret both ways; our signatures (RFC 6979, and hedged
    /// with entropy) verified by .NET, .NET's signatures verified by us, and a changed digest
    /// refused by both.
    /// </summary>
    [Fact]
    public void AgreesWithDotNet()
    {
        Platform.RequireLinuxX64();
        var random = new Random(384);
        for (int i = 0; i < 60; i++)
        {
            using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            ECParameters a = alice.ExportParameters(includePrivateParameters: true);
            ECParameters b = bob.ExportParameters(includePrivateParameters: false);
            byte[] alicePublic = [0x04, .. a.Q.X!, .. a.Q.Y!];
            byte[] bobPublic = [0x04, .. b.Q.X!, .. b.Q.Y!];
            Assert.Equal(Convert.ToHexString(alicePublic), Convert.ToHexString(PublicKey(a.D!).Key));
            (int result, byte[] shared) = Ecdh(a.D!, bobPublic);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(alice.DeriveRawSecretAgreement(bob.PublicKey)), Convert.ToHexString(shared));

            using var ecdsa = ECDsa.Create(a);
            byte[] digest = new byte[48];
            random.NextBytes(digest);
            byte[]? entropy = i % 2 == 0 ? null : RandomNumberGenerator.GetBytes(48);
            (int signed, byte[] signature) = Sign(a.D!, digest, entropy);
            Assert.Equal(0, signed);
            Assert.True(ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            byte[] theirs = ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.Equal(0, Verify(alicePublic, digest, theirs));
            digest[random.Next(48)] ^= (byte)(1 << random.Next(8));
            Assert.Equal(-1, Verify(alicePublic, digest, signature));
            Assert.Equal(-1, Verify(alicePublic, digest, theirs));
            Assert.False(ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
    }

    /// <summary>
    /// Against the BigInteger model on 120 scalars, the edges first (1, 2, 3, n - 1, n - 2, n - 3,
    /// 2^383, 2^192, n / 2, the small multiples the tables hold, ones that make Booth digits
    /// negative everywhere): public keys and shared secrets by Jacobian double-and-add, signatures
    /// by RFC 6979 3.2 in C# (HMACSHA384) for digests of every length from 0 to 100 octets (the
    /// leftmost 384 bits, or all of a shorter one), with and without entropy, each verified.
    /// </summary>
    [Fact]
    public void MatchesABigIntegerModel()
    {
        Platform.RequireLinuxX64();
        var random = new Random(6979);
        BigInteger[] edges =
        [
            1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, N - 1, N - 2, N - 3, BigInteger.One << 383, BigInteger.One << 192,
            N / 2, (BigInteger.One << 384) - (BigInteger.One << 128),
            Hex("7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDE"),
            Hex("842108421084210842108421084210842108421084210842108421084210842108421084210842108421084210842108"),
            Hex("7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFDFBF7EFD"),
        ];
        for (int i = 0; i < 120; i++)
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
            byte[]? entropy = i % 3 == 0 ? null : RandomNumberGenerator.GetBytes(48);
            (BigInteger r, BigInteger s) = Rfc6979Sign(d, digest, entropy);
            (int signed, byte[] signature) = Sign(Scalar(d), digest, entropy);
            Assert.Equal(0, signed);
            Assert.Equal(Convert.ToHexString([.. Scalar(r), .. Scalar(s)]), Convert.ToHexString(signature));
            Assert.Equal(0, Verify(key, digest, signature));
        }
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
            Assert.True(Verify(Encode(q), Scalar(e), [.. Scalar(r), .. Scalar(s)]) == (valid ? 0 : -1), $"c {c}, u1 {u1}, u2 {u2}");
        }
    }

    /// <summary>
    /// What must be refused, with zeros written where there is an output: private keys 0, n, n + 1
    /// and 2^384 - 1 (all three functions that take one); public keys with any first octet but 04,
    /// with x or y equal to p, p + 1 or 2^384 - 1, or one off the curve; r or s 0, n or more; one
    /// flipped bit of a valid signature. And what must not be: n - s (ECDSA's twin signature).
    /// </summary>
    [Fact]
    public void RefusesInvalidKeysAndSignatures()
    {
        Platform.RequireLinuxX64();
        BigInteger d = Hex("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5");
        byte[] key = Encode(Multiply(d, G)!.Value);
        byte[] digest = SHA384.HashData("refuse"u8);
        (int _, byte[] valid) = Sign(Scalar(d), digest, null);
        foreach (BigInteger bad in new[] { BigInteger.Zero, N, N + 1, (BigInteger.One << 384) - 1 })
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

        foreach (BigInteger coordinate in new[] { P, P + 1, (BigInteger.One << 384) - 1 })
        {
            points.Add([0x04, .. Scalar(coordinate), .. key.AsSpan(49)]);
            points.Add([.. key.AsSpan(0, 49), .. Scalar(coordinate)]);
        }

        byte[] offCurve = (byte[])key.Clone();
        offCurve[96] ^= 1;
        points.Add(offCurve);
        points.Add(new byte[97]);
        foreach (byte[] point in points)
        {
            (int result, byte[] output) = Ecdh(Scalar(d), point);
            Assert.True(result == -1 && output.All(o => o == 0), Convert.ToHexString(point));
            Assert.Equal(-1, Verify(point, digest, valid));
        }

        BigInteger r = new(valid.AsSpan(0, 48), isUnsigned: true, isBigEndian: true);
        BigInteger s = new(valid.AsSpan(48), isUnsigned: true, isBigEndian: true);
        foreach ((BigInteger rr, BigInteger ss) in new[] { (BigInteger.Zero, s), (r, BigInteger.Zero), (N, s), (r, N), (r + N, s), ((BigInteger.One << 384) - 1, s), (r, (BigInteger.One << 384) - 1) })
        {
            if (rr < BigInteger.One << 384 && ss < BigInteger.One << 384)
            {
                Assert.Equal(-1, Verify(key, digest, [.. Scalar(rr), .. Scalar(ss)]));
            }
        }

        Assert.Equal(0, Verify(key, digest, [.. Scalar(r), .. Scalar(N - s)]));
        for (int bit = 0; bit < 768; bit += 7)
        {
            byte[] flipped = (byte[])valid.Clone();
            flipped[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(key, digest, flipped));
        }
    }

    /// <summary>One httpasm_p384_public_key call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">48 octets.</param>
    /// <returns>The result and the 97-octet public key.</returns>
    private static (int Result, byte[] Key) PublicKey(byte[] privateKey)
    {
        byte[] output = new byte[97];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey)
        {
            result = Native.P384PublicKey(o, k);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p384_ecdh call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">48 octets.</param>
    /// <param name="point">97 octets.</param>
    /// <returns>The result and the 48-octet shared secret.</returns>
    private static (int Result, byte[] Shared) Ecdh(byte[] privateKey, byte[] point)
    {
        byte[] output = new byte[48];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey, q = point)
        {
            result = Native.P384Ecdh(o, k, q);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p384_sign call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">48 octets.</param>
    /// <param name="digest">The digest (any length).</param>
    /// <param name="entropy">48 octets, or null.</param>
    /// <returns>The result and the 96-octet signature.</returns>
    private static (int Result, byte[] Signature) Sign(byte[] privateKey, byte[] digest, byte[]? entropy)
    {
        byte[] output = new byte[96];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey, h = digest, e = entropy)
        {
            result = Native.P384Sign(o, k, h, (nuint)digest.Length, e);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p384_verify call.</summary>
    /// <param name="key">97 octets.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="signature">96 octets.</param>
    /// <returns>0 or -1.</returns>
    private static int Verify(byte[] key, byte[] digest, byte[] signature)
    {
        fixed (byte* q = key, h = digest, s = signature)
        {
            return Native.P384Verify(q, h, (nuint)digest.Length, s);
        }
    }

    /// <summary>A big-endian hexadecimal integer (any length, leading zeros allowed).</summary>
    /// <param name="hex">The digits.</param>
    /// <returns>The nonnegative integer.</returns>
    private static BigInteger Hex(string hex) => new(Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex), isUnsigned: true, isBigEndian: true);

    /// <summary>A nonnegative integer below 2^384 as 48 big-endian octets.</summary>
    /// <param name="x">The integer.</param>
    /// <returns>48 octets.</returns>
    private static byte[] Scalar(BigInteger x)
    {
        byte[] octets = new byte[48];
        Assert.True(x.TryWriteBytes(octets.AsSpan(48 - x.GetByteCount(isUnsigned: true)), out _, isUnsigned: true, isBigEndian: true));
        return octets;
    }

    /// <summary>04 || x || y for a CAVP record's hex coordinates (each fits 48 octets).</summary>
    /// <param name="x">Qx.</param>
    /// <param name="y">Qy.</param>
    /// <returns>97 octets.</returns>
    /// <exception cref="InvalidDataException">A coordinate does not fit 48 octets (only PKV's
    /// out-of-range keys do, and they go through <see cref="TryPoint"/>).</exception>
    private static byte[] Point(string x, string y) => TryPoint(x, y) ?? throw new InvalidDataException($"a coordinate past 48 octets: {x}, {y}");

    /// <summary>04 || x || y, or null when a coordinate does not fit 48 octets (PKV's out-of-range keys).</summary>
    /// <param name="x">Qx in hex.</param>
    /// <param name="y">Qy in hex.</param>
    /// <returns>97 octets or null.</returns>
    private static byte[]? TryPoint(string x, string y)
    {
        BigInteger qx = Hex(x), qy = Hex(y);
        return qx >= BigInteger.One << 384 || qy >= BigInteger.One << 384 ? null : [0x04, .. Scalar(qx), .. Scalar(qy)];
    }

    /// <summary>The 97-octet uncompressed encoding of an affine point.</summary>
    /// <param name="q">The point.</param>
    /// <returns>04 || x || y.</returns>
    private static byte[] Encode((BigInteger X, BigInteger Y) q) => [0x04, .. Scalar(q.X), .. Scalar(q.Y)];

    /// <summary>A uniform scalar in [1, n - 1].</summary>
    /// <param name="random">The source.</param>
    /// <returns>The scalar.</returns>
    private static BigInteger RandomScalar(Random random)
    {
        byte[] octets = new byte[49];
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
    /// the model, fast enough at 384 bits where an affine step's inversion each would not be.
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
    /// ECDSA with RFC 6979 3.2's k from HMAC-SHA384 (and 3.6's extra input when entropy is given),
    /// as the library defines its nonces: e = bits2int(digest) mod n; candidates until 1 <= k < n
    /// and neither r nor s is 0, each refusal followed by step h.3 (K = HMAC_K(V || 0x00),
    /// V = HMAC_K(V)).
    /// </summary>
    /// <param name="d">The private key.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="entropy">48 octets or null.</param>
    /// <returns>(r, s).</returns>
    private static (BigInteger R, BigInteger S) Rfc6979Sign(BigInteger d, byte[] digest, byte[]? entropy)
    {
        BigInteger e = Bits2Int(digest) % N;
        byte[] seed = [.. Scalar(d), .. Scalar(e), .. entropy ?? []];
        byte[] v = new byte[48], k = new byte[48];
        v.AsSpan().Fill(0x01);
        byte[] input = [.. v, 0x00, .. seed];
        k = HMACSHA384.HashData(k, input);
        v = HMACSHA384.HashData(k, v);
        input = [.. v, 0x01, .. seed];
        k = HMACSHA384.HashData(k, input);
        v = HMACSHA384.HashData(k, v);
        while (true)
        {
            v = HMACSHA384.HashData(k, v);
            BigInteger candidate = new(v, isUnsigned: true, isBigEndian: true);
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
            k = HMACSHA384.HashData(k, rejected);
            v = HMACSHA384.HashData(k, v);
        }
    }

    /// <summary>RFC 6979 2.3.2's bits2int for qlen = 384: the leftmost 384 bits of the digest, or all of a shorter one.</summary>
    /// <param name="digest">The digest.</param>
    /// <returns>The integer.</returns>
    private static BigInteger Bits2Int(byte[] digest) => new(digest.AsSpan(0, Math.Min(48, digest.Length)), isUnsigned: true, isBigEndian: true);

    /// <summary>
    /// RFC 6979 A.2.6 from the pinned text (specs/rfc/rfc6979.txt): its "name = HEX" values up to
    /// the signatures (q, x, Ux, Uy), and each "With SHA-..., message = "...":" block's k, r and s.
    /// Each value is 96 hex digits on two lines: 64 after "name = ", 32 on the next, indented. The
    /// page breaks between them (form feeds, running headers) match no pattern and are passed.
    /// </summary>
    /// <returns>The key values by name, and the ten signatures.</returns>
    /// <exception cref="InvalidDataException">The section was not found, or a value's second line is missing.</exception>
    private static (Dictionary<string, BigInteger> Keys, List<(string Hash, string Message, BigInteger K, BigInteger R, BigInteger S)> Signatures) Rfc6979()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc6979.txt"));
        int start = Array.FindIndex(lines, l => l.StartsWith("A.2.6.  ECDSA, 384 Bits (Prime Field)", StringComparison.Ordinal));
        int end = start < 0 ? -1 : Array.FindIndex(lines, start + 1, l => l.StartsWith("A.2.7.", StringComparison.Ordinal));
        if (end < 0)
        {
            throw new InvalidDataException("RFC 6979's A.2.6 was not found in the pinned text");
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
                Match rest = i + 1 < end ? ContinuationLine().Match(lines[i + 1]) : Match.Empty;
                if (!rest.Success)
                {
                    throw new InvalidDataException($"RFC 6979 A.2.6: {m.Groups[1].Value}'s second line is missing");
                }

                BigInteger value = Hex(m.Groups[2].Value + rest.Groups[1].Value);
                i++;
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
    /// The key pairs of one curve in FIPS 186-4's KeyPair.rsp: its curve sections ("[P-384]") are
    /// each followed by a second bracketed line naming the generation method, which the generic
    /// <see cref="Vectors.CavpRecords"/> would take as the section; so the curve is tracked here
    /// from the lines that name one, and each d/Qx/Qy triple under the curve is returned.
    /// </summary>
    /// <param name="path">KeyPair.rsp.</param>
    /// <param name="wanted">The curve's section name ("P-384").</param>
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

    /// <summary>A CAVP curve section line: "[P-384]", "[K-233]", "[B-571]".</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^\[[PKB]-[0-9]+\]$")]
    private static partial Regex CurveLine();

    /// <summary>A signature block's heading: "   With SHA-384, message = "sample":".</summary>
    /// <returns>The pattern (hash, message).</returns>
    [GeneratedRegex("^   With (SHA-[0-9]+), message = \"([a-z]+)\":$")]
    private static partial Regex WithLine();

    /// <summary>A value's first line: "   x = 6B9D..." (64 hex digits; the 32 more are on the next line).</summary>
    /// <returns>The pattern (name, digits).</returns>
    [GeneratedRegex("^   ([A-Za-z]+) = ([0-9A-F]{64})$")]
    private static partial Regex ValueLine();

    /// <summary>A value's second line: the remaining 32 hex digits, indented.</summary>
    /// <returns>The pattern (digits).</returns>
    [GeneratedRegex("^ +([0-9A-F]{32})$")]
    private static partial Regex ContinuationLine();
}
