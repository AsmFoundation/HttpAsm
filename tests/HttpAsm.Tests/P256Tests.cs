using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_p256_public_key, httpasm_p256_ecdh, httpasm_p256_sign and httpasm_p256_verify (NIST
/// P-256) through the C ABI, held to RFC 6979 A.2.5's key pair and ten signatures (read from the
/// pinned text), every P-256 record of NIST's CAVP files (KAS ECC CDH, and FIPS 186-4's KeyPair,
/// PKV, SigGen and SigVer), Project Wycheproof's ECDH tests on raw points and its ECDSA tests in
/// IEEE P1363 form (SHA-256 and SHA-512), .NET's ECDiffieHellman and ECDsa on random keys both
/// ways, and a BigInteger model of the curve and of RFC 6979. tests/run-linux.sh runs the suite at
/// every CPU tier, so both versions answer: v3 (mulx with adcx/adox, AVX2 table scans) and v1
/// (mul, SSE2).
/// </summary>
public sealed unsafe partial class P256Tests
{
    /// <summary>The field's prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1.</summary>
    private static readonly BigInteger P = Hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

    /// <summary>The group order n.</summary>
    private static readonly BigInteger N = Hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    /// <summary>The curve's b (a = -3).</summary>
    private static readonly BigInteger B = Hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

    /// <summary>The base point G.</summary>
    private static readonly (BigInteger X, BigInteger Y) G = (
        Hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        Hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

    /// <summary>
    /// RFC 6979 A.2.5 (NIST P-256), read from the pinned text: the key pair from x; the two
    /// SHA-256 signatures exactly (this library's nonces are RFC 6979's HMAC-SHA256 ones); and
    /// all ten signatures (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 of "sample" and "test")
    /// verified, since a deterministic k is still a valid one.
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
        foreach ((string hash, string message, BigInteger k, BigInteger r, BigInteger s) in signatures)
        {
            byte[] digest = Digest(hash, Encoding.ASCII.GetBytes(message));
            byte[] signature = [.. Scalar(r), .. Scalar(s)];
            Assert.True(Verify(publicKey, digest, signature) == 0, $"{hash} \"{message}\"");
            // k's public key carries r as its x (mod n): the fixed base at RFC 6979's own nonces.
            (int kResult, byte[] kPoint) = PublicKey(Scalar(k));
            Assert.Equal(0, kResult);
            Assert.Equal(r, new BigInteger(kPoint.AsSpan(1, 32), isUnsigned: true, isBigEndian: true) % N);
            if (hash == "SHA-256")
            {
                (int signed, byte[] ours) = Sign(Scalar(x), digest, null);
                Assert.Equal(0, signed);
                Assert.Equal(Convert.ToHexString(signature), Convert.ToHexString(ours));
            }
        }
    }

    /// <summary>
    /// NIST's KAS ECC CDH primitive vectors (ecccdhtestvectors.zip), every [P-256] record: dIUT's
    /// public key is QIUT, and the shared secret of dIUT with QCAVS is ZIUT.
    /// </summary>
    [Fact]
    public void PassesNistsEcdhVectors()
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecccdh/KAS_ECC_CDH_PrimitiveTest.txt")))
        {
            if (record.GetValueOrDefault("Section") != "P-256")
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
    /// FIPS 186-4's ECDSA vectors (186-4ecdsatestvectors.zip), every P-256 record: KeyPair's 10
    /// (d's public key is Q), PKV's 12 (public key validation: a key marked P works for ECDH, one
    /// marked F, out of range or off the curve, is refused), SigGen's 60 (SHA-224 to SHA-512:
    /// every (R, S) verifies under Q, and k's public key has R as its x) and SigVer's 75 (SHA-1
    /// to SHA-512: P verifies, F does not), the digest each record's hash gives (SHA-224 through
    /// <see cref="Sha224"/>).
    /// </summary>
    [Fact]
    public void PassesNistsEcdsaVectors()
    {
        Platform.RequireLinuxX64();
        int keyPairs = 0, validations = 0, generated = 0, verified = 0;
        foreach ((string d, string qx, string qy) in P256KeyPairs(Vectors.Path("cavp/ecdsa/KeyPair.rsp")))
        {
            Assert.Equal(Convert.ToHexString(Point(qx, qy)), Convert.ToHexString(PublicKey(Convert.FromHexString(d)).Key));
            keyPairs++;
        }

        byte[] someKey = Scalar(12345);
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/PKV.rsp")))
        {
            if (record.GetValueOrDefault("Section") != "P-256")
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
            if (!section.StartsWith("P-256,", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] digest = Digest(section["P-256,".Length..], Convert.FromHexString(record["Msg"]));
            byte[] key = Point(record["Qx"], record["Qy"]);
            Assert.Equal(Convert.ToHexString(key), Convert.ToHexString(PublicKey(Convert.FromHexString(record["d"])).Key));
            byte[] signature = [.. Convert.FromHexString(record["R"]), .. Convert.FromHexString(record["S"])];
            Assert.Equal(0, Verify(key, digest, signature));
            byte[] kPoint = PublicKey(Convert.FromHexString(record["k"])).Key;
            Assert.Equal(Hex(record["R"]), new BigInteger(kPoint.AsSpan(1, 32), isUnsigned: true, isBigEndian: true) % N);
            generated++;
        }

        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/ecdsa/SigVer.rsp")))
        {
            string section = record.GetValueOrDefault("Section") ?? "";
            if (!section.StartsWith("P-256,", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] digest = Digest(section["P-256,".Length..], Convert.FromHexString(record["Msg"]));
            byte[] signature = [.. Convert.FromHexString(record["R"]), .. Convert.FromHexString(record["S"])];
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
    /// Project Wycheproof's ECDH tests on raw points (ecdh_secp256r1_ecpoint_test.json, 355, commit
    /// 65ca494): every valid one's shared secret (the 204 EdgeCaseDoubling and the edge-case
    /// ephemeral keys and secrets included); the 16 invalid-curve-attack points refused with
    /// zeros; the compressed and empty encodings, which this function does not take (TLS 1.3 uses
    /// the uncompressed form only), never marked valid.
    /// </summary>
    [Fact]
    public void PassesWycheproofsEcdhTests()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0, refused = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/ecdh_secp256r1_ecpoint_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] point = Convert.FromHexString(test.GetProperty("public").GetString()!);
            byte[] key = Scalar(Hex(test.GetProperty("private").GetString()!));
            byte[] shared = Convert.FromHexString(test.GetProperty("shared").GetString()!);
            count++;
            if (point.Length != 65)
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

        Assert.Equal(355, count);
        Assert.Equal(330, valid);
        Assert.Equal(16, refused);
    }

    /// <summary>
    /// Project Wycheproof's ECDSA tests in IEEE P1363 form (r || s), SHA-256 (262) and SHA-512
    /// (332): every valid signature verifies (arithmetic edge cases, special hashes, edge-case
    /// keys, the point-duplication and Shamir edge cases), every invalid one is refused (r or s
    /// zero or n or more, the duplicated points, sizes other than 64 octets never passed).
    /// </summary>
    /// <param name="file">The file under wycheproof/.</param>
    /// <param name="tests">Its test count.</param>
    [Theory]
    [InlineData("ecdsa_secp256r1_sha256_p1363_test.json", 262)]
    [InlineData("ecdsa_secp256r1_sha512_p1363_test.json", 332)]
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
            if (signature.Length != 64)
            {
                Assert.True(expected == "invalid", id);
                continue;
            }

            Assert.True(Verify(key, digest, signature) == (expected == "valid" ? 0 : -1), id);
        }

        Assert.Equal(tests, count);
    }

    /// <summary>
    /// .NET's ECDiffieHellman and ECDsa (the platform's OpenSSL) on 150 random key pairs: the
    /// public key of .NET's d; the shared secret both ways; our signatures (RFC 6979, and hedged
    /// with entropy) verified by .NET, .NET's signatures verified by us, and a changed digest
    /// refused by both.
    /// </summary>
    [Fact]
    public void AgreesWithDotNet()
    {
        Platform.RequireLinuxX64();
        var random = new Random(256);
        for (int i = 0; i < 150; i++)
        {
            using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ECParameters a = alice.ExportParameters(includePrivateParameters: true);
            ECParameters b = bob.ExportParameters(includePrivateParameters: false);
            byte[] alicePublic = [0x04, .. a.Q.X!, .. a.Q.Y!];
            byte[] bobPublic = [0x04, .. b.Q.X!, .. b.Q.Y!];
            Assert.Equal(Convert.ToHexString(alicePublic), Convert.ToHexString(PublicKey(a.D!).Key));
            (int result, byte[] shared) = Ecdh(a.D!, bobPublic);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(alice.DeriveRawSecretAgreement(bob.PublicKey)), Convert.ToHexString(shared));

            using var ecdsa = ECDsa.Create(a);
            byte[] digest = new byte[32];
            random.NextBytes(digest);
            byte[]? entropy = i % 2 == 0 ? null : RandomNumberGenerator.GetBytes(32);
            (int signed, byte[] signature) = Sign(a.D!, digest, entropy);
            Assert.Equal(0, signed);
            Assert.True(ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            byte[] theirs = ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.Equal(0, Verify(alicePublic, digest, theirs));
            digest[random.Next(32)] ^= (byte)(1 << random.Next(8));
            Assert.Equal(-1, Verify(alicePublic, digest, signature));
            Assert.Equal(-1, Verify(alicePublic, digest, theirs));
            Assert.False(ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
    }

    /// <summary>
    /// Against the BigInteger model on 200 scalars, the edges first (1, 2, 3, n - 1, n - 2, n - 3,
    /// 2^255, 2^128, n / 2, the small multiples the table holds, ones that make Booth digits
    /// negative everywhere): public keys and shared secrets by affine double-and-add, signatures
    /// by RFC 6979 3.2 in C# (HMACSHA256) for digests of every length from 0 to 80 octets (the
    /// leftmost 256 bits, or all of a shorter one), with and without entropy, each verified.
    /// </summary>
    [Fact]
    public void MatchesABigIntegerModel()
    {
        Platform.RequireLinuxX64();
        var random = new Random(6979);
        BigInteger[] edges =
        [
            1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 64, 65, N - 1, N - 2, N - 3, BigInteger.One << 255, BigInteger.One << 128,
            N / 2, (BigInteger.One << 256) - (BigInteger.One << 224), Hex("7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDEF7BDE"),
            Hex("8421084210842108421084210842108421084210842108421084210842108421"),
        ];
        for (int i = 0; i < 200; i++)
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

            byte[] digest = new byte[i % 81];
            random.NextBytes(digest);
            byte[]? entropy = i % 3 == 0 ? null : RandomNumberGenerator.GetBytes(32);
            (BigInteger r, BigInteger s, int _) = Rfc6979Sign(d, digest, entropy);
            (int signed, byte[] signature) = Sign(Scalar(d), digest, entropy);
            Assert.Equal(0, signed);
            Assert.Equal(Convert.ToHexString([.. Scalar(r), .. Scalar(s)]), Convert.ToHexString(signature));
            Assert.Equal(0, Verify(key, digest, signature));
        }
    }

    /// <summary>
    /// RFC 6979 3.2's step h.3, the retry after a candidate k out of range, which one signature in
    /// about 2^32 meets: with RFC 6979 A.2.5's key, SHA-256 of "sample" and this entropy (found by
    /// a search over 702 million draws, the scratchpad's p256/retry_search.c), the first candidate
    /// is FFFFFFFF3F01F7D1... (n or more), so the signature comes from the second one; it must equal
    /// the reference, which counts the refusal, and verify.
    /// </summary>
    [Fact]
    public void RetriesANonceCandidateOfNOrMore()
    {
        Platform.RequireLinuxX64();
        BigInteger d = Hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        byte[] digest = SHA256.HashData("sample"u8);
        byte[] entropy = Convert.FromHexString("5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A1D000000014EECBF");
        (BigInteger r, BigInteger s, int refused) = Rfc6979Sign(d, digest, entropy);
        Assert.Equal(1, refused);
        (int result, byte[] signature) = Sign(Scalar(d), digest, entropy);
        Assert.Equal(0, result);
        Assert.Equal(Convert.ToHexString([.. Scalar(r), .. Scalar(s)]), Convert.ToHexString(signature));
        Assert.Equal(0, Verify(Encode(Multiply(d, G)!.Value), digest, signature));
    }

    /// <summary>
    /// The verification's variable-time additions at their edges. Its single pass (wNAF digits of
    /// u1 by 7 bits and of u2 by 5, from the top, u1's digit before u2's at each position) can meet
    /// equal or opposite points; with a public key Q = c G and a signature built for chosen u1 and
    /// u2 (r = x(u1 G + u2 Q) mod n, s = r / u2, e = u1 s, which give back exactly u1 and u2) each
    /// case is reached on purpose:
    /// - the mixed addition doubling: c = (n + 1) / 2, u1 = 1, u2 = 2: u2's digit at position 1 puts
    ///   c G in, the doubling makes it (n + 1) G = G, and u1's digit adds G to G; R = 2G: valid;
    /// - the mixed addition cancelling: c = -(n + 1) / 2: the accumulator is -G when u1's G comes,
    ///   so R is at infinity: refused (r, s built for any r);
    /// - the Jacobian addition doubling: Q = G, u1 = u2 = 1: G, then G again; R = 2G: valid;
    /// - the Jacobian addition cancelling: Q = -G, u1 = u2 = 1: R at infinity: refused.
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
    /// and 2^256 - 1 (all four functions that take one); public keys with any first octet but 04,
    /// with x or y equal to p, p + 1 or 2^256 - 1, or one off the curve; r or s 0, n or more; one
    /// flipped bit of a valid signature. And what must not be: n - s (ECDSA's twin signature).
    /// </summary>
    [Fact]
    public void RefusesInvalidKeysAndSignatures()
    {
        Platform.RequireLinuxX64();
        BigInteger d = Hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        byte[] key = Encode(Multiply(d, G)!.Value);
        byte[] digest = SHA256.HashData("refuse"u8);
        (int _, byte[] valid) = Sign(Scalar(d), digest, null);
        foreach (BigInteger bad in new[] { BigInteger.Zero, N, N + 1, (BigInteger.One << 256) - 1 })
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

        foreach (BigInteger coordinate in new[] { P, P + 1, (BigInteger.One << 256) - 1 })
        {
            points.Add([0x04, .. Scalar(coordinate), .. key.AsSpan(33)]);
            points.Add([.. key.AsSpan(0, 33), .. Scalar(coordinate)]);
        }

        byte[] offCurve = (byte[])key.Clone();
        offCurve[64] ^= 1;
        points.Add(offCurve);
        points.Add(new byte[65]);
        foreach (byte[] point in points)
        {
            (int result, byte[] output) = Ecdh(Scalar(d), point);
            Assert.True(result == -1 && output.All(o => o == 0), Convert.ToHexString(point));
            Assert.Equal(-1, Verify(point, digest, valid));
        }

        BigInteger r = new(valid.AsSpan(0, 32), isUnsigned: true, isBigEndian: true);
        BigInteger s = new(valid.AsSpan(32), isUnsigned: true, isBigEndian: true);
        foreach ((BigInteger rr, BigInteger ss) in new[] { (BigInteger.Zero, s), (r, BigInteger.Zero), (N, s), (r, N), (r + N, s), ((BigInteger.One << 256) - 1, s), (r, (BigInteger.One << 256) - 1) })
        {
            if (rr < BigInteger.One << 256 && ss < BigInteger.One << 256)
            {
                Assert.Equal(-1, Verify(key, digest, [.. Scalar(rr), .. Scalar(ss)]));
            }
        }

        Assert.Equal(0, Verify(key, digest, [.. Scalar(r), .. Scalar(N - s)]));
        for (int bit = 0; bit < 512; bit += 7)
        {
            byte[] flipped = (byte[])valid.Clone();
            flipped[bit / 8] ^= (byte)(1 << (bit % 8));
            Assert.Equal(-1, Verify(key, digest, flipped));
        }
    }

    /// <summary>One httpasm_p256_public_key call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">32 octets.</param>
    /// <returns>The result and the 65-octet public key.</returns>
    private static (int Result, byte[] Key) PublicKey(byte[] privateKey)
    {
        byte[] output = new byte[65];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey)
        {
            result = Native.P256PublicKey(o, k);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p256_ecdh call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">32 octets.</param>
    /// <param name="point">65 octets.</param>
    /// <returns>The result and the 32-octet shared secret.</returns>
    private static (int Result, byte[] Shared) Ecdh(byte[] privateKey, byte[] point)
    {
        byte[] output = new byte[32];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey, q = point)
        {
            result = Native.P256Ecdh(o, k, q);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p256_sign call (the output pre-filled with 0xEE).</summary>
    /// <param name="privateKey">32 octets.</param>
    /// <param name="digest">The digest (any length).</param>
    /// <param name="entropy">32 octets, or null.</param>
    /// <returns>The result and the 64-octet signature.</returns>
    private static (int Result, byte[] Signature) Sign(byte[] privateKey, byte[] digest, byte[]? entropy)
    {
        byte[] output = new byte[64];
        output.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* o = output, k = privateKey, h = digest, e = entropy)
        {
            result = Native.P256Sign(o, k, h, (nuint)digest.Length, e);
        }

        return (result, output);
    }

    /// <summary>One httpasm_p256_verify call.</summary>
    /// <param name="key">65 octets.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="signature">64 octets.</param>
    /// <returns>0 or -1.</returns>
    private static int Verify(byte[] key, byte[] digest, byte[] signature)
    {
        fixed (byte* q = key, h = digest, s = signature)
        {
            return Native.P256Verify(q, h, (nuint)digest.Length, s);
        }
    }

    /// <summary>A big-endian hexadecimal integer (any length, leading zeros allowed).</summary>
    /// <param name="hex">The digits.</param>
    /// <returns>The nonnegative integer.</returns>
    private static BigInteger Hex(string hex) => new(Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex), isUnsigned: true, isBigEndian: true);

    /// <summary>A nonnegative integer below 2^256 as 32 big-endian octets.</summary>
    /// <param name="x">The integer.</param>
    /// <returns>32 octets.</returns>
    private static byte[] Scalar(BigInteger x)
    {
        byte[] octets = new byte[32];
        Assert.True(x.TryWriteBytes(octets.AsSpan(32 - x.GetByteCount(isUnsigned: true)), out _, isUnsigned: true, isBigEndian: true));
        return octets;
    }

    /// <summary>04 || x || y for a CAVP record's hex coordinates (each fits 32 octets).</summary>
    /// <param name="x">Qx.</param>
    /// <param name="y">Qy.</param>
    /// <returns>65 octets.</returns>
    /// <exception cref="InvalidDataException">A coordinate does not fit 32 octets (only PKV's
    /// out-of-range keys do, and they go through <see cref="TryPoint"/>).</exception>
    private static byte[] Point(string x, string y) => TryPoint(x, y) ?? throw new InvalidDataException($"a coordinate past 32 octets: {x}, {y}");

    /// <summary>04 || x || y, or null when a coordinate does not fit 32 octets (PKV's out-of-range keys).</summary>
    /// <param name="x">Qx in hex.</param>
    /// <param name="y">Qy in hex.</param>
    /// <returns>65 octets or null.</returns>
    private static byte[]? TryPoint(string x, string y)
    {
        BigInteger qx = Hex(x), qy = Hex(y);
        return qx >= BigInteger.One << 256 || qy >= BigInteger.One << 256 ? null : [0x04, .. Scalar(qx), .. Scalar(qy)];
    }

    /// <summary>The 65-octet uncompressed encoding of an affine point.</summary>
    /// <param name="q">The point.</param>
    /// <returns>04 || x || y.</returns>
    private static byte[] Encode((BigInteger X, BigInteger Y) q) => [0x04, .. Scalar(q.X), .. Scalar(q.Y)];

    /// <summary>A uniform scalar in [1, n - 1].</summary>
    /// <param name="random">The source.</param>
    /// <returns>The scalar.</returns>
    private static BigInteger RandomScalar(Random random)
    {
        byte[] octets = new byte[33];
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

    /// <summary>k q by double-and-add.</summary>
    /// <param name="k">The scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>k q, or null for infinity.</returns>
    private static (BigInteger X, BigInteger Y)? Multiply(BigInteger k, (BigInteger X, BigInteger Y) q)
    {
        (BigInteger X, BigInteger Y)? result = null, addend = q;
        for (; !k.IsZero; k >>= 1)
        {
            if (!k.IsEven)
            {
                result = Add(result, addend);
            }

            addend = Add(addend, addend);
        }

        return result;
    }

    /// <summary>
    /// ECDSA with RFC 6979 3.2's k from HMAC-SHA256 (and 3.6's extra input when entropy is given),
    /// as the library defines its nonces: e = bits2int(digest) mod n; candidates until 1 <= k < n
    /// and neither r nor s is 0, each refusal followed by step h.3 (K = HMAC_K(V || 0x00),
    /// V = HMAC_K(V)).
    /// </summary>
    /// <param name="d">The private key.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="entropy">32 octets or null.</param>
    /// <returns>(r, s), and how many candidates were refused before them (0 almost always).</returns>
    private static (BigInteger R, BigInteger S, int Refused) Rfc6979Sign(BigInteger d, byte[] digest, byte[]? entropy)
    {
        BigInteger e = Bits2Int(digest) % N;
        byte[] seed = [.. Scalar(d), .. Scalar(e), .. entropy ?? []];
        byte[] v = new byte[32], k = new byte[32];
        v.AsSpan().Fill(0x01);
        byte[] input = [.. v, 0x00, .. seed];
        k = HMACSHA256.HashData(k, input);
        v = HMACSHA256.HashData(k, v);
        input = [.. v, 0x01, .. seed];
        k = HMACSHA256.HashData(k, input);
        v = HMACSHA256.HashData(k, v);
        for (int refused = 0; ; refused++)
        {
            v = HMACSHA256.HashData(k, v);
            BigInteger candidate = new(v, isUnsigned: true, isBigEndian: true);
            if (candidate >= 1 && candidate < N)
            {
                BigInteger r = Multiply(candidate, G)!.Value.X % N;
                BigInteger s = BigInteger.ModPow(candidate, N - 2, N) * (e + r * d) % N;
                if (!r.IsZero && !s.IsZero)
                {
                    return (r, s, refused);
                }
            }

            byte[] rejected = [.. v, 0x00];
            k = HMACSHA256.HashData(k, rejected);
            v = HMACSHA256.HashData(k, v);
        }
    }

    /// <summary>RFC 6979 2.3.2's bits2int for qlen = 256: the leftmost 256 bits of the digest, or all of a shorter one.</summary>
    /// <param name="digest">The digest.</param>
    /// <returns>The integer.</returns>
    private static BigInteger Bits2Int(byte[] digest) => new(digest.AsSpan(0, Math.Min(32, digest.Length)), isUnsigned: true, isBigEndian: true);

    /// <summary>A message's digest by the hash a vector file names ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA512").</summary>
    /// <param name="hash">The name.</param>
    /// <param name="message">The message.</param>
    /// <returns>The digest.</returns>
    /// <exception cref="InvalidDataException">An unknown hash.</exception>
    private static byte[] Digest(string hash, byte[] message) => hash.Replace("-", "", StringComparison.Ordinal) switch
    {
        "SHA1" => SHA1.HashData(message),
        "SHA224" => Sha224(message),
        "SHA256" => SHA256.HashData(message),
        "SHA384" => SHA384.HashData(message),
        "SHA512" => SHA512.HashData(message),
        _ => throw new InvalidDataException("unknown hash " + hash),
    };

    /// <summary>
    /// SHA-224 (FIPS 180-4 6.3: SHA-256 from its own initial value, the digest cut to 28 octets),
    /// which .NET does not offer and which RFC 6979's and the CAVP files' P-256 vectors use.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <returns>The 28-octet digest.</returns>
    private static byte[] Sha224(byte[] message)
    {
        uint[] k =
        [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        uint[] h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
        int padded = (message.Length + 9 + 63) / 64 * 64;
        byte[] data = new byte[padded];
        message.CopyTo(data, 0);
        data[message.Length] = 0x80;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(padded - 8), (ulong)message.Length * 8);
        uint[] w = new uint[64];
        for (int block = 0; block < padded; block += 64)
        {
            for (int t = 0; t < 16; t++)
            {
                w[t] = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(block + 4 * t));
            }

            for (int t = 16; t < 64; t++)
            {
                uint s0 = BitOperations.RotateRight(w[t - 15], 7) ^ BitOperations.RotateRight(w[t - 15], 18) ^ (w[t - 15] >> 3);
                uint s1 = BitOperations.RotateRight(w[t - 2], 17) ^ BitOperations.RotateRight(w[t - 2], 19) ^ (w[t - 2] >> 10);
                w[t] = w[t - 16] + s0 + w[t - 7] + s1;
            }

            uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int t = 0; t < 64; t++)
            {
                uint t1 = hh + (BitOperations.RotateRight(e, 6) ^ BitOperations.RotateRight(e, 11) ^ BitOperations.RotateRight(e, 25)) + ((e & f) ^ (~e & g)) + k[t] + w[t];
                uint t2 = (BitOperations.RotateRight(a, 2) ^ BitOperations.RotateRight(a, 13) ^ BitOperations.RotateRight(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                (hh, g, f, e, d, c, b, a) = (g, f, e, d + t1, c, b, a, t1 + t2);
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }

        byte[] digest = new byte[28];
        for (int i = 0; i < 7; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(digest.AsSpan(4 * i), h[i]);
        }

        return digest;
    }

    /// <summary>
    /// RFC 6979 A.2.5 from the pinned text (specs/rfc/rfc6979.txt): its "name = HEX" lines up to
    /// the signatures (q, x, Ux, Uy), and each "With SHA-..., message = "...":" block's k, r and s.
    /// The page breaks between them (form feeds, running headers) match no pattern and are passed.
    /// </summary>
    /// <returns>The key values by name, and the ten signatures.</returns>
    /// <exception cref="InvalidDataException">The section was not found.</exception>
    private static (Dictionary<string, BigInteger> Keys, List<(string Hash, string Message, BigInteger K, BigInteger R, BigInteger S)> Signatures) Rfc6979()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc6979.txt"));
        int start = Array.FindIndex(lines, l => l.StartsWith("A.2.5.  ECDSA, 256 Bits (Prime Field)", StringComparison.Ordinal));
        int end = start < 0 ? -1 : Array.FindIndex(lines, start + 1, l => l.StartsWith("A.2.6.", StringComparison.Ordinal));
        if (end < 0)
        {
            throw new InvalidDataException("RFC 6979's A.2.5 was not found in the pinned text");
        }

        var keys = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        var signatures = new List<(string, string, BigInteger, BigInteger, BigInteger)>();
        string? hash = null, message = null;
        var values = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        foreach (string line in lines[start..end])
        {
            Match m;
            if ((m = WithLine().Match(line)).Success)
            {
                hash = m.Groups[1].Value;
                message = m.Groups[2].Value;
                values.Clear();
            }
            else if ((m = ValueLine().Match(line)).Success)
            {
                if (hash is null)
                {
                    keys[m.Groups[1].Value] = Hex(m.Groups[2].Value);
                }
                else
                {
                    values[m.Groups[1].Value] = Hex(m.Groups[2].Value);
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
    /// The P-256 key pairs of FIPS 186-4's KeyPair.rsp: its curve sections ("[P-256]") are each
    /// followed by a second bracketed line naming the generation method, which the generic
    /// <see cref="Vectors.CavpRecords"/> would take as the section; so the curve is tracked here
    /// from the lines that name one, and each d/Qx/Qy triple under P-256 is returned.
    /// </summary>
    /// <param name="path">KeyPair.rsp.</param>
    /// <returns>(d, Qx, Qy) in hex, file order.</returns>
    private static IEnumerable<(string D, string Qx, string Qy)> P256KeyPairs(string path)
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
            else if (line.StartsWith("Qy = ", StringComparison.Ordinal) && curve == "P-256" && d is not null && qx is not null)
            {
                yield return (d, qx, line[5..]);
            }
        }
    }

    /// <summary>A CAVP curve section line: "[P-256]", "[K-233]", "[B-571]".</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^\[[PKB]-[0-9]+\]$")]
    private static partial Regex CurveLine();

    /// <summary>A signature block's heading: "   With SHA-256, message = "sample":".</summary>
    /// <returns>The pattern (hash, message).</returns>
    [GeneratedRegex("^   With (SHA-[0-9]+), message = \"([a-z]+)\":$")]
    private static partial Regex WithLine();

    /// <summary>A value line: "   x = C9AF..." (64 hex digits, one line in A.2.5).</summary>
    /// <returns>The pattern (name, digits).</returns>
    [GeneratedRegex("^   ([A-Za-z]+) = ([0-9A-F]{64})$")]
    private static partial Regex ValueLine();
}
