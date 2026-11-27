using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static HttpAsm.Tests.Digests;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_rsa_public_key_init, httpasm_rsa_verify_pkcs1 and httpasm_rsa_verify_pss (RFC 8017)
/// through the C ABI, held to NIST's CAVP files (FIPS 186-3's SigVer15, SigVerPSS, SigGen15 and
/// SigGenPSS: 700 signatures of 1024 to 3072 bits), Project Wycheproof's RSASSA-PKCS1-v1_5 tests
/// at 2048 to 8192 bits and its RSASSA-PSS ones, .NET's RSA (the platform's OpenSSL) on fresh
/// keys, RFC 8017's own DigestInfo prefixes (read from the pinned text), and a BigInteger model:
/// of the key's preparation (R^2 mod n by long division, each of its paths reached on purpose)
/// and of RFC 8017's encodings, signed with the private exponent of keys whose moduli are chosen
/// (primes of 1024, 1025 and 2049 bits, the last two one bit past an octet, where PSS's encoded
/// message is an octet shorter than the signature). tests/run-linux.sh runs the suite at every CPU
/// tier, so both versions of the arithmetic answer: v3 (mulx with adcx/adox: the product, the
/// square, the reduction) and v1 (mul).
/// </summary>
public sealed unsafe class RsaTests
{
    /// <summary>The hashes this library verifies PKCS#1 v1.5 signatures with, by HTTPASM_HASH_* order.</summary>
    private static readonly string[] Pkcs1Hashes = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

    /// <summary>The hashes it verifies PSS signatures with (MGF1 on the same hash).</summary>
    private static readonly string[] PssHashes = ["SHA-256", "SHA-384", "SHA-512"];

    /// <summary>The key's size, as the library reports it (struct size 16) and as the tests' copy lays it out.</summary>
    [Fact]
    public void HasTheKeysLayout()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(2080, sizeof(RsaPublicKey));
        Assert.Equal((uint)sizeof(RsaPublicKey), Native.StructSize(16));
    }

    /// <summary>
    /// The init against a BigInteger model of every field of the key (n's limbs, R^2 mod n for
    /// R = 2^(64k), -n^-1 mod 2^64, e, k = n's limbs rounded up to 8, the bit length, zeros above
    /// and in the reserved field), for random moduli at each size where the limbs or the octets
    /// change (1024 to 8192 bits: each 64- and 512-bit boundary and either side of it), and for
    /// moduli shaped to reach each path of the long division that makes R^2 mod n (found by a
    /// model of it, the scratchpad's rsa/knuth_paths.py):
    /// - 2^1024 - 2^64 + 1: a quotient digit clamped to 2^64 - 1 (the window's top limb equals N's)
    ///   and then lowered once by Knuth's test with N's second limb;
    /// - 2^1024 - 2^128 + 1: a clamped digit whose remainder passes 2^64 (so no test), and an
    ///   add-back;
    /// - 2^1024 - 2^65 + 1: a lowering that carries the remainder past 2^64 (the test stops there);
    /// - 2^1023 + 2^960 - 1: digits lowered twice;
    /// - 2^1023 + 3: the add-back (the digit one too big after the test);
    /// - 2^1024 + 1: a top limb of 1, normalized by 63 bits: a clamp at the first digit and two
    ///   add-backs;
    /// - 2^8192 - 1 and 2^8191 + 1: the largest k (128 limbs; a dividend of 258).
    /// The octet strings carry 0 to 2 leading zero octets, and e runs from 3 to 2^64 - 1.
    /// </summary>
    [Fact]
    public void PreparesKeysAsABigIntegerModelDoes()
    {
        Platform.RequireLinuxX64();
        var random = new Random(8017);
        var moduli = new List<BigInteger>
        {
            (BigInteger.One << 1024) - (BigInteger.One << 64) + 1,
            (BigInteger.One << 1024) - (BigInteger.One << 128) + 1,
            (BigInteger.One << 1024) - (BigInteger.One << 65) + 1,
            (BigInteger.One << 1023) + (BigInteger.One << 960) - 1,
            (BigInteger.One << 1023) + 3,
            (BigInteger.One << 1024) + 1,
            (BigInteger.One << 8192) - 1,
            (BigInteger.One << 8191) + 1,
        };
        foreach (int bits in new[] { 1024, 1025, 1087, 1088, 1089, 1535, 1536, 1537, 1600, 2047, 2048, 2049, 2112, 3071, 3072, 3073, 4095, 4096, 4097, 6143, 6144, 6145, 8191, 8192 })
        {
            for (int i = 0; i < 3; i++)
            {
                moduli.Add(RandomOdd(random, bits));
            }
        }

        BigInteger[] exponents = [3, 65537, (BigInteger.One << 64) - 1, (BigInteger.One << 32) + 1, 17, 0x1_0000_0001];
        for (int i = 0; i < moduli.Count; i++)
        {
            BigInteger n = moduli[i];
            BigInteger e = exponents[i % exponents.Length];
            (int result, RsaPublicKey key) = Init([.. new byte[i % 3], .. Octets(n)], [.. new byte[i % 2], .. Octets(e)]);
            Assert.True(result == 0, $"n of {n.GetBitLength()} bits, modulus #{i}");
            AssertKey(key, n, e);
        }
    }

    /// <summary>
    /// The keys the init must refuse, each leaving the key all zeros over a pattern that filled it
    /// first: n even; n of 1023 bits (the largest below the minimum) and 8193 (more than 1024
    /// octets); n 0, 1, empty, or 1024 zero octets; e 0, 1, 2, even, empty, all zeros, or 2^64 + 1
    /// (9 octets). And the ones at the limits it must take: n of exactly 1024 bits and 2^8192 - 1
    /// (1024 octets of FF), n after leading zeros, e 2^64 - 1, e after leading zeros. A refused
    /// key fails every verification, a signature of length 0 (its own octets' count) included.
    /// </summary>
    [Fact]
    public void RefusesKeysOutsideItsLimits()
    {
        Platform.RequireLinuxX64();
        var random = new Random(1024);
        BigInteger good = RandomOdd(random, 2048);
        byte[] e65537 = [1, 0, 1];
        (byte[] N, byte[] E, bool Accepted, string What)[] cases =
        [
            (Octets(good), e65537, true, "a 2048-bit key"),
            (Octets(good - 1), e65537, false, "n even"),
            (Octets(RandomOdd(random, 1023)), e65537, false, "n of 1023 bits"),
            (Octets(RandomOdd(random, 1024)), e65537, true, "n of 1024 bits"),
            (Octets((BigInteger.One << 8192) + 1), e65537, false, "n of 8193 bits"),
            (Octets((BigInteger.One << 8192) - 1), e65537, true, "n = 2^8192 - 1"),
            ([0], e65537, false, "n = 0"),
            ([1], e65537, false, "n = 1"),
            ([], e65537, false, "n empty"),
            (new byte[1024], e65537, false, "n of 1024 zero octets"),
            ([.. new byte[700], .. Octets(good)], e65537, true, "n after 700 zero octets"),
            (Octets(good), [0], false, "e = 0"),
            (Octets(good), [1], false, "e = 1"),
            (Octets(good), [2], false, "e = 2"),
            (Octets(good), [1, 0, 0], false, "e = 65536 (even)"),
            (Octets(good), [], false, "e empty"),
            (Octets(good), new byte[9], false, "e of 9 zero octets"),
            (Octets(good), [1, 0, 0, 0, 0, 0, 0, 0, 1], false, "e = 2^64 + 1"),
            (Octets(good), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], true, "e = 2^64 - 1"),
            (Octets(good), [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1], true, "e = 65537 after 9 zero octets"),
        ];
        foreach ((byte[] n, byte[] e, bool accepted, string what) in cases)
        {
            RsaPublicKey key;
            new Span<byte>(&key, sizeof(RsaPublicKey)).Fill(0xA5);
            int result;
            fixed (byte* pn = n)
            fixed (byte* pe = e)
            {
                result = Native.RsaPublicKeyInit(&key, pn, (nuint)n.Length, pe, (nuint)e.Length);
            }

            if (accepted)
            {
                Assert.True(result == 0, what);
                AssertKey(key, Unsigned(n), Unsigned(e));
                continue;
            }

            Assert.True(result == -1, what);
            Assert.True(new ReadOnlySpan<byte>(&key, sizeof(RsaPublicKey)).IndexOfAnyExcept((byte)0) < 0, what + ": the key not all zeros");
            byte[] digest = SHA256.HashData("refused"u8);
            Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, []));
            Assert.Equal(-1, VerifyPss(ref key, 3, digest, 0, []));
            Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, new byte[256]));
        }
    }

    /// <summary>
    /// FIPS 186-3's SigVer15 file (186-3rsatestvectors.zip): 270 PKCS#1 v1.5 signatures of 1024,
    /// 2048 and 3072 bits with SHA-1 to SHA-512 and their own exponents, 45 valid; the rest have a
    /// changed message, exponent, signature or encoding. P verifies, F does not.
    /// </summary>
    [Fact]
    public void PassesNistsSigVer15Vectors()
    {
        Platform.RequireLinuxX64();
        int count = 0, valid = 0;
        string? modulus = null;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/rsa/SigVer15_186-3.rsp")))
        {
            if (record.TryGetValue("n", out string? n))
            {
                modulus = n;
                continue;
            }

            if (!record.ContainsKey("S"))
            {
                continue;
            }

            (int result, RsaPublicKey key) = Init(Hex(modulus!), Hex(record["e"]));
            Assert.Equal(0, result);
            byte[] digest = Digest(record["SHAAlg"], Hex(record["Msg"]));
            bool pass = record["Result"].StartsWith('P');
            Assert.True(VerifyPkcs1(ref key, HashId(record["SHAAlg"]), digest, Hex(record["S"])) == (pass ? 0 : -1), $"SigVer15 {record["mod"]} {record["SHAAlg"]}: {record["Result"]}");
            count++;
            valid += pass ? 1 : 0;
        }

        Assert.Equal(270, count);
        Assert.Equal(45, valid);
    }

    /// <summary>
    /// FIPS 186-3's SigVerPSS file: 270 PSS signatures of 1024, 2048 and 3072 bits, salts of 0 to
    /// 64 octets (CAVS writes an empty salt as "SaltVal = 00": two hex digits, where every other
    /// salt here has 20 octets or more), 45 valid; the rest with a changed message, exponent or
    /// signature, the hash moved, or the 01 before the salt removed. With SHA-256, SHA-384 and
    /// SHA-512, P verifies (27) and F does not; SHA-1 and SHA-224 ones are refused whatever their
    /// result, as this library verifies PSS with those three hashes only.
    /// </summary>
    [Fact]
    [Requirement("RFC8017-8-p3")]
    public void PassesNistsSigVerPssVectors()
    {
        Platform.RequireLinuxX64();
        int count = 0, accepted = 0;
        string? modulus = null;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/rsa/SigVerPSS_186-3.rsp")))
        {
            if (record.TryGetValue("n", out string? n))
            {
                modulus = n;
                continue;
            }

            if (!record.ContainsKey("S"))
            {
                continue;
            }

            (int result, RsaPublicKey key) = Init(Hex(modulus!), Hex(record["e"]));
            Assert.Equal(0, result);
            string hash = record["SHAAlg"];
            byte[] digest = Digest(hash, Hex(record["Msg"]));
            int saltLength = record["SaltVal"].Length == 2 ? 0 : record["SaltVal"].Length / 2;
            bool expected = record["Result"].StartsWith('P') && PssHashes.Contains(Dashed(hash));
            int verified = VerifyPss(ref key, HashId(hash), digest, (nuint)saltLength, Hex(record["S"]));
            Assert.True(verified == (expected ? 0 : -1), $"SigVerPSS {record["mod"]} {hash} salt {saltLength}: {record["Result"]}");
            count++;
            accepted += verified == 0 ? 1 : 0;
        }

        Assert.Equal(270, count);
        Assert.Equal(27, accepted);
    }

    /// <summary>
    /// FIPS 186-3's SigGen15 and SigGenPSS files: the 80 PKCS#1 v1.5 signatures (2048 and 3072
    /// bits, SHA-224 to SHA-512) all verify; of the 80 PSS ones, whose salt lengths the file's
    /// header gives per modulus and hash ("SHA-256(Salt len: 20)"), the 60 with SHA-256, SHA-384
    /// and SHA-512 verify and the SHA-224 ones are refused.
    /// </summary>
    [Fact]
    public void VerifiesNistsSigGenSignatures()
    {
        Platform.RequireLinuxX64();
        int pkcs1 = 0;
        string? modulus = null, exponent = null;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(Vectors.Path("cavp/rsa/SigGen15_186-3.rsp")))
        {
            if (TrackKey(record, ref modulus, ref exponent))
            {
                continue;
            }

            (int result, RsaPublicKey key) = Init(Hex(modulus!), Hex(exponent!));
            Assert.Equal(0, result);
            Assert.True(VerifyPkcs1(ref key, HashId(record["SHAAlg"]), Digest(record["SHAAlg"], Hex(record["Msg"])), Hex(record["S"])) == 0, $"SigGen15 {record["mod"]} {record["SHAAlg"]}");
            pkcs1++;
        }

        string path = Vectors.Path("cavp/rsa/SigGenPSS_186-3.rsp");
        Dictionary<(string Mod, string Hash), int> salts = SigGenPssSaltLengths(path);
        Assert.Equal(8, salts.Count);
        int pss = 0, accepted = 0;
        modulus = exponent = null;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path))
        {
            if (TrackKey(record, ref modulus, ref exponent))
            {
                continue;
            }

            (int result, RsaPublicKey key) = Init(Hex(modulus!), Hex(exponent!));
            Assert.Equal(0, result);
            string hash = record["SHAAlg"];
            int saltLength = salts[(record["mod"], Dashed(hash))];
            bool supported = PssHashes.Contains(Dashed(hash));
            int verified = VerifyPss(ref key, HashId(hash), Digest(hash, Hex(record["Msg"])), (nuint)saltLength, Hex(record["S"]));
            Assert.True(verified == (supported ? 0 : -1), $"SigGenPSS {record["mod"]} {hash} salt {saltLength}");
            pss++;
            accepted += verified == 0 ? 1 : 0;
        }

        Assert.Equal(80, pkcs1);
        Assert.Equal(80, pss);
        Assert.Equal(60, accepted);
    }

    /// <summary>
    /// Project Wycheproof's RSASSA-PKCS1-v1_5 tests: every valid signature verifies (exponents 3
    /// and 65537, small signatures and ones close to n among them) and every invalid one is
    /// refused (BER and other DigestInfo encodings, changed paddings, wrong hashes, lengths other
    /// than the modulus', values of n or more). The one "acceptable" test of each file, a
    /// DigestInfo without the NULL parameters, is refused: RFC 8017 C's exception for
    /// EMSA-PKCS1-v1_5 makes the NULL part of the encoding, and verification compares encodings.
    /// </summary>
    /// <param name="file">The file under wycheproof/.</param>
    /// <param name="tests">Its test count.</param>
    [Theory]
    [InlineData("rsa_signature_2048_sha224_test.json", 258)]
    [InlineData("rsa_signature_2048_sha256_test.json", 259)]
    [InlineData("rsa_signature_2048_sha384_test.json", 258)]
    [InlineData("rsa_signature_2048_sha512_test.json", 259)]
    [InlineData("rsa_signature_3072_sha256_test.json", 259)]
    [InlineData("rsa_signature_3072_sha384_test.json", 259)]
    [InlineData("rsa_signature_3072_sha512_test.json", 260)]
    [InlineData("rsa_signature_4096_sha256_test.json", 258)]
    [InlineData("rsa_signature_4096_sha384_test.json", 259)]
    [InlineData("rsa_signature_4096_sha512_test.json", 259)]
    [InlineData("rsa_signature_8192_sha256_test.json", 258)]
    [InlineData("rsa_signature_8192_sha384_test.json", 259)]
    [InlineData("rsa_signature_8192_sha512_test.json", 259)]
    [Requirement("RFC8017-C-p30")]
    public void PassesWycheproofsPkcs1Tests(string file, int tests)
    {
        Platform.RequireLinuxX64();
        int count = 0, acceptable = 0;
        foreach ((JsonElement group, JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/" + file)))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            (int result, RsaPublicKey key) = WycheproofKey(group);
            Assert.True(result == 0, id);
            string hash = group.GetProperty("sha").GetString()!;
            byte[] digest = Digest(hash, Hex(test.GetProperty("msg").GetString()!));
            int verified = VerifyPkcs1(ref key, HashId(hash), digest, Hex(test.GetProperty("sig").GetString()!));
            if (expected == "acceptable")
            {
                Assert.Equal(new[] { "MissingNull" }, test.GetProperty("flags").EnumerateArray().Select(f => f.GetString()!));
                acceptable++;
            }

            Assert.True(verified == (expected == "valid" ? 0 : -1), id);
            count++;
        }

        Assert.Equal(tests, count);
        Assert.Equal(1, acceptable);
    }

    /// <summary>
    /// Project Wycheproof's RSASSA-PSS tests. Where the hash is SHA-256, SHA-384 or SHA-512 and
    /// MGF1 runs on the same hash (what this library verifies, as RFC 8017 recommends), every
    /// valid signature verifies (salts of 0 to 64 octets, special-case hashes) and every invalid
    /// one is refused (modified signatures, wrong primitives). Every other pairing - the misc
    /// file's SHA-1 and SHA-224 and its mixed MGF1 hashes, a whole SHA-1 file, a whole MGF1-SHA1
    /// file - is refused, valid or not.
    /// </summary>
    /// <param name="file">The file under wycheproof/.</param>
    /// <param name="tests">Its test count.</param>
    /// <param name="verifiable">How many of them must verify.</param>
    [Theory]
    [InlineData("rsa_pss_2048_sha256_mgf1_0_test.json", 103, 61)]
    [InlineData("rsa_pss_2048_sha256_mgf1_32_test.json", 108, 63)]
    [InlineData("rsa_pss_2048_sha384_mgf1_48_test.json", 141, 95)]
    [InlineData("rsa_pss_3072_sha256_mgf1_32_test.json", 108, 63)]
    [InlineData("rsa_pss_4096_sha256_mgf1_32_test.json", 108, 63)]
    [InlineData("rsa_pss_4096_sha384_mgf1_48_test.json", 141, 95)]
    [InlineData("rsa_pss_4096_sha512_mgf1_32_test.json", 177, 132)]
    [InlineData("rsa_pss_4096_sha512_mgf1_64_test.json", 179, 132)]
    [InlineData("rsa_pss_misc_test.json", 150, 18)]
    [InlineData("rsa_pss_2048_sha1_mgf1_20_test.json", 88, 0)]
    [InlineData("rsa_pss_2048_sha256_mgf1sha1_20_test.json", 108, 0)]
    [Requirement("RFC8017-8-p3", "RFC8017-8.1-p4", "RFC8017-9.1-p12", "RFC8017-A.2.3-p7#2")]
    public void PassesWycheproofsPssTests(string file, int tests, int verifiable)
    {
        Platform.RequireLinuxX64();
        int count = 0, accepted = 0;
        foreach ((JsonElement group, JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/" + file)))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            string expected = test.GetProperty("result").GetString()!;
            Assert.NotEqual("acceptable", expected);
            (int result, RsaPublicKey key) = WycheproofKey(group);
            Assert.True(result == 0, id);
            string hash = group.GetProperty("sha").GetString()!;
            bool supported = group.GetProperty("mgf").GetString() == "MGF1" && group.GetProperty("mgfSha").GetString() == hash && PssHashes.Contains(hash);
            byte[] digest = Digest(hash, Hex(test.GetProperty("msg").GetString()!));
            int saltLength = group.GetProperty("sLen").GetInt32();
            int verified = VerifyPss(ref key, HashId(hash), digest, (nuint)saltLength, Hex(test.GetProperty("sig").GetString()!));
            Assert.True(verified == (supported && expected == "valid" ? 0 : -1), id);
            count++;
            accepted += verified == 0 ? 1 : 0;
        }

        Assert.Equal(tests, count);
        Assert.Equal(verifiable, accepted);
    }

    /// <summary>
    /// .NET's RSA (the platform's OpenSSL) on fresh keys of 1024, 1032, 1536, 2048, 2056, 3072 and
    /// 4096 bits (1032 and 2056: a top limb partly used, k rounded up past n's limbs): its
    /// PKCS#1 v1.5 signatures with SHA-1, SHA-256, SHA-384 and SHA-512 and its PSS ones with
    /// SHA-256, SHA-384 and SHA-512 (salts of the hash's length, where the key holds one: not
    /// SHA-512's at 1024 bits) verify; the same with one bit of
    /// the signature or of the digest flipped, or PSS with a salt length one off, do not. And the
    /// model's own encodings, signed with the key's d, verify under .NET too, so the model that the
    /// other tests trust agrees with OpenSSL's.
    /// </summary>
    [Fact]
    public void AgreesWithDotNet()
    {
        Platform.RequireLinuxX64();
        var random = new Random(1032);
        Dictionary<string, byte[]> prefixes = Rfc8017Prefixes();
        foreach (int bits in new[] { 1024, 1032, 1536, 2048, 2056, 3072, 4096 })
        {
            using var rsa = RSA.Create(bits);
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: true);
            (int result, RsaPublicKey key) = Init(parameters.Modulus!, parameters.Exponent!);
            Assert.Equal(0, result);
            var model = new ModelKey(Unsigned(parameters.Modulus!), Unsigned(parameters.Exponent!), Unsigned(parameters.D!));
            foreach (string hash in new[] { "SHA-1", "SHA-256", "SHA-384", "SHA-512" })
            {
                HashAlgorithmName name = new(hash.Replace("-", "", StringComparison.Ordinal));
                byte[] digest = Digest(hash, RandomBytes(random, 1 + random.Next(100)));
                byte[] signature = rsa.SignHash(digest, name, RSASignaturePadding.Pkcs1);
                Assert.True(VerifyPkcs1(ref key, HashId(hash), digest, signature) == 0, $"{bits} {hash} PKCS#1");
                Assert.Equal(-1, VerifyPkcs1(ref key, HashId(hash), digest, Flipped(random, signature)));
                Assert.Equal(-1, VerifyPkcs1(ref key, HashId(hash), Flipped(random, digest), signature));
                byte[] ours = model.Sign(EncodePkcs1(prefixes[hash], digest, model.Octets));
                Assert.Equal(Convert.ToHexString(signature), Convert.ToHexString(ours));
                if (hash == "SHA-1" || (bits - 1 + 7) / 8 < 2 * digest.Length + 2)
                {
                    continue;                   // no PSS with SHA-1; nor a salt of hLen past emLen
                }

                signature = rsa.SignHash(digest, name, RSASignaturePadding.Pss);
                Assert.True(VerifyPss(ref key, HashId(hash), digest, (nuint)digest.Length, signature) == 0, $"{bits} {hash} PSS");
                Assert.Equal(-1, VerifyPss(ref key, HashId(hash), digest, (nuint)digest.Length, Flipped(random, signature)));
                Assert.Equal(-1, VerifyPss(ref key, HashId(hash), Flipped(random, digest), (nuint)digest.Length, signature));
                Assert.Equal(-1, VerifyPss(ref key, HashId(hash), digest, (nuint)digest.Length + 1, signature));
                Assert.Equal(-1, VerifyPss(ref key, HashId(hash), digest, (nuint)digest.Length - 1, signature));
                ours = model.Sign(EncodePss(hash, digest, RandomBytes(random, digest.Length), model.Bits - 1));
                Assert.True(rsa.VerifyHash(digest, ours, name, RSASignaturePadding.Pss), $"{bits} {hash}: the model's PSS under .NET");
                Assert.Equal(0, VerifyPss(ref key, HashId(hash), digest, (nuint)digest.Length, ours));
            }
        }
    }

    /// <summary>
    /// RFC 8017 9.2 note 1's DigestInfo prefixes, read from the pinned RFC: each of the five
    /// hashes this library takes for PKCS#1 v1.5 (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512),
    /// encoded with the RFC's own octets and signed by the model, verifies; so the library's
    /// prefix tables are the RFC's, octet for octet (all nine of the note's entries are read).
    /// </summary>
    [Fact]
    public void MatchesRfc8017sDigestInfoPrefixes()
    {
        Platform.RequireLinuxX64();
        Dictionary<string, byte[]> prefixes = Rfc8017Prefixes();
        string[] entries = ["MD2", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"];
        Assert.Equal(entries.Order(StringComparer.Ordinal), prefixes.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(19, prefixes["SHA-256"].Length);   // 30 31 30 0d 06 09 <9 OID octets> 05 00 04 20
        ModelKey model = ModelKey.Prime(1023, 1155, 65537);
        RsaPublicKey key = model.Init();
        foreach (string hash in Pkcs1Hashes)
        {
            byte[] digest = Digest(hash, Encoding.ASCII.GetBytes("RFC 8017 " + hash));
            Assert.True(VerifyPkcs1(ref key, HashId(hash), digest, model.Sign(EncodePkcs1(prefixes[hash], digest, model.Octets))) == 0, hash);
        }
    }

    /// <summary>
    /// The model's encodings, signed with d, on keys whose moduli are primes chosen for their
    /// sizes (with gcd(3 * 65537, n - 1) = 1, so both exponents have a d): 2^1023 + 1155 (1024
    /// bits), 2^1024 + 643 (1025 bits) and 2^2048 + 3211 (2049 bits). At 1025 and 2049 bits PSS's
    /// emBits is a multiple of 8, so the encoded message is an octet shorter than the signature,
    /// whose first octet must then be 0 (RFC 8017 8.1.2 step 2c). Under e = 3 and 65537: PKCS#1
    /// v1.5 with all five hashes verifies; PSS with SHA-256, SHA-384 and SHA-512 at salts of 0, 1,
    /// the hash's length and the largest the key allows (emLen - hLen - 2) verifies, and each with
    /// the salt length one more, or one less, does not; a message whose first octet is not 0
    /// (s^e = 2^(8 emLen) + 1, below n) is refused. (Salts past the largest are left out: SHA-512's
    /// own length does not fit 1024 bits.)
    /// </summary>
    [Fact]
    [Requirement("RFC8017-8-p3")]
    public void VerifiesTheModelsSignaturesAtChosenSizes()
    {
        Platform.RequireLinuxX64();
        var random = new Random(2049);
        Dictionary<string, byte[]> prefixes = Rfc8017Prefixes();
        foreach ((int top, int offset) in new[] { (1023, 1155), (1024, 643), (2048, 3211) })
        {
            foreach (BigInteger e in new BigInteger[] { 3, 65537 })
            {
                ModelKey model = ModelKey.Prime(top, offset, e);
                RsaPublicKey key = model.Init();
                foreach (string hash in Pkcs1Hashes)
                {
                    byte[] digest = Digest(hash, RandomBytes(random, 40));
                    Assert.True(VerifyPkcs1(ref key, HashId(hash), digest, model.Sign(EncodePkcs1(prefixes[hash], digest, model.Octets))) == 0, $"{model.Bits} e {e} {hash}");
                }

                int emLength = (model.Bits - 1 + 7) / 8;
                foreach (string hash in PssHashes)
                {
                    byte[] digest = Digest(hash, RandomBytes(random, 40));
                    int largest = emLength - digest.Length - 2;
                    foreach (int saltLength in new[] { 0, 1, digest.Length, largest }.Where(l => l <= largest).Distinct())
                    {
                        byte[] signature = model.Sign(EncodePss(hash, digest, RandomBytes(random, saltLength), model.Bits - 1));
                        string what = $"{model.Bits} e {e} {hash} salt {saltLength}";
                        Assert.True(VerifyPss(ref key, HashId(hash), digest, (nuint)saltLength, signature) == 0, what);
                        Assert.True(VerifyPss(ref key, HashId(hash), digest, (nuint)saltLength + 1, signature) == -1, what + " + 1");
                        if (saltLength > 0)
                        {
                            Assert.True(VerifyPss(ref key, HashId(hash), digest, (nuint)saltLength - 1, signature) == -1, what + " - 1");
                        }
                    }

                    if (model.Bits % 8 == 1)
                    {
                        BigInteger m = (BigInteger.One << (8 * emLength)) + 1;
                        Assert.True(m < model.N);
                        Assert.Equal(-1, VerifyPss(ref key, HashId(hash), digest, (nuint)digest.Length, model.Sign(I2Osp(m, model.Octets))));
                    }
                }
            }
        }
    }

    /// <summary>
    /// Encodings one detail off RFC 8017's, each signed with d (so only the encoding is wrong),
    /// all refused, beside a correct one that verifies. PKCS#1 v1.5 (SHA-256): the 01 as 02, the 00
    /// after the padding as FF, one padding octet FE, the DigestInfo without its NULL (the padding
    /// an octet... two octets longer, as a signer that omits it would make), SHA-256's DigestInfo
    /// verified as SHA-384, the digest moved left with garbage after it. PSS (SHA-256, a 32-octet
    /// salt): the trailer BD, the top bit of the masked DB set (emBits is 1023: that bit must be
    /// 0), a padding octet of DB 01, the 01 before the salt as 00 or 02, H changed, the salt
    /// changed, and salt lengths the key cannot hold (emLen - hLen - 1, and 2^64 - 1, whose sum with
    /// hLen wraps around).
    /// </summary>
    [Fact]
    public void RefusesEncodingsOneDetailOff()
    {
        Platform.RequireLinuxX64();
        ModelKey model = ModelKey.Prime(1023, 1155, 65537);
        RsaPublicKey key = model.Init();
        byte[] digest = SHA256.HashData("one detail off"u8);
        byte[] prefix = Rfc8017Prefixes()["SHA-256"];
        byte[] em = EncodePkcs1(prefix, digest, model.Octets);
        Assert.Equal(0, VerifyPkcs1(ref key, 3, digest, model.Sign(em)));
        int separator = model.Octets - prefix.Length - digest.Length - 1;
        Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, model.Sign(Changed(em, 1, 0x02))));
        Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, model.Sign(Changed(em, separator, 0xFF))));
        Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, model.Sign(Changed(em, 5, 0xFE))));
        byte[] noNull = [0x30, 0x2f, 0x30, 0x0b, .. prefix.AsSpan(4, 11), 0x04, 0x20];
        Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, model.Sign(EncodePkcs1(noNull, digest, model.Octets))));
        Assert.Equal(-1, VerifyPkcs1(ref key, 4, SHA384.HashData("one detail off"u8), model.Sign(em)));
        byte[] moved = EncodePkcs1(prefix, [.. digest, 0x5A, 0x5A], model.Octets);
        Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, model.Sign(moved)));

        byte[] salt = RandomBytes(new Random(32), 32);
        int emBits = model.Bits - 1, emLength = (emBits + 7) / 8, dbLength = emLength - 33;
        byte[] pss = EncodePss("SHA-256", digest, salt, emBits);
        Assert.Equal(0, VerifyPss(ref key, 3, digest, 32, model.Sign(pss)));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Changed(pss, emLength - 1, 0xBD))));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Changed(pss, 0, (byte)(pss[0] | 0x80)))));
        byte[] h = pss.AsSpan(dbLength, 32).ToArray();
        byte[] mask = Mgf1("SHA-256", h, dbLength);
        // DB's own octets, re-masked after the change: the padding, the 01 before the salt, the salt
        int one = dbLength - salt.Length - 1;
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Remasked(pss, mask, 3, 0x01))));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Remasked(pss, mask, one, 0x00))));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Remasked(pss, mask, one, 0x02))));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Remasked(pss, mask, one + 1, (byte)(salt[0] ^ 1)))));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, model.Sign(Changed(pss, dbLength, (byte)(h[0] ^ 1)))));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, (nuint)(emLength - 32 - 1), model.Sign(pss)));
        Assert.Equal(-1, VerifyPss(ref key, 3, digest, nuint.MaxValue, model.Sign(pss)));
    }

    /// <summary>
    /// Signatures outside the rules, refused under a .NET 2048-bit key: lengths one short, one
    /// long (a leading zero octet), and 0; values 0, 1, n - 1, n, n + 1 and 2^2048 - 1 (s must be
    /// below n: RSAVP1's first step); hash identifiers 0, 6, -1, int.MinValue and int.MaxValue
    /// for both functions, and SHA-1's and SHA-224's for PSS. The key is not written by any of it.
    /// </summary>
    [Fact]
    public void RefusesSignaturesOutsideTheRules()
    {
        Platform.RequireLinuxX64();
        using var rsa = RSA.Create(2048);
        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);
        (int result, RsaPublicKey key) = Init(parameters.Modulus!, parameters.Exponent!);
        Assert.Equal(0, result);
        RsaPublicKey copy = key;
        BigInteger n = Unsigned(parameters.Modulus!);
        byte[] digest = SHA256.HashData("outside the rules"u8);
        byte[] valid = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] pss = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.Equal(0, VerifyPkcs1(ref key, 3, digest, valid));
        Assert.Equal(0, VerifyPss(ref key, 3, digest, 32, pss));
        byte[][] signatures =
        [
            valid[..^1], [0, .. valid], [], I2Osp(0, 256), I2Osp(1, 256), I2Osp(n - 1, 256), I2Osp(n, 256), I2Osp((BigInteger.One << 2048) - 1, 256),
        ];
        if (n + 1 < BigInteger.One << 2048)
        {
            signatures = [.. signatures, I2Osp(n + 1, 256)];
        }

        foreach (byte[] signature in signatures)
        {
            Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, signature));
            Assert.Equal(-1, VerifyPss(ref key, 3, digest, 32, signature));
        }

        foreach (int hash in new[] { 0, 6, -1, int.MinValue, int.MaxValue })
        {
            Assert.Equal(-1, VerifyPkcs1(ref key, hash, digest, valid));
            Assert.Equal(-1, VerifyPss(ref key, hash, digest, 32, pss));
        }

        Assert.Equal(-1, VerifyPss(ref key, 1, digest[..20], 20, pss));
        Assert.Equal(-1, VerifyPss(ref key, 2, digest[..28], 28, pss));
        Assert.True(new ReadOnlySpan<byte>(&key, sizeof(RsaPublicKey)).SequenceEqual(new ReadOnlySpan<byte>(&copy, sizeof(RsaPublicKey))));
    }

    /// <summary>
    /// Bleichenbacher's forgery of 2006 against e = 3 under a 3072-bit modulus (the prime
    /// 2^3071 + 7755, so the test also has the d that makes an honest signature): s is the cube root
    /// (rounded up) of 00 01 FF 00 || DigestInfo || digest followed by zeros, so s^3 starts with a
    /// well-formed PKCS#1 v1.5 prefix and ends in garbage where the padding should have been; a
    /// verifier that parses the encoding and stops after the digest accepts it (the test checks
    /// that s^3 really carries the prefix). Comparing the whole encoded message, this library
    /// refuses it; the honest encoding signed with the matching d verifies under the same e.
    /// </summary>
    [Fact]
    public void RefusesBleichenbachersForgery()
    {
        Platform.RequireLinuxX64();
        ModelKey model = ModelKey.Prime(3071, 7755, 3);
        RsaPublicKey key = model.Init();
        byte[] digest = SHA256.HashData("forged"u8);
        byte[] prefix = Rfc8017Prefixes()["SHA-256"];
        byte[] head = [0x00, 0x01, 0xFF, 0x00, .. prefix, .. digest];
        int garbage = model.Octets - head.Length;
        BigInteger target = Unsigned(head) << (8 * garbage);
        BigInteger s = CubeRootCeiling(target);
        Assert.Equal(Unsigned(head), (s * s * s) >> (8 * garbage));
        Assert.True(s * s * s < model.N);
        Assert.Equal(-1, VerifyPkcs1(ref key, 3, digest, I2Osp(s, model.Octets)));
        Assert.Equal(0, VerifyPkcs1(ref key, 3, digest, model.Sign(EncodePkcs1(prefix, digest, model.Octets))));
    }

    // -------------------------------------------------------------------------------------------
    // The C ABI
    // -------------------------------------------------------------------------------------------

    /// <summary>httpasm_rsa_public_key_init on n and e as given (their leading zero octets kept).</summary>
    /// <param name="n">The modulus, big-endian.</param>
    /// <param name="e">The exponent, big-endian.</param>
    /// <returns>The result (0 or -1) and the key the function wrote.</returns>
    private static (int Result, RsaPublicKey Key) Init(byte[] n, byte[] e)
    {
        RsaPublicKey key;
        fixed (byte* pn = n)
        fixed (byte* pe = e)
        {
            int result = Native.RsaPublicKeyInit(&key, pn, (nuint)n.Length, pe, (nuint)e.Length);
            return (result, key);
        }
    }

    /// <summary>httpasm_rsa_verify_pkcs1 under the caller's key (by reference: a test can see that nothing writes it).</summary>
    /// <param name="key">The key.</param>
    /// <param name="hash">HTTPASM_HASH_* (or any int, to test the refusal).</param>
    /// <param name="digest">The digest: the hash's length when the identifier names one (the function reads that many).</param>
    /// <param name="signature">The signature, any length.</param>
    /// <returns>0 or -1.</returns>
    private static int VerifyPkcs1(ref RsaPublicKey key, int hash, byte[] digest, byte[] signature)
    {
        fixed (RsaPublicKey* k = &key)
        fixed (byte* d = digest)
        fixed (byte* s = signature)
        {
            return Native.RsaVerifyPkcs1(k, hash, d, s, (nuint)signature.Length);
        }
    }

    /// <summary>httpasm_rsa_verify_pss under the caller's key (by reference).</summary>
    /// <param name="key">The key.</param>
    /// <param name="hash">HTTPASM_HASH_* (or any int).</param>
    /// <param name="digest">The digest.</param>
    /// <param name="saltLength">The salt's length.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>0 or -1.</returns>
    private static int VerifyPss(ref RsaPublicKey key, int hash, byte[] digest, nuint saltLength, byte[] signature)
    {
        fixed (RsaPublicKey* k = &key)
        fixed (byte* d = digest)
        fixed (byte* s = signature)
        {
            return Native.RsaVerifyPss(k, hash, d, saltLength, s, (nuint)signature.Length);
        }
    }

    /// <summary>
    /// Holds an initialized key to the BigInteger model: every field, the limbs above n's and
    /// R^2's own zero, the reserved field zero.
    /// </summary>
    /// <param name="key">The key the init wrote.</param>
    /// <param name="n">Its modulus.</param>
    /// <param name="e">Its exponent.</param>
    private static void AssertKey(RsaPublicKey key, BigInteger n, BigInteger e)
    {
        int bits = (int)n.GetBitLength();
        int limbs = (bits + 511) / 512 * 8;
        BigInteger two64 = BigInteger.One << 64;
        BigInteger rr = BigInteger.ModPow(2, 128 * limbs, n);
        BigInteger n0 = two64 - ModInverse(n % two64, two64);
        string what = $"n of {bits} bits";
        Assert.True(key.Bits == (uint)bits, what);
        Assert.True(key.Limbs == (uint)limbs, what);
        Assert.True(key.E == (ulong)e, what);
        Assert.True(key.N0 == (ulong)n0, what);
        Assert.True(key.Reserved == 0, what);
        for (int i = 0; i < 128; i++)
        {
            Assert.True(key.N[i] == (ulong)((n >> (64 * i)) & ulong.MaxValue), $"{what}: n's limb {i}");
            Assert.True(key.RR[i] == (ulong)((rr >> (64 * i)) & ulong.MaxValue), $"{what}: R^2's limb {i}");
        }
    }

    /// <summary>A Wycheproof group's public key (modulus and publicExponent in hex), through the init.</summary>
    /// <param name="group">The test group.</param>
    /// <returns>The init's result and the key.</returns>
    private static (int Result, RsaPublicKey Key) WycheproofKey(JsonElement group)
    {
        JsonElement publicKey = group.GetProperty("publicKey");
        return Init(Hex(publicKey.GetProperty("modulus").GetString()!), Hex(publicKey.GetProperty("publicExponent").GetString()!));
    }

    /// <summary>
    /// Keeps the key of a CAVP SigGen file, whose "n = " and "e = " come as records of their own
    /// before the signatures under them.
    /// </summary>
    /// <param name="record">The record.</param>
    /// <param name="modulus">The current modulus (hex), updated.</param>
    /// <param name="exponent">The current exponent (hex), updated.</param>
    /// <returns>True when the record held no signature (a key line, or nothing to verify).</returns>
    private static bool TrackKey(Dictionary<string, string> record, ref string? modulus, ref string? exponent)
    {
        if (record.TryGetValue("n", out string? n))
        {
            modulus = n;
        }

        if (record.TryGetValue("e", out string? e))
        {
            exponent = e;
        }

        return !record.ContainsKey("S");
    }

    /// <summary>
    /// SigGenPSS's salt lengths, which only its header gives: "# Combinations selected:Mod Size
    /// 2048 with SHA-224(Salt len: 15); SHA-256(Salt len: 20); ...;; Mod Size 3072 with ...".
    /// </summary>
    /// <param name="path">The file.</param>
    /// <returns>The salt length by (modulus size, hash name with a dash).</returns>
    /// <exception cref="InvalidDataException">No such header.</exception>
    private static Dictionary<(string Mod, string Hash), int> SigGenPssSaltLengths(string path)
    {
        string header = File.ReadLines(path).FirstOrDefault(l => l.StartsWith("# Combinations selected:", StringComparison.Ordinal))
            ?? throw new InvalidDataException("no combinations header in " + path);
        var salts = new Dictionary<(string, string), int>();
        foreach (Match size in Regex.Matches(header, @"Mod Size (\d+) with ([^;]+(?:;[^;]+)*)"))
        {
            foreach (Match pair in Regex.Matches(size.Groups[2].Value, @"SHA-(\d+)\(Salt len: (\d+)\)"))
            {
                salts[(size.Groups[1].Value, "SHA-" + pair.Groups[1].Value)] = int.Parse(pair.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture);
            }
        }

        return salts;
    }

    // -------------------------------------------------------------------------------------------
    // The model: RFC 8017's encodings and RSA with d
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// RFC 8017 9.2 note 1's DigestInfo prefixes from the pinned text (specs/rfc/rfc8017.txt):
    /// each "NAME: (0x)30 .. || H." entry after the note's "encoding T of the DigestInfo value is
    /// equal to the following:", its octets running onto the next line. (7.1.1's note lists the
    /// empty string's hashes in the same "NAME: (0x)..." form: the note's own line keeps them out.)
    /// </summary>
    /// <returns>The DER before the digest, by hash name ("SHA-256").</returns>
    /// <exception cref="InvalidDataException">The note was not found, or an entry is not made of octets.</exception>
    private static Dictionary<string, byte[]> Rfc8017Prefixes()
    {
        var prefixes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        string? name = null;
        var octets = new List<byte>();
        bool inNote = false;
        foreach (string raw in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc8017.txt")))
        {
            string line = raw.Trim();
            if (!inNote)
            {
                inNote = line.EndsWith("encoding T of the DigestInfo value is equal to the following:", StringComparison.Ordinal);
                continue;
            }

            if (prefixes.Count == 9)
            {
                break;
            }

            Match start = Regex.Match(line, @"^(MD2|MD5|SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|SHA-512/224|SHA-512/256):\s+\(0x\)(.*)$");
            if (start.Success)
            {
                name = start.Groups[1].Value;
                octets.Clear();
                line = start.Groups[2].Value;
            }
            else if (name is null)
            {
                continue;
            }

            int end = line.IndexOf("||", StringComparison.Ordinal);
            foreach (string octet in (end < 0 ? line : line[..end]).Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (octet.Length != 2)
                {
                    throw new InvalidDataException($"RFC 8017 9.2's {name} entry: '{octet}' is no octet");
                }

                octets.Add(Convert.ToByte(octet, 16));
            }

            if (end >= 0)
            {
                prefixes[name] = [.. octets];
                name = null;
            }
        }

        return prefixes.Count == 9 ? prefixes : throw new InvalidDataException("RFC 8017 9.2's note 1 was not found whole");
    }

    /// <summary>RFC 8017 9.2's EMSA-PKCS1-v1_5 encoding: 00 01, FF octets, 00, the DigestInfo prefix, the digest.</summary>
    /// <param name="prefix">The DigestInfo up to the digest.</param>
    /// <param name="digest">The digest (or anything, to build a wrong encoding).</param>
    /// <param name="emLength">The encoded message's length (the modulus' octets).</param>
    /// <returns>EM.</returns>
    private static byte[] EncodePkcs1(byte[] prefix, byte[] digest, int emLength)
    {
        byte[] em = new byte[emLength];
        int t = prefix.Length + digest.Length;
        em[1] = 0x01;
        em.AsSpan(2, emLength - t - 3).Fill(0xFF);
        prefix.CopyTo(em, emLength - t);
        digest.CopyTo(em, emLength - digest.Length);
        return em;
    }

    /// <summary>
    /// RFC 8017 9.1.1's EMSA-PSS encoding with MGF1 on the same hash: H = Hash(00^8 || mHash ||
    /// salt), DB = PS || 01 || salt masked by MGF1(H), its top 8 emLen - emBits bits cleared,
    /// then H and BC.
    /// </summary>
    /// <param name="hash">The hash's name.</param>
    /// <param name="digest">mHash.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="emBits">The modulus' bits less one.</param>
    /// <returns>EM, ceil(emBits / 8) octets.</returns>
    /// <exception cref="ArgumentException">The salt does not fit (emLen below hLen + sLen + 2).</exception>
    private static byte[] EncodePss(string hash, byte[] digest, byte[] salt, int emBits)
    {
        int emLength = (emBits + 7) / 8;
        if (emLength < digest.Length + salt.Length + 2)
        {
            throw new ArgumentException("the salt does not fit", nameof(salt));
        }

        byte[] h = Digest(hash, [.. new byte[8], .. digest, .. salt]);
        int dbLength = emLength - digest.Length - 1;
        byte[] db = new byte[dbLength];
        db[dbLength - salt.Length - 1] = 0x01;
        salt.CopyTo(db, dbLength - salt.Length);
        byte[] mask = Mgf1(hash, h, dbLength);
        for (int i = 0; i < dbLength; i++)
        {
            db[i] ^= mask[i];
        }

        db[0] &= (byte)(0xFF >> (8 * emLength - emBits));
        return [.. db, .. h, 0xBC];
    }

    /// <summary>RFC 8017 B.2.1's MGF1: Hash(seed || counter) for counters 0, 1, ..., cut to the length.</summary>
    /// <param name="hash">The hash's name.</param>
    /// <param name="seed">The seed.</param>
    /// <param name="length">The mask's length.</param>
    /// <returns>The mask.</returns>
    private static byte[] Mgf1(string hash, byte[] seed, int length)
    {
        var mask = new List<byte>(length + 64);
        for (uint counter = 0; mask.Count < length; counter++)
        {
            mask.AddRange(Digest(hash, [.. seed, (byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter]));
        }

        return [.. mask.Take(length)];
    }

    /// <summary>A PSS encoding with one octet of its DB (before masking) replaced, masked again with the same mask.</summary>
    /// <param name="em">The encoding.</param>
    /// <param name="mask">MGF1(H) over DB's length.</param>
    /// <param name="index">DB's octet to replace.</param>
    /// <param name="value">Its new unmasked value.</param>
    /// <returns>A copy with the change.</returns>
    private static byte[] Remasked(byte[] em, byte[] mask, int index, byte value) => Changed(em, index, (byte)(value ^ mask[index]));

    /// <summary>A copy of the octets with one replaced.</summary>
    /// <param name="octets">The octets.</param>
    /// <param name="index">Which.</param>
    /// <param name="value">Its new value.</param>
    /// <returns>The copy.</returns>
    private static byte[] Changed(byte[] octets, int index, byte value)
    {
        byte[] copy = [.. octets];
        copy[index] = value;
        return copy;
    }

    /// <summary>
    /// An RSA key the model signs with: n, e and d. Its signatures are RSASP1 on an encoded message
    /// (s = m^d mod n), so a test can sign any octets, wrong encodings included.
    /// </summary>
    /// <param name="N">The modulus.</param>
    /// <param name="E">The public exponent.</param>
    /// <param name="D">The private exponent.</param>
    private sealed record ModelKey(BigInteger N, BigInteger E, BigInteger D)
    {
        /// <summary>n's bit length.</summary>
        public int Bits => (int)N.GetBitLength();

        /// <summary>n's length in octets: a signature's.</summary>
        public int Octets => (Bits + 7) / 8;

        /// <summary>
        /// A key whose modulus is the prime 2^top + offset (the offsets the tests use were found by a
        /// Miller-Rabin search with 40 bases, each the least with gcd(3 * 65537, n - 1) = 1; a wrong
        /// one would fail the tests' own signatures): d = e^-1 mod (n - 1), since phi(n) = n - 1.
        /// </summary>
        /// <param name="top">The power of two.</param>
        /// <param name="offset">The offset.</param>
        /// <param name="e">The public exponent (prime to n - 1).</param>
        /// <returns>The key.</returns>
        /// <exception cref="ArgumentException">e has no inverse mod n - 1.</exception>
        public static ModelKey Prime(int top, int offset, BigInteger e)
        {
            BigInteger n = (BigInteger.One << top) + offset;
            return new ModelKey(n, e, ModInverse(e, n - 1));
        }

        /// <summary>The key through the library's init (which must take it).</summary>
        /// <returns>The prepared key.</returns>
        public RsaPublicKey Init()
        {
            (int result, RsaPublicKey key) = RsaTests.Init(RsaTests.Octets(N), RsaTests.Octets(E));
            Assert.Equal(0, result);
            return key;
        }

        /// <summary>RSASP1 on an encoded message, as a signature of n's octets.</summary>
        /// <param name="em">The encoded message (its value below n).</param>
        /// <returns>m^d mod n, big-endian, n's length.</returns>
        public byte[] Sign(byte[] em) => I2Osp(BigInteger.ModPow(Unsigned(em), D, N), Octets);
    }

    // -------------------------------------------------------------------------------------------
    // Numbers and octets
    // -------------------------------------------------------------------------------------------

    /// <summary>a^-1 mod m by the extended Euclidean algorithm.</summary>
    /// <param name="a">The number.</param>
    /// <param name="m">The modulus.</param>
    /// <returns>The inverse in [0, m).</returns>
    /// <exception cref="ArgumentException">a and m are not coprime.</exception>
    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger t = 0, newT = 1, r = m, newR = ((a % m) + m) % m;
        while (!newR.IsZero)
        {
            BigInteger q = r / newR;
            (t, newT) = (newT, t - q * newT);
            (r, newR) = (newR, r - q * newR);
        }

        if (!r.IsOne)
        {
            throw new ArgumentException("not invertible", nameof(a));
        }

        return t.Sign < 0 ? t + m : t;
    }

    /// <summary>The least s with s^3 at least x (Newton's method from above, then one step up if needed).</summary>
    /// <param name="x">A positive number.</param>
    /// <returns>ceil(x^(1/3)).</returns>
    private static BigInteger CubeRootCeiling(BigInteger x)
    {
        BigInteger r = BigInteger.One << (int)((x.GetBitLength() + 2) / 3);
        while (true)
        {
            BigInteger next = (2 * r + x / (r * r)) / 3;
            if (next >= r)
            {
                break;
            }

            r = next;
        }

        while (r * r * r < x)
        {
            r++;
        }

        return r;
    }

    /// <summary>A random odd number of exactly the bits given (the top bit set).</summary>
    /// <param name="random">The source.</param>
    /// <param name="bits">The bit length.</param>
    /// <returns>The number.</returns>
    private static BigInteger RandomOdd(Random random, int bits)
    {
        byte[] octets = RandomBytes(random, (bits + 7) / 8);
        BigInteger x = Unsigned(octets) & ((BigInteger.One << bits) - 1);
        return x | (BigInteger.One << (bits - 1)) | 1;
    }

    /// <summary>Random octets.</summary>
    /// <param name="random">The source.</param>
    /// <param name="length">How many.</param>
    /// <returns>The octets.</returns>
    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] octets = new byte[length];
        random.NextBytes(octets);
        return octets;
    }

    /// <summary>A copy of the octets with one random bit flipped.</summary>
    /// <param name="random">The source.</param>
    /// <param name="octets">The octets (at least one).</param>
    /// <returns>The copy.</returns>
    private static byte[] Flipped(Random random, byte[] octets)
    {
        byte[] copy = [.. octets];
        copy[random.Next(copy.Length)] ^= (byte)(1 << random.Next(8));
        return copy;
    }

    /// <summary>An unsigned big-endian number.</summary>
    /// <param name="octets">Its octets.</param>
    /// <returns>The number.</returns>
    private static BigInteger Unsigned(ReadOnlySpan<byte> octets) => new(octets, isUnsigned: true, isBigEndian: true);

    /// <summary>A number's shortest big-endian octets (0: one zero octet).</summary>
    /// <param name="x">A number of 0 or more.</param>
    /// <returns>The octets.</returns>
    private static byte[] Octets(BigInteger x) => x.ToByteArray(isUnsigned: true, isBigEndian: true);

    /// <summary>RFC 8017 4.1's I2OSP: x as exactly length octets, big-endian.</summary>
    /// <param name="x">A number of 0 or more.</param>
    /// <param name="length">The octets wanted.</param>
    /// <returns>The octets.</returns>
    /// <exception cref="ArgumentException">x needs more octets.</exception>
    private static byte[] I2Osp(BigInteger x, int length)
    {
        byte[] raw = Octets(x);
        int start = raw.Length > length && raw[0] == 0 ? 1 : 0;
        if (raw.Length - start > length)
        {
            throw new ArgumentException("integer too large", nameof(x));
        }

        byte[] octets = new byte[length];
        raw.AsSpan(start).CopyTo(octets.AsSpan(length - (raw.Length - start)));
        return octets;
    }

    /// <summary>Octets from hex, an odd number of digits taken with a leading 0 (CAVP writes exponents like "3").</summary>
    /// <param name="hex">The hex digits.</param>
    /// <returns>The octets.</returns>
    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex);

    /// <summary>HTTPASM_HASH_* for a vector file's hash name ("SHA-256", "SHA256"); 0 for any other.</summary>
    /// <param name="name">The name.</param>
    /// <returns>1 to 5, or 0.</returns>
    private static int HashId(string name) => Array.IndexOf(Pkcs1Hashes, Dashed(name)) + 1;

    /// <summary>A hash name with its dash ("SHA256" to "SHA-256"; "SHA-256" as it is).</summary>
    /// <param name="name">The name.</param>
    /// <returns>The dashed name.</returns>
    private static string Dashed(string name) => name.StartsWith("SHA", StringComparison.Ordinal) && !name.StartsWith("SHA-", StringComparison.Ordinal) ? "SHA-" + name[3..] : name;
}
