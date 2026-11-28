using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// HMAC-SHA512 (FIPS 198-1, RFC 2104) and HKDF-SHA512 (RFC 5869) through the C ABI: the HMAC of
/// RFC 6979's deterministic nonces at P-521 (httpasm_p521_sign's HMAC_DRBG), which no TLS 1.3
/// cipher suite uses but a caller's protocol may. Held to RFC 4231's examples, NIST's CAVP HMAC
/// file (its SHA-512 section), Project Wycheproof's HMAC and HKDF files, and .NET's HMACSHA512 and
/// HKDF on random keys and messages. The code is SHA-256's and SHA-384's (crypto/hmac.asm writes
/// the three from one macro) over SHA-512's compression, whose versions the suite at every tier
/// (tests/run-linux.sh) runs: these tests prove the SHA-512 instance, its 128-octet block and
/// 64-octet digest (HKDF-Expand's limit 16,320), on its own.
/// </summary>
public sealed unsafe class HmacSha512Tests
{
    /// <summary>
    /// The .NET copy of httpasm_hmac_sha512_ctx has the library's size, 416 octets, under id 22
    /// (the end of the registry is checked by the newest structure's tests: Asn1Tests).
    /// </summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(416, Unsafe.SizeOf<HmacSha512Context>());
        Assert.Equal((uint)Unsafe.SizeOf<HmacSha512Context>(), Native.StructSize(22));
    }

    /// <summary>
    /// RFC 4231's seven HMAC-SHA-512 examples: keys of 20, 4 and 25 octets (under the 128-octet
    /// block) and of 131 (over it: hashed first), messages shorter and longer than a block, and
    /// case 5's MAC truncated to its first 16 octets.
    /// </summary>
    /// <param name="key">The key: hex, or "XX*N" for the octet XX N times.</param>
    /// <param name="message">The message: text, "hex:" and hex, or "XX*N".</param>
    /// <param name="mac">The MAC (or its truncation), in hex.</param>
    [Theory]
    [InlineData("0b*20", "Hi There", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")]
    [InlineData("4a656665", "what do ya want for nothing?", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")]
    [InlineData("aa*20", "dd*50", "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")]
    [InlineData("0102030405060708090a0b0c0d0e0f10111213141516171819", "cd*50", "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")]
    [InlineData("0c*20", "Test With Truncation", "415fad6271580a531d4179bc891d87a6")]
    [InlineData("aa*131", "Test Using Larger Than Block-Size Key - Hash Key First", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")]
    [InlineData("aa*131",
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")]
    public void MatchesRfc4231(string key, string message, string mac)
    {
        Platform.RequireLinuxX64();
        byte[] full = Mac(HmacTests.Octets(key, text: false), HmacTests.Octets(message, text: true));
        Assert.Equal(mac, Convert.ToHexStringLower(full)[..mac.Length]);
    }

    /// <summary>
    /// NIST's CAVP HMAC file, every SHA-512 record ([L=64]: 375 MACs): keys of 100, 125, 128, 139
    /// and 142 octets (under, at and over the block), 128-octet messages, tags truncated to 32,
    /// 40, 48, 56 and 64 octets.
    /// </summary>
    [Fact]
    public void MatchesNistsHmacVectors()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/hmac/HMAC.rsp");
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path).Where(r => r.GetValueOrDefault("L") == "64"))
        {
            byte[] key = Convert.FromHexString(record["Key"]);
            byte[] message = Convert.FromHexString(record["Msg"]);
            int tag = int.Parse(record["Tlen"], System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(int.Parse(record["Klen"], System.Globalization.CultureInfo.InvariantCulture), key.Length);
            Assert.Equal(record["Mac"], Convert.ToHexStringLower(Mac(key, message))[..(2 * tag)]);
            count++;
        }

        Assert.Equal(375, count);
    }

    /// <summary>
    /// Project Wycheproof's HMAC-SHA512 tests (174): keys of 32, 64 and 65 octets, empty and long
    /// messages, full and truncated (32-octet) tags, and tags with flipped bits that must not match.
    /// </summary>
    [Fact]
    public void PassesWycheproofsHmacTests()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("wycheproof/hmac_sha512_test.json");
        int count = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(path))
        {
            int tagOctets = group.GetProperty("tagSize").GetInt32() / 8;
            byte[] key = Convert.FromHexString(test.GetProperty("key").GetString()!);
            byte[] message = Convert.FromHexString(test.GetProperty("msg").GetString()!);
            byte[] tag = Convert.FromHexString(test.GetProperty("tag").GetString()!);
            bool valid = test.GetProperty("result").GetString() == "valid";
            byte[] mac = Mac(key, message);
            bool matches = tag.Length == tagOctets && CryptographicOperations.FixedTimeEquals(mac.AsSpan(0, tagOctets), tag);
            Assert.True(matches == valid, $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}");
            count++;
        }

        Assert.Equal(174, count);
    }

    /// <summary>
    /// .NET's HMACSHA512 on random keys of 0 to 300 octets (both sides of the 128-octet block,
    /// and the digest of a long one) and messages to 400 octets fed in random pieces; and a
    /// context copied right after init MACs a second message under the same key, as HKDF uses it.
    /// </summary>
    [Fact]
    public void MatchesDotNetOnRandomKeysAndMessages()
    {
        Platform.RequireLinuxX64();
        var random = new Random(198_1512);
        for (int i = 0; i < 2000; i++)
        {
            byte[] key = new byte[random.Next(0, 301)];
            byte[] message = new byte[random.Next(0, 401)];
            byte[] second = new byte[random.Next(0, 200)];
            random.NextBytes(key);
            random.NextBytes(message);
            random.NextBytes(second);
            byte[] one = new byte[64], two = new byte[64];
            HmacSha512Context h;
            fixed (byte* k = key, m = message, s = second, o = one, t = two)
            {
                Native.HmacSha512Init(&h, k, (nuint)key.Length);
                HmacSha512Context reuse = h;    // the key's state, before any message
                int at = 0;
                while (at < message.Length)
                {
                    int piece = Math.Min(message.Length - at, random.Next(0, 160));
                    Native.HmacSha512Update(&h, m + at, (nuint)piece);
                    at += piece;
                }

                Native.HmacSha512Final(&h, o);
                Native.HmacSha512Update(&reuse, s, (nuint)second.Length);
                Native.HmacSha512Final(&reuse, t);
                Assert.True(new ReadOnlySpan<byte>(&h, sizeof(HmacSha512Context)).IndexOfAnyExcept((byte)0) < 0, "final left key state behind");
            }

            Assert.Equal(HMACSHA512.HashData(key, message), one);
            Assert.Equal(HMACSHA512.HashData(key, second), two);
            Assert.Equal(one, Mac(key, message));
        }
    }

    /// <summary>
    /// Project Wycheproof's HKDF-SHA512 tests (83): Extract then Expand gives the expected octets
    /// for every valid test; the invalid ones ask for more than 255 * 64 octets, which Expand
    /// refuses without writing.
    /// </summary>
    [Fact]
    public void PassesWycheproofsHkdfTests()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("wycheproof/hkdf_sha512_test.json");
        int count = 0, refused = 0;
        foreach ((_, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(path))
        {
            byte[] ikm = Convert.FromHexString(test.GetProperty("ikm").GetString()!);
            byte[] salt = Convert.FromHexString(test.GetProperty("salt").GetString()!);
            byte[] info = Convert.FromHexString(test.GetProperty("info").GetString()!);
            int size = test.GetProperty("size").GetInt32();
            bool valid = test.GetProperty("result").GetString() == "valid";
            (int result, byte[] okm) = Hkdf(salt, ikm, info, size);
            if (valid)
            {
                Assert.Equal(0, result);
                Assert.Equal(test.GetProperty("okm").GetString(), Convert.ToHexStringLower(okm));
            }
            else
            {
                Assert.Equal(-1, result);
                Assert.True(okm.AsSpan().IndexOfAnyExcept((byte)0xEE) < 0, $"tcId {test.GetProperty("tcId").GetInt32()}: wrote past a refusal");
                refused++;
            }

            count++;
        }

        Assert.Equal(83, count);
        Assert.Equal(3, refused);
    }

    /// <summary>
    /// .NET's HKDF on random salts (empty ones too), keying material, info and lengths up to the
    /// limit, 16,320 octets (each side of a 64-octet block, and the last block whole); 16,321 is
    /// refused (-1) and nothing is written.
    /// </summary>
    [Fact]
    public void MatchesDotNetHkdfToItsLimit()
    {
        Platform.RequireLinuxX64();
        var random = new Random(5869_512);
        foreach (int length in new[] { 0, 1, 63, 64, 65, 128, 129, 1000, 16_319, 16_320 })
        {
            byte[] salt = new byte[random.Next(0, 3) == 0 ? 0 : random.Next(1, 200)];
            byte[] ikm = new byte[random.Next(1, 200)];
            byte[] info = new byte[random.Next(0, 160)];
            random.NextBytes(salt);
            random.NextBytes(ikm);
            random.NextBytes(info);
            (int result, byte[] okm) = Hkdf(salt, ikm, info, length);
            Assert.Equal(0, result);
            byte[] expected = length == 0 ? [] : HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, length, salt, info);   // .NET refuses 0; RFC 5869 does not
            Assert.Equal(expected, okm);
        }

        (int refused, byte[] untouched) = Hkdf([1, 2, 3], [4, 5, 6], [], 16_321);
        Assert.Equal(-1, refused);
        Assert.True(untouched.AsSpan().IndexOfAnyExcept((byte)0xEE) < 0, "Expand wrote past its refusal");
    }

    /// <summary>
    /// The three HMACs under one key and message are three different MACs: SHA-512's instance
    /// starts its hashes from SHA-512's values (not SHA-384's, whose context has the same layout)
    /// and gives all 64 octets; SHA-384's MAC is not a prefix of it.
    /// </summary>
    [Fact]
    public void DiffersFromTheOtherHmacs()
    {
        Platform.RequireLinuxX64();
        byte[] key = [.. Enumerable.Range(0, 64).Select(i => (byte)i)];
        byte[] message = "P-521's HMAC_DRBG"u8.ToArray();
        byte[] mac512 = Mac(key, message);
        byte[] mac384 = new byte[48];
        fixed (byte* k = key, m = message, o = mac384)
        {
            Native.HmacSha384(k, (nuint)key.Length, m, (nuint)message.Length, o);
        }

        Assert.Equal(HMACSHA512.HashData(key, message), mac512);
        Assert.Equal(HMACSHA384.HashData(key, message), mac384);
        Assert.NotEqual(mac384, mac512.AsSpan(0, 48).ToArray());
    }

    /// <summary>The one-shot MAC.</summary>
    /// <param name="key">The key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 64-octet MAC.</returns>
    private static byte[] Mac(byte[] key, byte[] message)
    {
        byte[] mac = new byte[64];
        fixed (byte* k = key, m = message, o = mac)
        {
            Native.HmacSha512(k, (nuint)key.Length, m, (nuint)message.Length, o);
        }

        return mac;
    }

    /// <summary>Extract, then Expand into a buffer pre-filled with 0xEE (so writes past a refusal show).</summary>
    /// <param name="salt">The salt.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="info">The context.</param>
    /// <param name="length">The octets asked for.</param>
    /// <returns>Expand's result and the buffer.</returns>
    private static (int Result, byte[] Okm) Hkdf(byte[] salt, byte[] ikm, byte[] info, int length)
    {
        byte[] prk = new byte[64];
        byte[] okm = new byte[length];
        okm.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* s = salt, i = ikm, n = info, p = prk, o = okm)
        {
            Native.HkdfSha512Extract(s, (nuint)salt.Length, i, (nuint)ikm.Length, p);
            result = Native.HkdfSha512Expand(p, 64, n, (nuint)info.Length, o, (nuint)length);
        }

        return (result, okm);
    }
}
