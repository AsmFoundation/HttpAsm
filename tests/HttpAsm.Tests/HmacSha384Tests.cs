using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// HMAC-SHA384 (FIPS 198-1, RFC 2104) and HKDF-SHA384 (RFC 5869) through the C ABI: the MAC and
/// key derivation of TLS_AES_256_GCM_SHA384's key schedule. Held to RFC 4231's examples, NIST's
/// CAVP HMAC file (its SHA-384 section), Project Wycheproof's HMAC and HKDF files, and .NET's
/// HMACSHA384 and HKDF on random keys and messages. Both run on SHA-512's compression, so the
/// suite at every tier (tests/run-linux.sh) runs both of its versions under them. The code is
/// SHA-256's (crypto/hmac.asm writes both from one macro): these tests prove the SHA-384
/// instance, with its 128-octet block and 48-octet digest, on its own.
/// </summary>
public sealed unsafe class HmacSha384Tests
{
    /// <summary>The .NET copy of httpasm_hmac_sha384_ctx has the library's size: 416 octets.</summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(416, Unsafe.SizeOf<HmacSha384Context>());
        Assert.Equal((uint)Unsafe.SizeOf<HmacSha384Context>(), Native.StructSize(13));
    }

    /// <summary>
    /// RFC 4231's seven HMAC-SHA-384 examples: keys of 20, 4 and 25 octets (under the 128-octet
    /// block) and of 131 (over it: hashed first), messages shorter and longer than a block, and
    /// case 5's MAC truncated to its first 16 octets.
    /// </summary>
    /// <param name="key">The key: hex, or "XX*N" for the octet XX N times.</param>
    /// <param name="message">The message: text, "hex:" and hex, or "XX*N".</param>
    /// <param name="mac">The MAC (or its truncation), in hex.</param>
    [Theory]
    [InlineData("0b*20", "Hi There", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")]
    [InlineData("4a656665", "what do ya want for nothing?", "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")]
    [InlineData("aa*20", "dd*50", "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27")]
    [InlineData("0102030405060708090a0b0c0d0e0f10111213141516171819", "cd*50", "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb")]
    [InlineData("0c*20", "Test With Truncation", "3abf34c3503b2a23a46efc619baef897")]
    [InlineData("aa*131", "Test Using Larger Than Block-Size Key - Hash Key First", "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952")]
    [InlineData("aa*131",
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e")]
    public void MatchesRfc4231(string key, string message, string mac)
    {
        Platform.RequireLinuxX64();
        byte[] full = Mac(HmacTests.Octets(key, text: false), HmacTests.Octets(message, text: true));
        Assert.Equal(mac, Convert.ToHexStringLower(full)[..mac.Length]);
    }

    /// <summary>
    /// NIST's CAVP HMAC file, every SHA-384 record ([L=48]: 300 MACs): keys of 50, 55, 128, 130
    /// and 145 octets (under, at and over the block), 128-octet messages, tags truncated to 24,
    /// 32, 40 and 48 octets.
    /// </summary>
    [Fact]
    public void MatchesNistsHmacVectors()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/hmac/HMAC.rsp");
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path).Where(r => r.GetValueOrDefault("L") == "48"))
        {
            byte[] key = Convert.FromHexString(record["Key"]);
            byte[] message = Convert.FromHexString(record["Msg"]);
            int tag = int.Parse(record["Tlen"], System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(int.Parse(record["Klen"], System.Globalization.CultureInfo.InvariantCulture), key.Length);
            Assert.Equal(record["Mac"], Convert.ToHexStringLower(Mac(key, message))[..(2 * tag)]);
            count++;
        }

        Assert.Equal(300, count);
    }

    /// <summary>
    /// Project Wycheproof's HMAC-SHA384 tests (174): keys of 24, 48 and 65 octets, empty and long
    /// messages, full and truncated (24-octet) tags, and tags with flipped bits that must not match.
    /// </summary>
    [Fact]
    public void PassesWycheproofsHmacTests()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("wycheproof/hmac_sha384_test.json");
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
    /// .NET's HMACSHA384 on random keys of 0 to 300 octets (both sides of the 128-octet block,
    /// and the digest of a long one) and messages to 400 octets fed in random pieces; and a
    /// context copied right after init MACs a second message under the same key, as HKDF uses it.
    /// </summary>
    [Fact]
    public void MatchesDotNetOnRandomKeysAndMessages()
    {
        Platform.RequireLinuxX64();
        var random = new Random(198_1384);
        for (int i = 0; i < 2000; i++)
        {
            byte[] key = new byte[random.Next(0, 301)];
            byte[] message = new byte[random.Next(0, 401)];
            byte[] second = new byte[random.Next(0, 200)];
            random.NextBytes(key);
            random.NextBytes(message);
            random.NextBytes(second);
            byte[] one = new byte[48], two = new byte[48];
            HmacSha384Context h;
            fixed (byte* k = key, m = message, s = second, o = one, t = two)
            {
                Native.HmacSha384Init(&h, k, (nuint)key.Length);
                HmacSha384Context reuse = h;    // the key's state, before any message
                int at = 0;
                while (at < message.Length)
                {
                    int piece = Math.Min(message.Length - at, random.Next(0, 160));
                    Native.HmacSha384Update(&h, m + at, (nuint)piece);
                    at += piece;
                }

                Native.HmacSha384Final(&h, o);
                Native.HmacSha384Update(&reuse, s, (nuint)second.Length);
                Native.HmacSha384Final(&reuse, t);
                Assert.True(new ReadOnlySpan<byte>(&h, sizeof(HmacSha384Context)).IndexOfAnyExcept((byte)0) < 0, "final left key state behind");
            }

            Assert.Equal(HMACSHA384.HashData(key, message), one);
            Assert.Equal(HMACSHA384.HashData(key, second), two);
            Assert.Equal(one, Mac(key, message));
        }
    }

    /// <summary>
    /// Project Wycheproof's HKDF-SHA384 tests (83): Extract then Expand gives the expected octets
    /// for every valid test; the invalid ones ask for more than 255 * 48 octets, which Expand
    /// refuses without writing.
    /// </summary>
    [Fact]
    public void PassesWycheproofsHkdfTests()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("wycheproof/hkdf_sha384_test.json");
        int count = 0;
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
            }

            count++;
        }

        Assert.Equal(83, count);
    }

    /// <summary>
    /// .NET's HKDF on random salts (empty ones too), keying material, info and lengths up to the
    /// limit, 12,240 octets; 12,241 is refused (-1) and nothing is written.
    /// </summary>
    [Fact]
    public void MatchesDotNetHkdfToItsLimit()
    {
        Platform.RequireLinuxX64();
        var random = new Random(5869_384);
        foreach (int length in new[] { 0, 1, 47, 48, 49, 96, 97, 100, 1000, 12_239, 12_240 })
        {
            byte[] salt = new byte[random.Next(0, 3) == 0 ? 0 : random.Next(1, 200)];
            byte[] ikm = new byte[random.Next(1, 200)];
            byte[] info = new byte[random.Next(0, 160)];
            random.NextBytes(salt);
            random.NextBytes(ikm);
            random.NextBytes(info);
            (int result, byte[] okm) = Hkdf(salt, ikm, info, length);
            Assert.Equal(0, result);
            byte[] expected = length == 0 ? [] : HKDF.DeriveKey(HashAlgorithmName.SHA384, ikm, length, salt, info);   // .NET refuses 0; RFC 5869 does not
            Assert.Equal(expected, okm);
        }

        (int refused, byte[] untouched) = Hkdf([1, 2, 3], [4, 5, 6], [], 12_241);
        Assert.Equal(-1, refused);
        Assert.True(untouched.AsSpan().IndexOfAnyExcept((byte)0xEE) < 0, "Expand wrote past its refusal");
    }

    /// <summary>The one-shot MAC.</summary>
    /// <param name="key">The key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 48-octet MAC.</returns>
    private static byte[] Mac(byte[] key, byte[] message)
    {
        byte[] mac = new byte[48];
        fixed (byte* k = key, m = message, o = mac)
        {
            Native.HmacSha384(k, (nuint)key.Length, m, (nuint)message.Length, o);
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
        byte[] prk = new byte[48];
        byte[] okm = new byte[length];
        okm.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* s = salt, i = ikm, n = info, p = prk, o = okm)
        {
            Native.HkdfSha384Extract(s, (nuint)salt.Length, i, (nuint)ikm.Length, p);
            result = Native.HkdfSha384Expand(p, 48, n, (nuint)info.Length, o, (nuint)length);
        }

        return (result, okm);
    }
}
