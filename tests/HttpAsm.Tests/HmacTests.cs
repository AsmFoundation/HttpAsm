using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// HMAC-SHA256 (FIPS 198-1, RFC 2104) and HKDF-SHA256 (RFC 5869) through the C ABI, held to
/// RFC 4231's examples, NIST's CAVP HMAC file (its SHA-256 section), Project Wycheproof's HMAC
/// and HKDF files, and .NET's HMACSHA256 and HKDF on random keys and messages. Both run on
/// SHA-256's compression, so the suite at every tier (tests/run-linux.sh) runs both of its
/// versions under them.
/// </summary>
public sealed unsafe class HmacTests
{
    /// <summary>The .NET copy of httpasm_hmac_sha256_ctx has the library's size: 224 octets.</summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(224, Unsafe.SizeOf<HmacSha256Context>());
        Assert.Equal((uint)Unsafe.SizeOf<HmacSha256Context>(), Native.StructSize(11));
    }

    /// <summary>
    /// RFC 4231's seven HMAC-SHA-256 examples: short and long keys (20, 4, 25 and 131 octets: the
    /// last hashed first), messages shorter and longer than a block, and case 5's MAC truncated
    /// to its first 16 octets.
    /// </summary>
    /// <param name="key">The key: hex, or "XX*N" for the octet XX N times.</param>
    /// <param name="message">The message: text, "hex:" and hex, or "XX*N".</param>
    /// <param name="mac">The MAC (or its truncation), in hex.</param>
    [Theory]
    [InlineData("0b*20", "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")]
    [InlineData("4a656665", "what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")]
    [InlineData("aa*20", "dd*50", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")]
    [InlineData("0102030405060708090a0b0c0d0e0f10111213141516171819", "cd*50", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")]
    [InlineData("0c*20", "Test With Truncation", "a3b6167473100ee06e0c796c2955552b")]
    [InlineData("aa*131", "Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")]
    [InlineData("aa*131",
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")]
    public void MatchesRfc4231(string key, string message, string mac)
    {
        Platform.RequireLinuxX64();
        byte[] full = Mac(Octets(key, text: false), Octets(message, text: true));
        Assert.Equal(mac, Convert.ToHexStringLower(full)[..mac.Length]);
    }

    /// <summary>
    /// NIST's CAVP HMAC file, every SHA-256 record ([L=32]: 225 MACs): keys from 40 to 74 octets
    /// on both sides of the block, 128-octet messages, tags truncated to 16, 24 and 32 octets.
    /// </summary>
    [Fact]
    public void MatchesNistsHmacVectors()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/hmac/HMAC.rsp");
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path).Where(r => r.GetValueOrDefault("L") == "32"))
        {
            byte[] key = Convert.FromHexString(record["Key"]);
            byte[] message = Convert.FromHexString(record["Msg"]);
            int tag = int.Parse(record["Tlen"], System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(int.Parse(record["Klen"], System.Globalization.CultureInfo.InvariantCulture), key.Length);
            Assert.Equal(record["Mac"], Convert.ToHexStringLower(Mac(key, message))[..(2 * tag)]);
            count++;
        }

        Assert.True(count >= 200, $"only {count} SHA-256 records in HMAC.rsp");
    }

    /// <summary>
    /// Project Wycheproof's HMAC-SHA256 tests (174): keys of 0 to 65 octets and longer, empty and
    /// long messages, full and truncated tags, and tags with flipped bits that must not match.
    /// </summary>
    [Fact]
    public void PassesWycheproofsHmacTests()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("wycheproof/hmac_sha256_test.json");
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
    /// .NET's HMACSHA256 on random keys of 0 to 200 octets (both sides of a block, and the digest
    /// of a long one) and messages to 300 octets fed in random pieces; and a context copied right
    /// after init MACs a second message under the same key, as HKDF uses it.
    /// </summary>
    [Fact]
    public void MatchesDotNetOnRandomKeysAndMessages()
    {
        Platform.RequireLinuxX64();
        var random = new Random(198_1);
        for (int i = 0; i < 2000; i++)
        {
            byte[] key = new byte[random.Next(0, 201)];
            byte[] message = new byte[random.Next(0, 301)];
            byte[] second = new byte[random.Next(0, 100)];
            random.NextBytes(key);
            random.NextBytes(message);
            random.NextBytes(second);
            byte[] one = new byte[32], two = new byte[32];
            HmacSha256Context h;
            fixed (byte* k = key, m = message, s = second, o = one, t = two)
            {
                Native.HmacSha256Init(&h, k, (nuint)key.Length);
                HmacSha256Context reuse = h;    // the key's state, before any message
                int at = 0;
                while (at < message.Length)
                {
                    int piece = Math.Min(message.Length - at, random.Next(0, 80));
                    Native.HmacSha256Update(&h, m + at, (nuint)piece);
                    at += piece;
                }

                Native.HmacSha256Final(&h, o);
                Native.HmacSha256Update(&reuse, s, (nuint)second.Length);
                Native.HmacSha256Final(&reuse, t);
                Assert.True(new ReadOnlySpan<byte>(&h, sizeof(HmacSha256Context)).IndexOfAnyExcept((byte)0) < 0, "final left key state behind");
            }

            Assert.Equal(HMACSHA256.HashData(key, message), one);
            Assert.Equal(HMACSHA256.HashData(key, second), two);
            Assert.Equal(one, Mac(key, message));
        }
    }

    /// <summary>
    /// Project Wycheproof's HKDF-SHA256 tests (86, RFC 5869's own among them): Extract then
    /// Expand gives the expected octets for every valid test; the invalid ones ask for more than
    /// 255 * 32 octets, which Expand refuses without writing.
    /// </summary>
    [Fact]
    public void PassesWycheproofsHkdfTests()
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("wycheproof/hkdf_sha256_test.json");
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

        Assert.Equal(86, count);
    }

    /// <summary>
    /// .NET's HKDF on random salts (empty ones too), keying material, info and lengths up to the
    /// limit, 8160 octets; 8161 is refused (-1) and nothing is written.
    /// </summary>
    [Fact]
    public void MatchesDotNetHkdfToItsLimit()
    {
        Platform.RequireLinuxX64();
        var random = new Random(5869);
        foreach (int length in new[] { 0, 1, 31, 32, 33, 64, 65, 100, 1000, 8159, 8160 })
        {
            byte[] salt = new byte[random.Next(0, 3) == 0 ? 0 : random.Next(1, 100)];
            byte[] ikm = new byte[random.Next(1, 100)];
            byte[] info = new byte[random.Next(0, 80)];
            random.NextBytes(salt);
            random.NextBytes(ikm);
            random.NextBytes(info);
            (int result, byte[] okm) = Hkdf(salt, ikm, info, length);
            Assert.Equal(0, result);
            byte[] expected = length == 0 ? [] : HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);   // .NET refuses 0; RFC 5869 does not
            Assert.Equal(expected, okm);
        }

        (int refused, byte[] untouched) = Hkdf([1, 2, 3], [4, 5, 6], [], 8161);
        Assert.Equal(-1, refused);
        Assert.True(untouched.AsSpan().IndexOfAnyExcept((byte)0xEE) < 0, "Expand wrote past its refusal");
    }

    /// <summary>An InlineData octet string: "XX*N" (the octet XX, N times), "hex:" and hex, or plain text or hex.</summary>
    /// <param name="spec">The string.</param>
    /// <param name="text">Whether a plain string is text (ASCII) rather than hex.</param>
    /// <returns>The octets.</returns>
    private static byte[] Octets(string spec, bool text)
    {
        int star = spec.IndexOf('*');
        if (star == 2 && Uri.IsHexDigit(spec[0]) && Uri.IsHexDigit(spec[1]))
        {
            return Enumerable.Repeat(Convert.FromHexString(spec[..2])[0], int.Parse(spec[3..], System.Globalization.CultureInfo.InvariantCulture)).ToArray();
        }

        if (spec.StartsWith("hex:", StringComparison.Ordinal))
        {
            return Convert.FromHexString(spec[4..]);
        }

        return text ? Encoding.ASCII.GetBytes(spec) : Convert.FromHexString(spec);
    }

    /// <summary>The one-shot MAC.</summary>
    /// <param name="key">The key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 32-octet MAC.</returns>
    private static byte[] Mac(byte[] key, byte[] message)
    {
        byte[] mac = new byte[32];
        fixed (byte* k = key, m = message, o = mac)
        {
            Native.HmacSha256(k, (nuint)key.Length, m, (nuint)message.Length, o);
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
        byte[] prk = new byte[32];
        byte[] okm = new byte[length];
        okm.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* s = salt, i = ikm, n = info, p = prk, o = okm)
        {
            Native.HkdfSha256Extract(s, (nuint)salt.Length, i, (nuint)ikm.Length, p);
            result = Native.HkdfSha256Expand(p, 32, n, (nuint)info.Length, o, (nuint)length);
        }

        return (result, okm);
    }
}
