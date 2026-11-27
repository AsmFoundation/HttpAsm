using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_aes_gcm_*: AES-GCM (NIST SP 800-38D) with 96-bit nonces and 128-bit tags, through the
/// C ABI, held to NIST's CAVP GCM files (every 96-bit-IV record of AES-128 and AES-256, every tag
/// length, the decrypt files' failures included), to Project Wycheproof's AES-GCM tests, and to
/// .NET's AesGcm on random keys, nonces, AAD and texts (in place too, and with every kind of
/// forgery refused). tests/run-linux.sh runs the suite at every CPU tier, so each version answers:
/// AES-NI with PCLMULQDQ and the constant-time v1.
/// </summary>
public sealed unsafe class AesGcmTests
{
    /// <summary>The .NET copy of httpasm_aes_gcm_key has the library's size: 1024 octets.</summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(1024, Unsafe.SizeOf<AesGcmKey>());
        Assert.Equal((uint)Unsafe.SizeOf<AesGcmKey>(), Native.StructSize(15));
    }

    /// <summary>
    /// NIST's GCM encrypt files (external IV), every record with a 96-bit IV: the ciphertext must
    /// match and the tag's first Taglen bits (32 to 128) must equal the record's tag.
    /// </summary>
    /// <param name="file">The response file.</param>
    [Theory]
    [InlineData("gcmEncryptExtIV128.rsp")]
    [InlineData("gcmEncryptExtIV256.rsp")]
    public void MatchesNistsEncryptVectors(string file)
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach (Dictionary<string, string> r in Vectors.CavpRecords(Vectors.Path("cavp/gcm/" + file)).Where(r => r["IVlen"] == "96"))
        {
            byte[] key = Convert.FromHexString(r["Key"]), nonce = Convert.FromHexString(r["IV"]);
            byte[] aad = Convert.FromHexString(r["AAD"]), plaintext = Convert.FromHexString(r["PT"]);
            (byte[] ciphertext, byte[] tag) = Seal(key, nonce, aad, plaintext);
            Assert.Equal(r["CT"], Convert.ToHexStringLower(ciphertext));
            Assert.Equal(r["Tag"], Convert.ToHexStringLower(tag)[..r["Tag"].Length]);
            count++;
        }

        Assert.Equal(2625, count);
    }

    /// <summary>
    /// NIST's GCM decrypt files, every record with a 96-bit IV. With a full 128-bit tag, open must
    /// give the plaintext, or -1 and zeros for a record marked FAIL. With a shorter tag (which TLS
    /// never sends, so open takes only 16 octets): the plaintext from the counter mode alone (a
    /// seal of the ciphertext), then the full tag of that plaintext, whose first Taglen bits must
    /// equal the record's exactly when the record does not say FAIL.
    /// </summary>
    /// <param name="file">The response file.</param>
    /// <param name="failures">How many 96-bit-IV records it marks FAIL.</param>
    [Theory]
    [InlineData("gcmDecrypt128.rsp", 1363)]
    [InlineData("gcmDecrypt256.rsp", 1317)]
    public void MatchesNistsDecryptVectors(string file, int failures)
    {
        Platform.RequireLinuxX64();
        int count = 0, failed = 0;
        foreach (Dictionary<string, string> r in Vectors.CavpRecords(Vectors.Path("cavp/gcm/" + file)).Where(r => r["IVlen"] == "96"))
        {
            byte[] key = Convert.FromHexString(r["Key"]), nonce = Convert.FromHexString(r["IV"]);
            byte[] aad = Convert.FromHexString(r["AAD"]), ciphertext = Convert.FromHexString(r["CT"]);
            byte[] tag = Convert.FromHexString(r["Tag"]);
            bool fails = !r.ContainsKey("PT");
            failed += fails ? 1 : 0;
            if (tag.Length == 16)
            {
                (int result, byte[] plaintext) = Open(key, nonce, aad, ciphertext, tag);
                Assert.Equal(fails ? -1 : 0, result);
                Assert.Equal(fails ? new byte[ciphertext.Length] : Convert.FromHexString(r["PT"]), plaintext);
            }
            else
            {
                byte[] plaintext = Seal(key, nonce, [], ciphertext).Ciphertext;     // the counter mode is its own inverse
                byte[] full = Seal(key, nonce, aad, plaintext).Tag;
                Assert.Equal(!fails, full.AsSpan(0, tag.Length).SequenceEqual(tag));
                if (!fails)
                {
                    Assert.Equal(r["PT"], Convert.ToHexStringLower(plaintext));
                }
            }

            count++;
        }

        Assert.Equal(2625, count);
        Assert.Equal(failures, failed);
    }

    /// <summary>
    /// Project Wycheproof's AES-GCM tests with 96-bit nonces and 128- or 256-bit keys (133): every
    /// valid one seals to its ciphertext and tag and opens back; every invalid one (modified tags,
    /// ciphertexts, and the like) is refused with the output zeroed. Other nonce sizes and AES-192
    /// are outside the API (TLS 1.3 and QUIC use 12-octet nonces and no AES-192).
    /// </summary>
    [Fact]
    public void PassesWycheproofsTests()
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/aes_gcm_test.json")))
        {
            int keySize = group.GetProperty("keySize").GetInt32();
            if (group.GetProperty("ivSize").GetInt32() != 96 || keySize == 192)
            {
                continue;
            }

            byte[] key = Convert.FromHexString(test.GetProperty("key").GetString()!), nonce = Convert.FromHexString(test.GetProperty("iv").GetString()!);
            byte[] aad = Convert.FromHexString(test.GetProperty("aad").GetString()!), message = Convert.FromHexString(test.GetProperty("msg").GetString()!);
            byte[] ciphertext = Convert.FromHexString(test.GetProperty("ct").GetString()!), tag = Convert.FromHexString(test.GetProperty("tag").GetString()!);
            bool valid = test.GetProperty("result").GetString() == "valid";
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}: {test.GetProperty("comment").GetString()}";
            if (valid)
            {
                (byte[] c, byte[] t) = Seal(key, nonce, aad, message);
                Assert.True(c.SequenceEqual(ciphertext) && t.SequenceEqual(tag), id);
            }

            (int result, byte[] plaintext) = Open(key, nonce, aad, ciphertext, tag);
            Assert.True(result == (valid ? 0 : -1), id);
            Assert.True(plaintext.SequenceEqual(valid ? message : new byte[ciphertext.Length]), id);
            count++;
        }

        Assert.Equal(133, count);
    }

    /// <summary>
    /// .NET's AesGcm on 3,000 random keys (both sizes), nonces, AAD (0 to 300 octets, both sides of
    /// 16 and 128) and texts (0 to 2,100 octets and a 16 KiB + 13 record), seal and open, then both
    /// again in place; and one flipped bit of the tag, the ciphertext or the AAD makes open refuse
    /// with the output all zeros (no unauthenticated plaintext left).
    /// </summary>
    [Fact]
    public void MatchesDotNetAndRefusesForgeries()
    {
        Platform.RequireLinuxX64();
        var random = new Random(3880);
        int[] aadLengths = [0, 1, 5, 13, 16, 17, 31, 128, 129, 300];
        for (int i = 0; i < 3000; i++)
        {
            byte[] key = new byte[random.Next(2) == 0 ? 16 : 32], nonce = new byte[12];
            byte[] aad = new byte[aadLengths[random.Next(aadLengths.Length)]];
            byte[] plaintext = new byte[i == 0 ? 16384 + 13 : random.Next(0, 2101)];
            random.NextBytes(key);
            random.NextBytes(nonce);
            random.NextBytes(aad);
            random.NextBytes(plaintext);
            byte[] expected = new byte[plaintext.Length], expectedTag = new byte[16];
            using (var gcm = new AesGcm(key, 16))
            {
                gcm.Encrypt(nonce, plaintext, expected, expectedTag, aad);
            }

            (byte[] ciphertext, byte[] tag) = Seal(key, nonce, aad, plaintext);
            Assert.Equal(expected, ciphertext);
            Assert.Equal(expectedTag, tag);
            (int opened, byte[] back) = Open(key, nonce, aad, ciphertext, tag);
            Assert.Equal(0, opened);
            Assert.Equal(plaintext, back);

            // In place: the buffer sealed into itself, then opened back into itself.
            byte[] buffer = (byte[])plaintext.Clone();
            byte[] inPlaceTag = new byte[16];
            AesGcmKey k = MakeKey(key);
            fixed (byte* n = nonce, a = aad, b = buffer, t = inPlaceTag)
            {
                Assert.Equal(0, Native.AesGcmSeal(&k, n, a, (nuint)aad.Length, b, (nuint)buffer.Length, b, t));
                Assert.Equal(expected, buffer);
                Assert.Equal(0, Native.AesGcmOpen(&k, n, a, (nuint)aad.Length, b, (nuint)buffer.Length, t, b));
                Assert.Equal(plaintext, buffer);
            }

            // One flipped bit anywhere authenticated: refused, the output zeroed.
            int where = random.Next(3);
            byte[] badTag = (byte[])tag.Clone(), badText = (byte[])ciphertext.Clone(), badAad = (byte[])aad.Clone();
            if (where == 1 && badText.Length > 0)
            {
                badText[random.Next(badText.Length)] ^= (byte)(1 << random.Next(8));
            }
            else if (where == 2 && badAad.Length > 0)
            {
                badAad[random.Next(badAad.Length)] ^= (byte)(1 << random.Next(8));
            }
            else
            {
                badTag[random.Next(16)] ^= (byte)(1 << random.Next(8));
            }

            (int refused, byte[] zeros) = Open(key, nonce, badAad, badText, badTag);
            Assert.Equal(-1, refused);
            Assert.True(zeros.AsSpan().IndexOfAnyExcept((byte)0) < 0, "open left plaintext behind a refusal");
        }
    }

    /// <summary>
    /// SP 800-38D's limits: a text longer than 2^36 - 32 octets, or AAD longer than 2^61 - 1
    /// octets, is refused with -1 before anything is read or written (the buffers here are 16
    /// octets: a read or write past them would fault or show).
    /// </summary>
    [Fact]
    public void RefusesTextsAndAadPastTheLimits()
    {
        Platform.RequireLinuxX64();
        AesGcmKey k = MakeKey(new byte[16]);
        byte[] nonce = new byte[12], buffer = new byte[16], tag = new byte[16];
        buffer.AsSpan().Fill(0x5A);
        tag.AsSpan().Fill(0x5A);
        fixed (byte* n = nonce, b = buffer, t = tag)
        {
            ulong longText = (1UL << 36) - 31, longAad = 1UL << 61;
            nuint tooLong = (nuint)longText, tooMuchAad = (nuint)longAad;   // x64 only: nuint is 64 bits
            Assert.Equal(-1, Native.AesGcmSeal(&k, n, b, 0, b, tooLong, b, t));
            Assert.Equal(-1, Native.AesGcmSeal(&k, n, b, tooMuchAad, b, 0, b, t));
            Assert.Equal(-1, Native.AesGcmOpen(&k, n, b, 0, b, tooLong, t, b));
            Assert.Equal(-1, Native.AesGcmOpen(&k, n, b, tooMuchAad, b, 0, t, b));
        }

        Assert.True(buffer.AsSpan().IndexOfAnyExcept((byte)0x5A) < 0 && tag.AsSpan().IndexOfAnyExcept((byte)0x5A) < 0, "a refusal wrote");
    }

    /// <summary>Key lengths other than 16 and 32 octets are refused, the key structure untouched.</summary>
    /// <param name="length">The refused length.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(24)]
    [InlineData(31)]
    public void RefusesOtherKeyLengths(int length)
    {
        Platform.RequireLinuxX64();
        byte[] key = new byte[Math.Max(length, 1)];
        AesGcmKey k;
        new Span<byte>(&k, sizeof(AesGcmKey)).Fill(0xA5);
        fixed (byte* p = key)
        {
            Assert.Equal(-1, Native.AesGcmInit(&k, p, (nuint)length));
        }

        Assert.True(new ReadOnlySpan<byte>(&k, sizeof(AesGcmKey)).IndexOfAnyExcept((byte)0xA5) < 0, "a refused init wrote into the key");
    }

    /// <summary>A key made by httpasm_aes_gcm_init.</summary>
    /// <param name="key">16 or 32 octets.</param>
    /// <returns>The key structure (by value: no alignment is needed).</returns>
    private static AesGcmKey MakeKey(byte[] key)
    {
        AesGcmKey k;
        fixed (byte* p = key)
        {
            Assert.Equal(0, Native.AesGcmInit(&k, p, (nuint)key.Length));
        }

        return k;
    }

    /// <summary>One seal into fresh buffers.</summary>
    /// <param name="key">The key octets.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The AAD.</param>
    /// <param name="plaintext">The text.</param>
    /// <returns>The ciphertext and the tag.</returns>
    private static (byte[] Ciphertext, byte[] Tag) Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        AesGcmKey k = MakeKey(key);
        byte[] ciphertext = new byte[plaintext.Length], tag = new byte[16];
        fixed (byte* n = nonce, a = aad, p = plaintext, c = ciphertext, t = tag)
        {
            Assert.Equal(0, Native.AesGcmSeal(&k, n, a, (nuint)aad.Length, p, (nuint)plaintext.Length, c, t));
        }

        return (ciphertext, tag);
    }

    /// <summary>One open into a buffer pre-filled with 0xEE (so a refusal's zeroing shows).</summary>
    /// <param name="key">The key octets.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The AAD.</param>
    /// <param name="ciphertext">The text.</param>
    /// <param name="tag">16 octets.</param>
    /// <returns>open's result and the output buffer.</returns>
    private static (int Result, byte[] Plaintext) Open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        AesGcmKey k = MakeKey(key);
        byte[] plaintext = new byte[ciphertext.Length];
        plaintext.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* n = nonce, a = aad, c = ciphertext, t = tag, p = plaintext)
        {
            result = Native.AesGcmOpen(&k, n, a, (nuint)aad.Length, c, (nuint)ciphertext.Length, t, p);
        }

        return (result, plaintext);
    }
}
