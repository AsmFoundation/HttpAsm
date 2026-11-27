using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_aes_*: the AES-128 and AES-256 block cipher (FIPS 197) through the C ABI, held to
/// FIPS 197's appendix C, to NIST's AESAVS known-answer files (ECB: GFSbox, KeySbox, VarKey,
/// VarTxt) and to .NET's AES on random keys and blocks. tests/run-linux.sh runs the suite at every
/// CPU tier, so both versions answer: AES-NI, and the constant-time bitsliced v1 (with its own key
/// schedule, whose SubWord is the bitsliced S-box too). A key made at one tier and used at another
/// is tested by tests/native/tiers, which switches tiers inside one process.
/// </summary>
public sealed unsafe class AesTests
{
    /// <summary>The .NET copy of httpasm_aes_key has the library's size: 496 octets.</summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(496, Unsafe.SizeOf<AesKey>());
        Assert.Equal((uint)Unsafe.SizeOf<AesKey>(), Native.StructSize(14));
    }

    /// <summary>
    /// FIPS 197 appendix C: the example vectors of AES-128 (C.1) and AES-256 (C.3), the key
    /// 00 01 02 ... and the plaintext 00 11 22 ... ff.
    /// </summary>
    /// <param name="key">The key, hex.</param>
    /// <param name="ciphertext">The ciphertext, hex.</param>
    [Theory]
    [InlineData("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a")]
    [InlineData("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089")]
    public void MatchesFips197AppendixC(string key, string ciphertext)
    {
        Platform.RequireLinuxX64();
        byte[] output = Encrypt(Convert.FromHexString(key), Convert.FromHexString("00112233445566778899aabbccddeeff"));
        Assert.Equal(ciphertext, Convert.ToHexStringLower(output));
    }

    /// <summary>
    /// FIPS 197 appendix A: the key schedule's words, through the round keys the library keeps
    /// (w[40..43] of A.1's AES-128 key and w[56..59] of A.3's AES-256 key, its last round key).
    /// </summary>
    /// <param name="key">The key, hex.</param>
    /// <param name="lastRoundKey">The last four words of its schedule, hex.</param>
    [Theory]
    [InlineData("2b7e151628aed2a6abf7158809cf4f3c", "d014f9a8c9ee2589e13f0cc8b6630ca6")]
    [InlineData("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "fe4890d1e6188d0b046df344706c631e")]
    public void ExpandsTheKeyAsFips197AppendixA(string key, string lastRoundKey)
    {
        Platform.RequireLinuxX64();
        byte[] octets = Convert.FromHexString(key);
        AesKey k;
        fixed (byte* p = octets)
        {
            Assert.Equal(0, Native.AesInit(&k, p, (nuint)octets.Length));
        }

        int rounds = (int)k.Rounds;
        Assert.Equal(octets.Length == 16 ? 10 : 14, rounds);
        Assert.Equal(lastRoundKey, Convert.ToHexStringLower(new ReadOnlySpan<byte>(k.RoundKeys + 16 * rounds, 16)));
    }

    /// <summary>
    /// Every record of NIST's AESAVS ECB known-answer files for AES-128 and AES-256 (both their
    /// encrypt and decrypt sections: each record is a key, a plaintext and its ciphertext):
    /// GFSbox and KeySbox (the S-box's tricky inputs), VarKey (every one-bit-prefix key) and
    /// VarTxt (every one-bit-prefix block).
    /// </summary>
    /// <param name="file">The response file.</param>
    /// <param name="records">How many records it holds.</param>
    [Theory]
    [InlineData("ECBGFSbox128.rsp", 14)]
    [InlineData("ECBGFSbox256.rsp", 10)]
    [InlineData("ECBKeySbox128.rsp", 42)]
    [InlineData("ECBKeySbox256.rsp", 32)]
    [InlineData("ECBVarKey128.rsp", 256)]
    [InlineData("ECBVarKey256.rsp", 512)]
    [InlineData("ECBVarTxt128.rsp", 256)]
    [InlineData("ECBVarTxt256.rsp", 256)]
    public void MatchesNistsKnownAnswers(string file, int records)
    {
        Platform.RequireLinuxX64();
        string path = Vectors.Path("cavp/aes/" + file);
        int count = 0;
        foreach (Dictionary<string, string> record in Vectors.CavpRecords(path))
        {
            byte[] output = Encrypt(Convert.FromHexString(record["KEY"]), Convert.FromHexString(record["PLAINTEXT"]));
            Assert.Equal(record["CIPHERTEXT"], Convert.ToHexStringLower(output));
            count++;
        }

        Assert.Equal(records, count);
    }

    /// <summary>
    /// .NET's AES (ECB, one block) on 4,000 random keys of both sizes and random blocks, and the
    /// encryption in place (the input octets overwritten by the output).
    /// </summary>
    [Fact]
    public void MatchesDotNetOnRandomKeysAndBlocks()
    {
        Platform.RequireLinuxX64();
        var random = new Random(197);
        for (int i = 0; i < 4000; i++)
        {
            byte[] key = new byte[random.Next(2) == 0 ? 16 : 32];
            byte[] block = new byte[16];
            random.NextBytes(key);
            random.NextBytes(block);
            using var aes = Aes.Create();
            aes.Key = key;
            byte[] expected = aes.EncryptEcb(block, PaddingMode.None);
            Assert.Equal(expected, Encrypt(key, block));
            AesKey k;
            fixed (byte* p = key, b = block)
            {
                Assert.Equal(0, Native.AesInit(&k, p, (nuint)key.Length));
                Native.AesEncryptBlock(&k, b, b);
            }

            Assert.Equal(expected, block);
        }
    }

    /// <summary>
    /// Any key length but 16 and 32 octets is refused with -1, and the key structure is left as
    /// it was (AES-192 is not offered: no TLS 1.3 or QUIC suite uses it).
    /// </summary>
    /// <param name="length">The refused length.</param>
    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(24)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void RefusesOtherKeyLengths(int length)
    {
        Platform.RequireLinuxX64();
        byte[] key = new byte[Math.Max(length, 1)];
        AesKey k;
        new Span<byte>(&k, sizeof(AesKey)).Fill(0xA5);
        fixed (byte* p = key)
        {
            Assert.Equal(-1, Native.AesInit(&k, p, (nuint)length));
        }

        Assert.True(new ReadOnlySpan<byte>(&k, sizeof(AesKey)).IndexOfAnyExcept((byte)0xA5) < 0, "a refused init wrote into the key");
    }

    /// <summary>One block under a key, through httpasm_aes_init and httpasm_aes_encrypt_block.</summary>
    /// <param name="key">16 or 32 octets.</param>
    /// <param name="block">16 octets.</param>
    /// <returns>The ciphertext block.</returns>
    private static byte[] Encrypt(byte[] key, byte[] block)
    {
        byte[] output = new byte[16];
        AesKey k;
        fixed (byte* p = key, b = block, o = output)
        {
            Assert.Equal(0, Native.AesInit(&k, p, (nuint)key.Length));
            Native.AesEncryptBlock(&k, b, o);
        }

        return output;
    }
}
