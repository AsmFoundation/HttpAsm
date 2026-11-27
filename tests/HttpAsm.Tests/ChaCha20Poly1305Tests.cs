using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_chacha20, httpasm_poly1305 and httpasm_chacha20_poly1305_seal/_open (RFC 8439) through
/// the C ABI, held to every test vector of RFC 8439 itself (read from the pinned text, so no octet
/// is copied by hand: the block function, encryption, Poly1305 with its reduction's edge cases,
/// the one-time key's generation, and the AEAD both ways), to Project Wycheproof's
/// ChaCha20-Poly1305 tests, to .NET's ChaCha20Poly1305 on random keys, nonces, AAD and texts (in
/// place too, and with every kind of forgery refused), to a BigInteger Poly1305 on random and
/// extreme keys and messages, and to a plain C# ChaCha20 across the 32-bit block counter's wrap.
/// tests/run-linux.sh runs the suite at every CPU tier, so each version answers: AVX2 (eight
/// blocks a step), SSSE3 and SSE2 (four), each with Poly1305 stitched into the AEAD.
/// </summary>
public sealed unsafe partial class ChaCha20Poly1305Tests
{
    /// <summary>2^130 - 5, Poly1305's prime.</summary>
    private static readonly BigInteger Prime = (BigInteger.One << 130) - 5;

    /// <summary>
    /// RFC 8439 A.1's five block-function vectors: each block's 64 octets of keystream (the
    /// cipher over 64 zero octets) from its key, nonce and block counter.
    /// </summary>
    [Fact]
    public void MatchesRfc8439sBlockFunctionVectors()
    {
        Platform.RequireLinuxX64();
        List<RfcVector> vectors = RfcVectors("A.1.  ", "A.2.  ");
        Assert.Equal(5, vectors.Count);
        foreach (RfcVector v in vectors)
        {
            byte[] keystream = ChaCha20(v.Octets["key"], (uint)v.Numbers["block counter"], v.Octets["nonce"], new byte[64]);
            Assert.Equal(Convert.ToHexStringLower(v.Octets["keystream"]), Convert.ToHexStringLower(keystream));
        }
    }

    /// <summary>RFC 8439 A.2's three encryption vectors (64, 375 and 127 octets, counters 0, 1, 42).</summary>
    [Fact]
    public void MatchesRfc8439sEncryptionVectors()
    {
        Platform.RequireLinuxX64();
        List<RfcVector> vectors = RfcVectors("A.2.  ", "A.3.  ");
        Assert.Equal(3, vectors.Count);
        foreach (RfcVector v in vectors)
        {
            byte[] ciphertext = ChaCha20(v.Octets["key"], (uint)v.Numbers["block counter"], v.Octets["nonce"], v.Octets["plaintext"]);
            Assert.Equal(Convert.ToHexStringLower(v.Octets["ciphertext"]), Convert.ToHexStringLower(ciphertext));
        }
    }

    /// <summary>
    /// RFC 8439 A.3's eleven Poly1305 vectors: #1-#4 whole messages (r = 0 among them), #5-#11
    /// the reduction's edges (a partially reduced result that is not reduced fully, s overflowing
    /// 2^128, carries from an all-ones limb, results of exactly 2^130 - 5 and 2^130 - 6, and the
    /// 5 * H + L folding producing 131 bits).
    /// </summary>
    [Fact]
    [Requirement("RFC8439-2.5-p3#1")]
    public void MatchesRfc8439sPoly1305Vectors()
    {
        Platform.RequireLinuxX64();
        List<RfcVector> vectors = RfcVectors("A.3.  ", "A.4.  ");
        Assert.Equal(11, vectors.Count);
        foreach (RfcVector v in vectors)
        {
            byte[] key = v.Octets.TryGetValue("one-time poly1305 key", out byte[]? k) ? k : [.. v.Octets["r"], .. v.Octets["s"]];
            byte[] message = v.Octets.TryGetValue("text to mac", out byte[]? m) ? m : v.Octets["data"];
            Assert.Equal(Convert.ToHexStringLower(v.Octets["tag"]), Convert.ToHexStringLower(Poly1305(key, message)));
        }
    }

    /// <summary>
    /// RFC 8439 A.4's three one-time key generations (2.6): the Poly1305 key is the first 32
    /// octets of ChaCha20's block 0 under the AEAD's key and nonce.
    /// </summary>
    [Fact]
    public void MatchesRfc8439sKeyGenerationVectors()
    {
        Platform.RequireLinuxX64();
        List<RfcVector> vectors = RfcVectors("A.4.  ", "A.5.  ");
        Assert.Equal(3, vectors.Count);
        foreach (RfcVector v in vectors)
        {
            byte[] key = ChaCha20(v.Octets["the chacha20 key"], 0, v.Octets["the nonce"], new byte[32]);
            Assert.Equal(Convert.ToHexStringLower(v.Octets["poly1305 one-time key"]), Convert.ToHexStringLower(key));
        }
    }

    /// <summary>
    /// RFC 8439's two AEAD examples: 2.8.2's seal (the nonce its 32-bit constant then its IV)
    /// must give the ciphertext and tag, and A.5's received message must open to its plaintext
    /// (and seal back to the received ciphertext and tag).
    /// </summary>
    [Fact]
    public void MatchesRfc8439sAeadExamples()
    {
        Platform.RequireLinuxX64();
        RfcVector example = Assert.Single(RfcVectors("2.8.2.  ", "3.  "));
        byte[] nonce = [.. example.Octets["32-bit fixed-common part"], .. example.Octets["iv"]];
        (byte[] ciphertext, byte[] tag) = Seal(example.Octets["key"], nonce, example.Octets["aad"], example.Octets["plaintext"]);
        Assert.Equal(Convert.ToHexStringLower(example.Octets["ciphertext"]), Convert.ToHexStringLower(ciphertext));
        Assert.Equal(Convert.ToHexStringLower(example.Octets["tag"]), Convert.ToHexStringLower(tag));

        RfcVector received = Assert.Single(RfcVectors("A.5.  ", "Appendix B."));
        Assert.Equal(received.Octets["received tag"], received.Octets["calculated tag"]);
        (int opened, byte[] plaintext) = Open(received.Octets["the chacha20 key"], received.Octets["the nonce"], received.Octets["the aad"], received.Octets["ciphertext"], received.Octets["received tag"]);
        Assert.Equal(0, opened);
        Assert.Equal(Convert.ToHexStringLower(received.Octets["plaintext"]), Convert.ToHexStringLower(plaintext));
        (byte[] again, byte[] againTag) = Seal(received.Octets["the chacha20 key"], received.Octets["the nonce"], received.Octets["the aad"], plaintext);
        Assert.Equal(received.Octets["ciphertext"], again);
        Assert.Equal(received.Octets["received tag"], againTag);
    }

    /// <summary>
    /// Project Wycheproof's ChaCha20-Poly1305 tests with 96-bit nonces (316): every valid one
    /// seals to its ciphertext and tag and opens back; every invalid one (modified tags and
    /// ciphertexts, edge cases of Poly1305's arithmetic) is refused with the output zeroed. The
    /// nine with other nonce sizes are outside the API (RFC 8439's nonce is 96 bits).
    /// </summary>
    [Fact]
    public void PassesWycheproofsTests()
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach ((System.Text.Json.JsonElement group, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path("wycheproof/chacha20_poly1305_test.json")))
        {
            if (group.GetProperty("ivSize").GetInt32() != 96)
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

        Assert.Equal(316, count);
    }

    /// <summary>
    /// .NET's ChaCha20Poly1305 on 3,000 random keys, nonces, AAD (0 to 300 octets, both sides of
    /// 16) and texts: first every edge of the drivers' paths (a text in block 1 alone up to 64
    /// octets; the first 64 then whole steps of 256 or 512 octets with nothing left, a short or a
    /// long rest; a 16 KiB + 13 record), then random lengths up to 2,100 octets. Seal and open,
    /// then both again in place; and one flipped bit of the tag, the ciphertext or the AAD makes
    /// open refuse with the output all zeros (no unauthenticated plaintext left).
    /// </summary>
    [Fact]
    public void MatchesDotNetAndRefusesForgeries()
    {
        Platform.RequireLinuxX64();
        Assert.True(ChaCha20Poly1305.IsSupported, ".NET's ChaCha20Poly1305 is the reference here");
        var random = new Random(8439);
        int[] aadLengths = [0, 1, 5, 13, 15, 16, 17, 31, 128, 129, 300];
        int[] edges = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257, 319, 320, 321,
                       511, 512, 513, 575, 576, 577, 832, 1087, 1088, 1089, 1600, 16384 + 13];
        for (int i = 0; i < 3000; i++)
        {
            byte[] key = new byte[32], nonce = new byte[12];
            byte[] aad = new byte[aadLengths[random.Next(aadLengths.Length)]];
            byte[] plaintext = new byte[i < edges.Length ? edges[i] : random.Next(0, 2101)];
            random.NextBytes(key);
            random.NextBytes(nonce);
            random.NextBytes(aad);
            random.NextBytes(plaintext);
            byte[] expected = new byte[plaintext.Length], expectedTag = new byte[16];
            using (var reference = new ChaCha20Poly1305(key))
            {
                reference.Encrypt(nonce, plaintext, expected, expectedTag, aad);
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
            fixed (byte* k = key, n = nonce, a = aad, b = buffer, t = inPlaceTag)
            {
                Assert.Equal(0, Native.ChaCha20Poly1305Seal(k, n, a, (nuint)aad.Length, b, (nuint)buffer.Length, b, t));
                Assert.Equal(expected, buffer);
                Assert.Equal(expectedTag, inPlaceTag);
                Assert.Equal(0, Native.ChaCha20Poly1305Open(k, n, a, (nuint)aad.Length, b, (nuint)buffer.Length, t, b));
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
    /// The whole tag is checked (RFC 8439 4: no truncation): each of the 16 octets, and each bit of
    /// it, changed alone makes open refuse, for texts that end in each driver's last-octets path.
    /// </summary>
    [Fact]
    [Requirement("RFC8439-4-p10#1", "RFC8439-4-p10#2")]
    public void ChecksEveryOctetOfTheTag()
    {
        Platform.RequireLinuxX64();
        var random = new Random(16);
        foreach (int length in new[] { 0, 1, 64, 65, 300, 1000 })
        {
            byte[] key = new byte[32], nonce = new byte[12], aad = new byte[5], plaintext = new byte[length];
            random.NextBytes(key);
            random.NextBytes(nonce);
            random.NextBytes(aad);
            random.NextBytes(plaintext);
            (byte[] ciphertext, byte[] tag) = Seal(key, nonce, aad, plaintext);
            for (int octet = 0; octet < 16; octet++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    byte[] bad = (byte[])tag.Clone();
                    bad[octet] ^= (byte)(1 << bit);
                    (int result, byte[] output) = Open(key, nonce, aad, ciphertext, bad);
                    Assert.Equal(-1, result);
                    Assert.True(output.AsSpan().IndexOfAnyExcept((byte)0) < 0, $"octet {octet} bit {bit}: plaintext left behind");
                }
            }
        }
    }

    /// <summary>
    /// Poly1305 against the definition computed with BigInteger (RFC 8439 2.5.1): 4,000 random
    /// keys and messages of 0 to 300 octets, and the extremes of the 64-bit-limb arithmetic: r as
    /// large as clamping leaves it, s all ones (its addition overflowing 2^128), messages of all
    /// 0xFF octets (each block's limbs at their tops, with the 2^128 bit), and r = 0.
    /// </summary>
    [Fact]
    [Requirement("RFC8439-2.5-p3#1")]
    public void MatchesABigIntegerPoly1305()
    {
        Platform.RequireLinuxX64();
        var random = new Random(1305);
        for (int i = 0; i < 4000; i++)
        {
            byte[] key = new byte[32], message = new byte[random.Next(0, 301)];
            random.NextBytes(key);
            random.NextBytes(message);
            switch (i % 8)
            {
                case 1:
                    key.AsSpan(0, 16).Fill(0xFF);                   // r: every bit clamping allows
                    break;
                case 2:
                    key.AsSpan(16, 16).Fill(0xFF);                  // s: the final addition wraps
                    break;
                case 3:
                    message.AsSpan().Fill(0xFF);                    // the limbs at their tops
                    key.AsSpan(0, 16).Fill(0xFF);
                    break;
                case 4:
                    key.AsSpan(0, 16).Clear();                      // r = 0: the tag is s
                    break;
            }

            Assert.Equal(Convert.ToHexStringLower(Poly1305Reference(key, message)), Convert.ToHexStringLower(Poly1305(key, message)));
        }
    }

    /// <summary>
    /// The raw cipher against a plain C# ChaCha20 (RFC 8439 2.3-2.4) on 2,000 random keys and
    /// nonces: first every edge of the drivers' paths (up to 128 octets in two horizontal blocks,
    /// whole steps of 256 or 512 octets with nothing left, a rest of 128 octets or less, a longer
    /// rest), then random lengths up to 1,100 octets and some of 4 KiB + 7; from random block
    /// counters and from counters just below 2^32, where the counter wraps to 0 with the nonce
    /// unchanged; and in place.
    /// </summary>
    [Fact]
    public void MatchesAPlainChaCha20AcrossTheCounterWrap()
    {
        Platform.RequireLinuxX64();
        var random = new Random(20);
        int[] edges = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 383, 384, 385, 511, 512, 513, 640, 641, 767, 768, 1024, 1153, 4096 + 7];
        for (int i = 0; i < 2000; i++)
        {
            int length = i < edges.Length ? edges[i] : i % 97 == 0 ? 4096 + 7 : random.Next(0, 1101);
            byte[] key = new byte[32], nonce = new byte[12], input = new byte[length];
            random.NextBytes(key);
            random.NextBytes(nonce);
            random.NextBytes(input);
            uint counter = i % 3 == 0 ? uint.MaxValue - (uint)random.Next(0, 20) : (uint)random.NextInt64(0, 1L << 32);
            byte[] expected = ChaCha20Reference(key, counter, nonce, input);
            Assert.Equal(expected, ChaCha20(key, counter, nonce, input));
            byte[] buffer = (byte[])input.Clone();
            fixed (byte* k = key, n = nonce, b = buffer)
            {
                Native.ChaCha20(k, counter, n, b, (nuint)buffer.Length, b);
            }

            Assert.Equal(expected, buffer);
        }
    }

    /// <summary>
    /// A text longer than 2^38 - 64 octets ((2^32 - 1) blocks from counter 1, RFC 8439 2.8) is
    /// refused with -1 before anything is read or written (the buffers here are 16 octets: a read
    /// or write past them would fault or show).
    /// </summary>
    [Fact]
    public void RefusesTextsPastTheLimit()
    {
        Platform.RequireLinuxX64();
        byte[] key = new byte[32], nonce = new byte[12], buffer = new byte[16], tag = new byte[16];
        buffer.AsSpan().Fill(0x5A);
        tag.AsSpan().Fill(0x5A);
        fixed (byte* k = key, n = nonce, b = buffer, t = tag)
        {
            ulong longest = (1UL << 38) - 64;
            nuint tooLong = (nuint)(longest + 1);                  // x64 only: nuint is 64 bits
            Assert.Equal(-1, Native.ChaCha20Poly1305Seal(k, n, b, 0, b, tooLong, b, t));
            Assert.Equal(-1, Native.ChaCha20Poly1305Open(k, n, b, 0, b, tooLong, t, b));
        }

        Assert.True(buffer.AsSpan().IndexOfAnyExcept((byte)0x5A) < 0 && tag.AsSpan().IndexOfAnyExcept((byte)0x5A) < 0, "a refusal wrote");
    }

    /// <summary>One call of httpasm_chacha20 into a fresh buffer.</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="counter">The first block's counter.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="input">The octets to xor with the keystream.</param>
    /// <returns>The result.</returns>
    private static byte[] ChaCha20(byte[] key, uint counter, byte[] nonce, byte[] input)
    {
        byte[] output = new byte[input.Length];
        fixed (byte* k = key, n = nonce, i = input, o = output)
        {
            Native.ChaCha20(k, counter, n, i, (nuint)input.Length, o);
        }

        return output;
    }

    /// <summary>One call of httpasm_poly1305.</summary>
    /// <param name="key">32 octets: r, then s.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 16-octet tag.</returns>
    private static byte[] Poly1305(byte[] key, byte[] message)
    {
        byte[] tag = new byte[16];
        fixed (byte* k = key, m = message, t = tag)
        {
            Native.Poly1305(k, m, (nuint)message.Length, t);
        }

        return tag;
    }

    /// <summary>One seal into fresh buffers.</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The AAD.</param>
    /// <param name="plaintext">The text.</param>
    /// <returns>The ciphertext and the tag.</returns>
    private static (byte[] Ciphertext, byte[] Tag) Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        byte[] ciphertext = new byte[plaintext.Length], tag = new byte[16];
        fixed (byte* k = key, n = nonce, a = aad, p = plaintext, c = ciphertext, t = tag)
        {
            Assert.Equal(0, Native.ChaCha20Poly1305Seal(k, n, a, (nuint)aad.Length, p, (nuint)plaintext.Length, c, t));
        }

        return (ciphertext, tag);
    }

    /// <summary>One open into a buffer pre-filled with 0xEE (so a refusal's zeroing shows).</summary>
    /// <param name="key">32 octets.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="aad">The AAD.</param>
    /// <param name="ciphertext">The text.</param>
    /// <param name="tag">16 octets.</param>
    /// <returns>open's result and the output buffer.</returns>
    private static (int Result, byte[] Plaintext) Open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        plaintext.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* k = key, n = nonce, a = aad, c = ciphertext, t = tag, p = plaintext)
        {
            result = Native.ChaCha20Poly1305Open(k, n, a, (nuint)aad.Length, c, (nuint)ciphertext.Length, t, p);
        }

        return (result, plaintext);
    }

    /// <summary>
    /// ChaCha20 as RFC 8439 2.3 and 2.4 define it, one block at a time in plain C#: the
    /// reference for the raw cipher's random tests. The counter wraps modulo 2^32.
    /// </summary>
    /// <param name="key">32 octets.</param>
    /// <param name="counter">The first block's counter.</param>
    /// <param name="nonce">12 octets.</param>
    /// <param name="input">The octets to xor with the keystream.</param>
    /// <returns>The result.</returns>
    private static byte[] ChaCha20Reference(byte[] key, uint counter, byte[] nonce, byte[] input)
    {
        byte[] output = new byte[input.Length];
        uint[] state = new uint[16], x = new uint[16];
        byte[] block = new byte[64];
        for (int offset = 0; offset < input.Length; offset += 64, counter++)
        {
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;
            for (int w = 0; w < 8; w++)
            {
                state[4 + w] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(4 * w));
            }

            state[12] = counter;
            for (int w = 0; w < 3; w++)
            {
                state[13 + w] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(4 * w));
            }

            state.CopyTo(x, 0);
            for (int round = 0; round < 10; round++)
            {
                QuarterRound(x, 0, 4, 8, 12);
                QuarterRound(x, 1, 5, 9, 13);
                QuarterRound(x, 2, 6, 10, 14);
                QuarterRound(x, 3, 7, 11, 15);
                QuarterRound(x, 0, 5, 10, 15);
                QuarterRound(x, 1, 6, 11, 12);
                QuarterRound(x, 2, 7, 8, 13);
                QuarterRound(x, 3, 4, 9, 14);
            }

            for (int w = 0; w < 16; w++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(4 * w), x[w] + state[w]);
            }

            for (int i = 0; i < 64 && offset + i < input.Length; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ block[i]);
            }
        }

        return output;
    }

    /// <summary>RFC 8439 2.1's quarter round on four words of the state.</summary>
    /// <param name="x">The working state.</param>
    /// <param name="a">The first word's index.</param>
    /// <param name="b">The second's.</param>
    /// <param name="c">The third's.</param>
    /// <param name="d">The fourth's.</param>
    private static void QuarterRound(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }

    /// <summary>
    /// Poly1305 as RFC 8439 2.5.1 defines it, with BigInteger: r clamped, each 16-octet piece
    /// (the last one shorter) read little-endian with a 1 octet past it, h = (h + piece) r mod
    /// 2^130 - 5, the tag (h + s) mod 2^128.
    /// </summary>
    /// <param name="key">32 octets: r, then s.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 16-octet tag.</returns>
    private static byte[] Poly1305Reference(byte[] key, byte[] message)
    {
        byte[] rOctets = key[..16];
        rOctets[3] &= 15;
        rOctets[7] &= 15;
        rOctets[11] &= 15;
        rOctets[15] &= 15;
        rOctets[4] &= 252;
        rOctets[8] &= 252;
        rOctets[12] &= 252;
        var r = new BigInteger(rOctets, isUnsigned: true);
        var s = new BigInteger(key.AsSpan(16, 16), isUnsigned: true);
        BigInteger h = BigInteger.Zero;
        for (int i = 0; i < message.Length; i += 16)
        {
            int n = Math.Min(16, message.Length - i);
            byte[] piece = new byte[n + 1];
            message.AsSpan(i, n).CopyTo(piece);
            piece[n] = 1;
            h = (h + new BigInteger(piece, isUnsigned: true)) * r % Prime;
        }

        BigInteger tag = (h + s) & ((BigInteger.One << 128) - 1);
        byte[] result = new byte[16];
        Assert.True(tag.TryWriteBytes(result, out _, isUnsigned: true));
        return result;
    }

    /// <summary>One test vector of RFC 8439: its hex dumps by label, and its numbers.</summary>
    /// <param name="Octets">Each label's octets (labels in lower case, without their colons).</param>
    /// <param name="Numbers">The "Block Counter = n" lines, as "block counter".</param>
    private sealed record RfcVector(Dictionary<string, byte[]> Octets, Dictionary<string, long> Numbers);

    /// <summary>
    /// The test vectors of one part of the pinned RFC 8439 text (specs/rfc/rfc8439.txt), from
    /// the line that starts with <paramref name="from"/> to the one that starts with
    /// <paramref name="to"/> (headings start at the margin; the contents' entries are indented,
    /// so they never match). A "Test Vector #n" line starts each vector; a part without them is
    /// one vector. Every other line that is not data names what follows it (a label), and the
    /// data lines under a label, in any of the RFC's three forms (offset rows "000  76 b8 ...",
    /// bare uppercase rows "FF FF ...", colon-separated octets "1a:e1:..."), are its octets. The
    /// page breaks inside a dump (the footer and header lines) are skipped.
    /// </summary>
    /// <param name="from">The part's heading, as the line starts.</param>
    /// <param name="to">The next part's heading.</param>
    /// <returns>The vectors, in order.</returns>
    /// <exception cref="InvalidDataException">The part was not found in the file.</exception>
    private static List<RfcVector> RfcVectors(string from, string to)
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc8439.txt"));
        int start = Array.FindIndex(lines, l => l.StartsWith(from, StringComparison.Ordinal));
        int end = Array.FindIndex(lines, Math.Max(start, 0) + 1, l => l.StartsWith(to, StringComparison.Ordinal));
        if (start < 0 || end < 0)
        {
            throw new InvalidDataException($"RFC 8439's part '{from.Trim()}' was not found in the pinned text");
        }

        var vectors = new List<RfcVector>();
        Dictionary<string, List<byte>>? dumps = null;            // the vector being read
        Dictionary<string, long>? numbers = null;
        List<byte>? octets = null;                                // the open label's octets

        // The vector read so far, frozen into the list (its octets as arrays). Prose before a
        // part's first "Test Vector" line reads as labels without octets: not a vector.
        void Finish()
        {
            if (dumps is not null && dumps.Values.Any(o => o.Count > 0))
            {
                vectors.Add(new RfcVector(dumps.ToDictionary(p => p.Key, p => p.Value.ToArray()), numbers!));
            }
        }

        foreach (string line in lines[(start + 1)..end])
        {
            if (line.Trim().Length == 0 || line.StartsWith("Nir & Langley", StringComparison.Ordinal) || line.StartsWith("RFC 8439 ", StringComparison.Ordinal))
            {
                continue;                                           // blank, or a page break
            }

            bool vectorStarts = line.TrimStart().StartsWith("Test Vector #", StringComparison.Ordinal);
            if (vectorStarts || dumps is null)
            {
                Finish();
                dumps = [];
                numbers = [];
                octets = null;
                if (vectorStarts)
                {
                    continue;
                }
            }

            Match match;
            if ((match = OffsetRow().Match(line)).Success || (match = BareRow().Match(line)).Success || (match = ColonRow().Match(line)).Success)
            {
                octets?.AddRange(Convert.FromHexString(match.Groups[1].Value.Replace(" ", "").Replace(":", "")));
            }
            else if ((match = CounterRow().Match(line)).Success)
            {
                numbers!["block counter"] = long.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
            }
            else if ((match = InlineColonRow().Match(line)).Success)
            {
                dumps[match.Groups[1].Value.Trim().ToLowerInvariant()] = [.. Convert.FromHexString(match.Groups[2].Value.Replace(":", ""))];
                octets = null;
            }
            else
            {
                // A label (or prose, which no data follows): the next data lines are its octets.
                // A label met again starts over (each part names its values once).
                octets = [];
                dumps[line.Trim().TrimEnd(':').ToLowerInvariant()] = octets;
            }
        }

        Finish();
        return vectors;
    }

    /// <summary>An offset row of a hex dump: "000  76 b8 e0 ...  v..." (the octets, not the text column).</summary>
    /// <returns>The pattern; group 1 holds the octets.</returns>
    [GeneratedRegex(@"^\s*\d{3}  ((?:[0-9a-f]{2} )*[0-9a-f]{2})")]
    private static partial Regex OffsetRow();

    /// <summary>A bare row of uppercase octets, as A.3's later vectors write them: "FF FF ... FF".</summary>
    /// <returns>The pattern; group 1 holds the octets.</returns>
    [GeneratedRegex(@"^\s*((?:[0-9A-F]{2} )*[0-9A-F]{2})\s*$")]
    private static partial Regex BareRow();

    /// <summary>A row of colon-separated octets, as 2.8.2's tag is written: "1a:e1:0b:...".</summary>
    /// <returns>The pattern; group 1 holds the octets.</returns>
    [GeneratedRegex(@"^\s*((?:[0-9a-f]{2}:)+[0-9a-f]{2}):?\s*$")]
    private static partial Regex ColonRow();

    /// <summary>A label with its colon-separated octets on the same line: "Tag: a8:06:...".</summary>
    /// <returns>The pattern; group 1 holds the label, group 2 the octets.</returns>
    [GeneratedRegex(@"^\s*([A-Za-z][^:]*):\s+((?:[0-9a-f]{2}:)+[0-9a-f]{2})\s*$")]
    private static partial Regex InlineColonRow();

    /// <summary>A vector's block counter: "Block Counter = 1" or "Initial Block Counter = 42".</summary>
    /// <returns>The pattern; group 1 holds the number.</returns>
    [GeneratedRegex(@"^\s*(?:Initial )?Block Counter = (\d+)\s*$")]
    private static partial Regex CounterRow();
}
