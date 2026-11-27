using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_mlkem512_*, httpasm_mlkem768_* and httpasm_mlkem1024_* (ML-KEM, FIPS 203) through the C
/// ABI, held to Project Wycheproof's ML-KEM files (key generation from seeds; encapsulation with
/// C2SP CCTV's modulus-overflow keys; decapsulation from seeds, with implicit rejection, CCTV's
/// strcmp case and malleable ciphertexts; decapsulation from expanded keys with wrong hashes), and
/// to a model of FIPS 203 written here in C# (a second implementation: plain integers, .NET's
/// SHA3_256, SHA3_512, Shake128 and Shake256) on random seeds and messages, corrupted ciphertexts
/// and invalid keys at every place. tests/run-linux.sh runs the suite at every CPU tier.
/// </summary>
public sealed unsafe class MlKemTests
{
    /// <summary>The three parameter sets of FIPS 203 (Table 2).</summary>
    public enum ParameterSet
    {
        /// <summary>ML-KEM-512: k = 2, eta1 = 3, du = 10, dv = 4.</summary>
        MlKem512 = 512,

        /// <summary>ML-KEM-768: k = 3, eta1 = 2, du = 10, dv = 4 (X25519MLKEM768's).</summary>
        MlKem768 = 768,

        /// <summary>ML-KEM-1024: k = 4, eta1 = 2, du = 11, dv = 5 (SecP384r1MLKEM1024's).</summary>
        MlKem1024 = 1024,
    }

    /// <summary>
    /// Wycheproof's key generation tests (100 a set, FIPS 203's own vectors): the seed's ek and dk,
    /// octet for octet.
    /// </summary>
    /// <param name="set">The parameter set.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512)]
    [InlineData(ParameterSet.MlKem768)]
    [InlineData(ParameterSet.MlKem1024)]
    public void PassesWycheproofsKeyGenerationTests(ParameterSet set)
    {
        Platform.RequireLinuxX64();
        int count = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path($"wycheproof/mlkem_{(int)set}_keygen_seed_test.json")))
        {
            Assert.Equal("valid", test.GetProperty("result").GetString());
            (byte[] ek, byte[] dk) = Keypair(set, Hex(test, "seed"));
            Assert.Equal(test.GetProperty("ek").GetString(), Convert.ToHexStringLower(ek));
            Assert.Equal(test.GetProperty("dk").GetString(), Convert.ToHexStringLower(dk));
            count++;
        }

        Assert.Equal(100, count);
    }

    /// <summary>
    /// Wycheproof's encapsulation tests: every valid one's ciphertext and key exactly (133 a set);
    /// every key with a coefficient of q or more (FIPS 203's invalid keys and CCTV's 12 modulus
    /// overflows: 108, 112 and 116) refused, -1 with both outputs zeroed; the 20 of wrong lengths
    /// (which the C types cannot carry) never marked valid.
    /// </summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="tests">The file's test count.</param>
    /// <param name="refused">How many keys the modulus check must refuse.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512, 261, 108)]
    [InlineData(ParameterSet.MlKem768, 265, 112)]
    [InlineData(ParameterSet.MlKem1024, 269, 116)]
    public void PassesWycheproofsEncapsulationTests(ParameterSet set, int tests, int refused)
    {
        Platform.RequireLinuxX64();
        (int ekLength, _, int ctLength) = Sizes(set);
        int count = 0, valid = 0, modulus = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path($"wycheproof/mlkem_{(int)set}_encaps_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] ek = Hex(test, "ek"), m = Hex(test, "m");
            count++;
            if (ek.Length != ekLength || m.Length != 32)
            {
                Assert.True(expected == "invalid", id);
                continue;
            }

            (int result, byte[] c, byte[] shared) = Encaps(set, ek, m);
            if (expected == "valid")
            {
                Assert.True(result == 0, id);
                Assert.Equal(test.GetProperty("c").GetString(), Convert.ToHexStringLower(c));
                Assert.Equal(test.GetProperty("K").GetString(), Convert.ToHexStringLower(shared));
                valid++;
            }
            else
            {
                Assert.True(result == -1 && c.All(o => o == 0) && shared.All(o => o == 0), id);
                Assert.Equal(ctLength, c.Length);
                modulus++;
            }
        }

        Assert.Equal(tests, count);
        Assert.Equal(refused, modulus);
        Assert.Equal(133, valid);
    }

    /// <summary>
    /// Wycheproof's decapsulation tests from seeds: the seed's key pair (its ek where the test
    /// gives one), then the given ciphertext's key exactly: the encapsulated key for a valid
    /// ciphertext, J(z || c) for a modified one (implicit rejection: no error); seeds and
    /// ciphertexts of wrong lengths never marked valid.
    /// </summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="tests">The file's test count.</param>
    /// <param name="decapsulations">How many of them decapsulate (the rest have wrong lengths).</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512, 200, 160)]
    [InlineData(ParameterSet.MlKem768, 201, 161)]
    [InlineData(ParameterSet.MlKem1024, 202, 162)]
    public void PassesWycheproofsDecapsulationTests(ParameterSet set, int tests, int decapsulations)
    {
        Platform.RequireLinuxX64();
        (_, _, int ctLength) = Sizes(set);
        int count = 0, decapsulated = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path($"wycheproof/mlkem_{(int)set}_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}";
            byte[] seed = Hex(test, "seed"), c = Hex(test, "c");
            count++;
            if (seed.Length != 64 || c.Length != ctLength)
            {
                Assert.True(test.GetProperty("result").GetString() == "invalid", id);
                continue;
            }

            (byte[] ek, byte[] dk) = Keypair(set, seed);
            if (test.TryGetProperty("ek", out System.Text.Json.JsonElement expectedEk))
            {
                Assert.Equal(expectedEk.GetString(), Convert.ToHexStringLower(ek));
            }

            (int result, byte[] shared) = Decaps(set, dk, c);
            Assert.True(result == 0, id);
            Assert.Equal("valid", test.GetProperty("result").GetString());
            Assert.Equal(test.GetProperty("K").GetString(), Convert.ToHexStringLower(shared));
            decapsulated++;
        }

        Assert.Equal(tests, count);
        Assert.Equal(decapsulations, decapsulated);
    }

    /// <summary>
    /// Wycheproof's decapsulation tests from expanded keys (aws-lc's, reenc's): the valid ones'
    /// keys exactly, a key whose stored H(ek) does not match refused (-1, the output zeroed), and
    /// wrong lengths never marked valid.
    /// </summary>
    /// <param name="set">The parameter set.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512)]
    [InlineData(ParameterSet.MlKem768)]
    [InlineData(ParameterSet.MlKem1024)]
    public void PassesWycheproofsExpandedKeyTests(ParameterSet set)
    {
        Platform.RequireLinuxX64();
        (_, int dkLength, int ctLength) = Sizes(set);
        int count = 0, hashRefused = 0;
        foreach ((System.Text.Json.JsonElement _, System.Text.Json.JsonElement test) in Vectors.WycheproofTests(Vectors.Path($"wycheproof/mlkem_{(int)set}_semi_expanded_decaps_test.json")))
        {
            string id = $"tcId {test.GetProperty("tcId").GetInt32()}";
            string expected = test.GetProperty("result").GetString()!;
            byte[] dk = Hex(test, "dk"), c = Hex(test, "c");
            count++;
            if (dk.Length != dkLength || c.Length != ctLength)
            {
                Assert.True(expected == "invalid", id);
                continue;
            }

            (int result, byte[] shared) = Decaps(set, dk, c);
            if (expected == "valid")
            {
                Assert.True(result == 0, id);
                Assert.Equal(test.GetProperty("K").GetString(), Convert.ToHexStringLower(shared));
            }
            else
            {
                Assert.True(result == -1 && shared.All(o => o == 0), id);
                hashRefused++;
            }
        }

        Assert.Equal(9, count);
        Assert.Equal(2, hashRefused);
    }

    /// <summary>
    /// Against the C# model on 40 random seeds and messages a set (the first seeds all zeros and all
    /// ones): ek and dk, the ciphertext and key, the decapsulated key; then each ciphertext with
    /// one bit flipped (a different place each time) decapsulates to the model's J(z || c), which
    /// differs from the real key; and a ciphertext of random octets likewise.
    /// </summary>
    /// <param name="set">The parameter set.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512)]
    [InlineData(ParameterSet.MlKem768)]
    [InlineData(ParameterSet.MlKem1024)]
    public void MatchesTheModel(ParameterSet set)
    {
        Platform.RequireLinuxX64();
        var random = new Random((int)set);
        for (int i = 0; i < 40; i++)
        {
            byte[] seed = i switch
            {
                0 => new byte[64],
                1 => Enumerable.Repeat((byte)0xFF, 64).ToArray(),
                _ => RandomBytes(random, 64),
            };
            byte[] m = RandomBytes(random, 32);
            (byte[] ek, byte[] dk) = Keypair(set, seed);
            (byte[] modelEk, byte[] modelDk) = Model.KeyGen(set, seed);
            Assert.Equal(Convert.ToHexString(modelEk), Convert.ToHexString(ek));
            Assert.Equal(Convert.ToHexString(modelDk), Convert.ToHexString(dk));
            (int result, byte[] c, byte[] shared) = Encaps(set, ek, m);
            (byte[] modelC, byte[] modelShared) = Model.Encaps(set, ek, m);
            Assert.Equal(0, result);
            Assert.Equal(Convert.ToHexString(modelC), Convert.ToHexString(c));
            Assert.Equal(Convert.ToHexString(modelShared), Convert.ToHexString(shared));
            Assert.Equal(Convert.ToHexString(shared), Convert.ToHexString(Decaps(set, dk, c).Shared));

            byte[] flipped = (byte[])c.Clone();
            flipped[random.Next(c.Length)] ^= (byte)(1 << random.Next(8));
            (int rejected, byte[] other) = Decaps(set, dk, flipped);
            Assert.Equal(0, rejected);
            Assert.Equal(Convert.ToHexString(Model.Decaps(set, dk, flipped)), Convert.ToHexString(other));
            Assert.NotEqual(Convert.ToHexString(shared), Convert.ToHexString(other));
            byte[] noise = RandomBytes(random, c.Length);
            Assert.Equal(Convert.ToHexString(Model.Decaps(set, dk, noise)), Convert.ToHexString(Decaps(set, dk, noise).Shared));
        }
    }

    /// <summary>
    /// FIPS 203 7.2's modulus check at every kind of place: in a valid ek, one 12-bit coefficient set
    /// to q, q + 1 and 4095 (in the low and the high half of its three octets, in the first, a middle
    /// and the last polynomial, at the first and the last pair) - each refused with -1 and both outputs
    /// zeroed - and to q - 1, accepted, as the model computes it. rho's octets (past the polynomials)
    /// are never checked: changing them is accepted.
    /// </summary>
    /// <param name="set">The parameter set.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512)]
    [InlineData(ParameterSet.MlKem768)]
    [InlineData(ParameterSet.MlKem1024)]
    public void RefusesEncapsulationKeysWithACoefficientOfQOrMore(ParameterSet set)
    {
        Platform.RequireLinuxX64();
        var random = new Random(7_2);
        int k = Parameters(set).K;
        (byte[] ek, _) = Keypair(set, RandomBytes(random, 64));
        byte[] m = RandomBytes(random, 32);
        foreach (int polynomial in new[] { 0, k / 2, k - 1 })
        {
            foreach (int pair in new[] { 0, 1, 64, 127 })
            {
                foreach (bool high in new[] { false, true })
                {
                    foreach (int value in new[] { 3329, 3330, 4095, 3328 })
                    {
                        byte[] changed = SetCoefficient(ek, 384 * polynomial + 3 * pair, high, value);
                        (int result, byte[] c, byte[] shared) = Encaps(set, changed, m);
                        if (value >= 3329)
                        {
                            Assert.True(result == -1 && c.All(o => o == 0) && shared.All(o => o == 0), $"poly {polynomial} pair {pair} {high} {value}");
                        }
                        else
                        {
                            Assert.Equal(0, result);
                            Assert.Equal(Convert.ToHexString(Model.Encaps(set, changed, m).C), Convert.ToHexString(c));
                        }
                    }
                }
            }
        }

        byte[] otherRho = (byte[])ek.Clone();
        otherRho[^1] ^= 0x80;
        Assert.Equal(0, Encaps(set, otherRho, m).Result);
    }

    /// <summary>
    /// FIPS 203 7.3's hash check: a decapsulation key whose ek part or stored H(ek) differs by one bit
    /// is refused (-1, the key zeroed); one whose secret part differs is not checkable and still
    /// decapsulates (to a different key: implicit rejection, as the model says).
    /// </summary>
    /// <param name="set">The parameter set.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512)]
    [InlineData(ParameterSet.MlKem768)]
    [InlineData(ParameterSet.MlKem1024)]
    public void RefusesDecapsulationKeysWhoseHashDiffers(ParameterSet set)
    {
        Platform.RequireLinuxX64();
        var random = new Random(7_3);
        int k = Parameters(set).K;
        (byte[] ek, byte[] dk) = Keypair(set, RandomBytes(random, 64));
        (_, byte[] c, byte[] shared) = Encaps(set, ek, RandomBytes(random, 32));
        foreach (int at in new[] { 384 * k, 384 * k + ek.Length - 1, 768 * k + 32, 768 * k + 63 })
        {
            byte[] changed = (byte[])dk.Clone();
            changed[at] ^= 0x04;
            (int result, byte[] key) = Decaps(set, changed, c);
            Assert.True(result == -1 && key.All(o => o == 0), $"octet {at}");
        }

        byte[] secret = (byte[])dk.Clone();
        secret[5] ^= 0x01;
        (int accepted, byte[] other) = Decaps(set, secret, c);
        Assert.Equal(0, accepted);
        Assert.Equal(Convert.ToHexString(Model.Decaps(set, secret, c)), Convert.ToHexString(other));
        Assert.NotEqual(Convert.ToHexString(shared), Convert.ToHexString(other));
    }

    /// <summary>
    /// Every output stays inside its length (canaries after ek, dk, c and the shared secrets), and
    /// the same inputs give the same outputs (no hidden randomness).
    /// </summary>
    /// <param name="set">The parameter set.</param>
    [Theory]
    [InlineData(ParameterSet.MlKem512)]
    [InlineData(ParameterSet.MlKem768)]
    [InlineData(ParameterSet.MlKem1024)]
    public void WritesOnlyItsOutputs(ParameterSet set)
    {
        Platform.RequireLinuxX64();
        (int ekLength, int dkLength, int ctLength) = Sizes(set);
        byte[] seed = RandomBytes(new Random(64), 64), m = RandomBytes(new Random(32), 32);
        byte[] ek = new byte[ekLength + 32], dk = new byte[dkLength + 32], c = new byte[ctLength + 32];
        byte[] shared = new byte[64], decapsulated = new byte[64];
        foreach (byte[] buffer in new[] { ek, dk, c, shared, decapsulated })
        {
            buffer.AsSpan().Fill(0xA5);
        }

        fixed (byte* e = ek, d = dk, s = seed, cc = c, k = shared, k2 = decapsulated, mm = m)
        {
            CallKeypair(set, e, d, s);
            Assert.Equal(0, CallEncaps(set, cc, k, e, mm));
            Assert.Equal(0, CallDecaps(set, k2, d, cc));
        }

        Assert.True(ek[ekLength..].All(o => o == 0xA5) && dk[dkLength..].All(o => o == 0xA5) && c[ctLength..].All(o => o == 0xA5));
        Assert.True(shared[32..].All(o => o == 0xA5) && decapsulated[32..].All(o => o == 0xA5));
        Assert.Equal(shared[..32], decapsulated[..32]);
        Assert.Equal(ek[..ekLength], Keypair(set, seed).Ek);
        Assert.Equal(c[..ctLength], Encaps(set, ek[..ekLength], m).C);
    }

    /// <summary>A parameter set's numbers.</summary>
    /// <param name="set">The set.</param>
    /// <returns>k, eta1, du, dv.</returns>
    private static (int K, int Eta1, int Du, int Dv) Parameters(ParameterSet set) => set switch
    {
        ParameterSet.MlKem512 => (2, 3, 10, 4),
        ParameterSet.MlKem768 => (3, 2, 10, 4),
        _ => (4, 2, 11, 5),
    };

    /// <summary>A parameter set's encapsulation key, decapsulation key and ciphertext lengths.</summary>
    /// <param name="set">The set.</param>
    /// <returns>The three lengths in octets.</returns>
    private static (int Ek, int Dk, int Ct) Sizes(ParameterSet set)
    {
        (int k, _, int du, int dv) = Parameters(set);
        return (384 * k + 32, 768 * k + 96, 32 * (du * k + dv));
    }

    /// <summary>The library's key generation.</summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="seed">d || z, 64 octets.</param>
    /// <returns>ek and dk.</returns>
    private static (byte[] Ek, byte[] Dk) Keypair(ParameterSet set, byte[] seed)
    {
        (int ekLength, int dkLength, _) = Sizes(set);
        byte[] ek = new byte[ekLength], dk = new byte[dkLength];
        fixed (byte* e = ek, d = dk, s = seed)
        {
            CallKeypair(set, e, d, s);
        }

        return (ek, dk);
    }

    /// <summary>The library's encapsulation (outputs pre-filled with 0xEE).</summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="ek">The encapsulation key.</param>
    /// <param name="m">32 octets.</param>
    /// <returns>The result, the ciphertext and the shared secret.</returns>
    private static (int Result, byte[] C, byte[] Shared) Encaps(ParameterSet set, byte[] ek, byte[] m)
    {
        byte[] c = new byte[Sizes(set).Ct], shared = new byte[32];
        c.AsSpan().Fill(0xEE);
        shared.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* cc = c, k = shared, e = ek, mm = m)
        {
            result = CallEncaps(set, cc, k, e, mm);
        }

        return (result, c, shared);
    }

    /// <summary>The library's decapsulation (the output pre-filled with 0xEE).</summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="dk">The decapsulation key.</param>
    /// <param name="c">The ciphertext.</param>
    /// <returns>The result and the shared secret.</returns>
    private static (int Result, byte[] Shared) Decaps(ParameterSet set, byte[] dk, byte[] c)
    {
        byte[] shared = new byte[32];
        shared.AsSpan().Fill(0xEE);
        int result;
        fixed (byte* k = shared, d = dk, cc = c)
        {
            result = CallDecaps(set, k, d, cc);
        }

        return (result, shared);
    }

    /// <summary>The set's keypair function.</summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="ek">ek's destination.</param>
    /// <param name="dk">dk's destination.</param>
    /// <param name="seed">The seed.</param>
    private static void CallKeypair(ParameterSet set, byte* ek, byte* dk, byte* seed)
    {
        switch (set)
        {
            case ParameterSet.MlKem512: Native.MlKem512Keypair(ek, dk, seed); break;
            case ParameterSet.MlKem768: Native.MlKem768Keypair(ek, dk, seed); break;
            default: Native.MlKem1024Keypair(ek, dk, seed); break;
        }
    }

    /// <summary>The set's encapsulation function.</summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="c">The ciphertext's destination.</param>
    /// <param name="shared">The shared secret's.</param>
    /// <param name="ek">The encapsulation key.</param>
    /// <param name="m">32 octets.</param>
    /// <returns>0 or -1.</returns>
    private static int CallEncaps(ParameterSet set, byte* c, byte* shared, byte* ek, byte* m) => set switch
    {
        ParameterSet.MlKem512 => Native.MlKem512Encaps(c, shared, ek, m),
        ParameterSet.MlKem768 => Native.MlKem768Encaps(c, shared, ek, m),
        _ => Native.MlKem1024Encaps(c, shared, ek, m),
    };

    /// <summary>The set's decapsulation function.</summary>
    /// <param name="set">The parameter set.</param>
    /// <param name="shared">The shared secret's destination.</param>
    /// <param name="dk">The decapsulation key.</param>
    /// <param name="c">The ciphertext.</param>
    /// <returns>0 or -1.</returns>
    private static int CallDecaps(ParameterSet set, byte* shared, byte* dk, byte* c) => set switch
    {
        ParameterSet.MlKem512 => Native.MlKem512Decaps(shared, dk, c),
        ParameterSet.MlKem768 => Native.MlKem768Decaps(shared, dk, c),
        _ => Native.MlKem1024Decaps(shared, dk, c),
    };

    /// <summary>A test's hex field as octets.</summary>
    /// <param name="test">The Wycheproof test.</param>
    /// <param name="name">The field.</param>
    /// <returns>The octets.</returns>
    private static byte[] Hex(System.Text.Json.JsonElement test, string name) => Convert.FromHexString(test.GetProperty(name).GetString()!);

    /// <summary>Random octets from a seeded source.</summary>
    /// <param name="random">The source.</param>
    /// <param name="count">How many.</param>
    /// <returns>The octets.</returns>
    private static byte[] RandomBytes(Random random, int count)
    {
        byte[] octets = new byte[count];
        random.NextBytes(octets);
        return octets;
    }

    /// <summary>A copy of ek with one 12-bit value of a pair replaced (its three octets at at).</summary>
    /// <param name="ek">The key.</param>
    /// <param name="at">The pair's first octet.</param>
    /// <param name="high">The pair's second value (else its first).</param>
    /// <param name="value">The new 12-bit value.</param>
    /// <returns>The changed copy.</returns>
    private static byte[] SetCoefficient(byte[] ek, int at, bool high, int value)
    {
        byte[] changed = (byte[])ek.Clone();
        int pair = changed[at] | (changed[at + 1] << 8) | (changed[at + 2] << 16);
        pair = high ? (pair & 0xFFF) | (value << 12) : (pair & 0xFFF000) | value;
        changed[at] = (byte)pair;
        changed[at + 1] = (byte)(pair >> 8);
        changed[at + 2] = (byte)(pair >> 16);
        return changed;
    }

    /// <summary>
    /// FIPS 203 in C#, algorithm by algorithm, with plain integers modulo q (no Montgomery form, no
    /// lazy reduction: a second implementation, independent of the assembly's arithmetic).
    /// </summary>
    private static class Model
    {
        /// <summary>The modulus.</summary>
        private const int Q = 3329;

        /// <summary>zeta^BitRev7(i) mod q (NTT, NTT^-1).</summary>
        private static readonly int[] Zetas = Enumerable.Range(0, 128).Select(i => Power(17, BitReverse7(i))).ToArray();

        /// <summary>zeta^(2 BitRev7(i) + 1) mod q (the base-case products).</summary>
        private static readonly int[] Gammas = Enumerable.Range(0, 128).Select(i => Power(17, 2 * BitReverse7(i) + 1)).ToArray();

        /// <summary>ML-KEM.KeyGen_internal (Algorithm 16) and K-PKE.KeyGen (Algorithm 13).</summary>
        /// <param name="set">The parameter set.</param>
        /// <param name="seed">d || z.</param>
        /// <returns>ek and dk.</returns>
        public static (byte[] Ek, byte[] Dk) KeyGen(ParameterSet set, byte[] seed)
        {
            (int k, int eta1, _, _) = Parameters(set);
            byte[] g = SHA3_512.HashData([.. seed.AsSpan(0, 32), (byte)k]);
            byte[] rho = g[..32], sigma = g[32..];
            int[][] s = Enumerable.Range(0, k).Select(i => Ntt(Cbd(Prf(sigma, i, eta1), eta1))).ToArray();
            int[][] e = Enumerable.Range(0, k).Select(i => Ntt(Cbd(Prf(sigma, k + i, eta1), eta1))).ToArray();
            var ek = new List<byte>();
            for (int i = 0; i < k; i++)
            {
                int[] t = e[i];
                for (int j = 0; j < k; j++)
                {
                    t = Add(t, MultiplyNtts(SampleNtt(rho, j, i), s[j]));
                }

                ek.AddRange(Encode(t, 12));
            }

            ek.AddRange(rho);
            byte[] ekBytes = [.. ek];
            byte[] dk = [.. s.SelectMany(x => Encode(x, 12)), .. ekBytes, .. SHA3_256.HashData(ekBytes), .. seed.AsSpan(32, 32)];
            return (ekBytes, dk);
        }

        /// <summary>ML-KEM.Encaps_internal (Algorithm 17), its key valid.</summary>
        /// <param name="set">The parameter set.</param>
        /// <param name="ek">The encapsulation key.</param>
        /// <param name="m">32 octets.</param>
        /// <returns>The ciphertext and the shared secret.</returns>
        public static (byte[] C, byte[] Shared) Encaps(ParameterSet set, byte[] ek, byte[] m)
        {
            byte[] g = SHA3_512.HashData([.. m, .. SHA3_256.HashData(ek)]);
            return (Encrypt(set, ek, m, g[32..]), g[..32]);
        }

        /// <summary>ML-KEM.Decaps_internal (Algorithm 18), its key's hash valid.</summary>
        /// <param name="set">The parameter set.</param>
        /// <param name="dk">The decapsulation key.</param>
        /// <param name="c">The ciphertext.</param>
        /// <returns>The shared secret (J(z || c) when c is not dk's encryption of what it decrypts to).</returns>
        public static byte[] Decaps(ParameterSet set, byte[] dk, byte[] c)
        {
            (int k, _, int du, int dv) = Parameters(set);
            byte[] ek = dk[(384 * k)..(768 * k + 32)], h = dk[(768 * k + 32)..(768 * k + 64)], z = dk[(768 * k + 64)..];
            int[] w = Decompress(Decode(c[(32 * du * k)..], dv), dv);
            int[] products = new int[256];
            for (int i = 0; i < k; i++)
            {
                int[] u = Ntt(Decompress(Decode(c[(32 * du * i)..(32 * du * (i + 1))], du), du));
                products = Add(products, MultiplyNtts(Decode(dk[(384 * i)..(384 * (i + 1))], 12), u));
            }

            byte[] m = Encode(Compress(Subtract(w, InverseNtt(products)), 1), 1);
            byte[] g = SHA3_512.HashData([.. m, .. h]);
            byte[] reencrypted = Encrypt(set, ek, m, g[32..]);
            return reencrypted.AsSpan().SequenceEqual(c) ? g[..32] : Shake256.HashData([.. z, .. c], 32);
        }

        /// <summary>K-PKE.Encrypt (Algorithm 14).</summary>
        /// <param name="set">The parameter set.</param>
        /// <param name="ek">The encapsulation key.</param>
        /// <param name="m">32 octets.</param>
        /// <param name="r">The randomness.</param>
        /// <returns>The ciphertext.</returns>
        private static byte[] Encrypt(ParameterSet set, byte[] ek, byte[] m, byte[] r)
        {
            (int k, int eta1, int du, int dv) = Parameters(set);
            byte[] rho = ek[(384 * k)..];
            int[][] t = Enumerable.Range(0, k).Select(i => Decode(ek[(384 * i)..(384 * (i + 1))], 12)).ToArray();
            int[][] y = Enumerable.Range(0, k).Select(i => Ntt(Cbd(Prf(r, i, eta1), eta1))).ToArray();
            var c = new List<byte>();
            for (int i = 0; i < k; i++)
            {
                int[] sum = new int[256];
                for (int j = 0; j < k; j++)
                {
                    sum = Add(sum, MultiplyNtts(SampleNtt(rho, i, j), y[j]));
                }

                c.AddRange(Encode(Compress(Add(InverseNtt(sum), Cbd(Prf(r, k + i, 2), 2)), du), du));
            }

            int[] v = new int[256];
            for (int j = 0; j < k; j++)
            {
                v = Add(v, MultiplyNtts(t[j], y[j]));
            }

            v = Add(Add(InverseNtt(v), Cbd(Prf(r, 2 * k, 2), 2)), Decompress(Decode(m, 1), 1));
            c.AddRange(Encode(Compress(v, dv), dv));
            return [.. c];
        }

        /// <summary>SampleNTT (Algorithm 7) of rho || j || i: SHAKE128's stream read three octets at a time.</summary>
        /// <param name="rho">32 octets.</param>
        /// <param name="j">The first index octet.</param>
        /// <param name="i">The second.</param>
        /// <returns>The polynomial (coefficients below q).</returns>
        private static int[] SampleNtt(byte[] rho, int j, int i)
        {
            byte[] input = [.. rho, (byte)j, (byte)i];
            for (int length = 168 * 8; ; length *= 2)
            {
                byte[] stream = Shake128.HashData(input, length);
                var a = new List<int>(256);
                for (int at = 0; at + 3 <= stream.Length && a.Count < 256; at += 3)
                {
                    int d1 = stream[at] | ((stream[at + 1] & 15) << 8);
                    int d2 = (stream[at + 1] >> 4) | (stream[at + 2] << 4);
                    if (d1 < Q)
                    {
                        a.Add(d1);
                    }

                    if (d2 < Q && a.Count < 256)
                    {
                        a.Add(d2);
                    }
                }

                if (a.Count == 256)
                {
                    return [.. a];
                }
            }
        }

        /// <summary>PRF_eta(s, b) = SHAKE256(s || b), 64 eta octets.</summary>
        /// <param name="s">32 octets.</param>
        /// <param name="b">The nonce.</param>
        /// <param name="eta">2 or 3.</param>
        /// <returns>The octets.</returns>
        private static byte[] Prf(byte[] s, int b, int eta) => Shake256.HashData([.. s, (byte)b], 64 * eta);

        /// <summary>SamplePolyCBD_eta (Algorithm 8).</summary>
        /// <param name="b">64 eta octets.</param>
        /// <param name="eta">2 or 3.</param>
        /// <returns>The polynomial (coefficients mod q).</returns>
        private static int[] Cbd(byte[] b, int eta)
        {
            int Bit(int n) => (b[n / 8] >> (n % 8)) & 1;
            int[] f = new int[256];
            for (int i = 0; i < 256; i++)
            {
                int x = 0, y = 0;
                for (int j = 0; j < eta; j++)
                {
                    x += Bit(2 * i * eta + j);
                    y += Bit(2 * i * eta + eta + j);
                }

                f[i] = Mod(x - y);
            }

            return f;
        }

        /// <summary>NTT (Algorithm 9).</summary>
        /// <param name="input">The polynomial.</param>
        /// <returns>Its NTT.</returns>
        private static int[] Ntt(int[] input)
        {
            int[] f = (int[])input.Clone();
            int i = 1;
            for (int length = 128; length >= 2; length /= 2)
            {
                for (int start = 0; start < 256; start += 2 * length)
                {
                    int zeta = Zetas[i++];
                    for (int j = start; j < start + length; j++)
                    {
                        int t = zeta * f[j + length] % Q;
                        f[j + length] = Mod(f[j] - t);
                        f[j] = (f[j] + t) % Q;
                    }
                }
            }

            return f;
        }

        /// <summary>NTT^-1 (Algorithm 10).</summary>
        /// <param name="input">The NTT representation.</param>
        /// <returns>The polynomial.</returns>
        private static int[] InverseNtt(int[] input)
        {
            int[] f = (int[])input.Clone();
            int i = 127;
            for (int length = 2; length <= 128; length *= 2)
            {
                for (int start = 0; start < 256; start += 2 * length)
                {
                    int zeta = Zetas[i--];
                    for (int j = start; j < start + length; j++)
                    {
                        int t = f[j];
                        f[j] = (t + f[j + length]) % Q;
                        f[j + length] = Mod(zeta * Mod(f[j + length] - t));
                    }
                }
            }

            return f.Select(x => x * 3303 % Q).ToArray();
        }

        /// <summary>MultiplyNTTs (Algorithms 11, 12).</summary>
        /// <param name="f">An NTT representation.</param>
        /// <param name="g">Another.</param>
        /// <returns>Their product's.</returns>
        private static int[] MultiplyNtts(int[] f, int[] g)
        {
            int[] h = new int[256];
            for (int i = 0; i < 128; i++)
            {
                long a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
                h[2 * i] = (int)((a0 * b0 + a1 * b1 % Q * Gammas[i]) % Q);
                h[2 * i + 1] = (int)((a0 * b1 + a1 * b0) % Q);
            }

            return h;
        }

        /// <summary>ByteEncode_d (Algorithm 5).</summary>
        /// <param name="f">256 values below 2^d (or q for d = 12).</param>
        /// <param name="d">The bits a value.</param>
        /// <returns>32 d octets.</returns>
        private static byte[] Encode(int[] f, int d)
        {
            byte[] b = new byte[32 * d];
            for (int i = 0; i < 256; i++)
            {
                for (int j = 0; j < d; j++)
                {
                    int bit = i * d + j;
                    b[bit / 8] |= (byte)(((f[i] >> j) & 1) << (bit % 8));
                }
            }

            return b;
        }

        /// <summary>ByteDecode_d (Algorithm 6): values mod 2^d, or mod q for d = 12.</summary>
        /// <param name="b">32 d octets (or more: the first 32 d are read).</param>
        /// <param name="d">The bits a value.</param>
        /// <returns>256 values.</returns>
        private static int[] Decode(byte[] b, int d)
        {
            int[] f = new int[256];
            for (int i = 0; i < 256; i++)
            {
                for (int j = 0; j < d; j++)
                {
                    int bit = i * d + j;
                    f[i] |= ((b[bit / 8] >> (bit % 8)) & 1) << j;
                }

                f[i] = d == 12 ? f[i] % Q : f[i];
            }

            return f;
        }

        /// <summary>Compress_d (4.2.1): round(2^d x / q) mod 2^d, ties up.</summary>
        /// <param name="f">Values mod q.</param>
        /// <param name="d">The bits.</param>
        /// <returns>The compressed values.</returns>
        private static int[] Compress(int[] f, int d) => f.Select(x => (int)(((((long)x << d) * 2 + Q) / (2 * Q)) % (1 << d))).ToArray();

        /// <summary>Decompress_d (4.2.1): round(q y / 2^d), ties up.</summary>
        /// <param name="f">Values below 2^d.</param>
        /// <param name="d">The bits.</param>
        /// <returns>The values mod q.</returns>
        private static int[] Decompress(int[] f, int d) => f.Select(y => (int)(((long)y * Q * 2 + (1L << d)) / (2L << d))).ToArray();

        /// <summary>Coefficient sums mod q.</summary>
        /// <param name="f">A polynomial.</param>
        /// <param name="g">Another.</param>
        /// <returns>f + g.</returns>
        private static int[] Add(int[] f, int[] g) => f.Zip(g, (a, b) => (a + b) % Q).ToArray();

        /// <summary>Coefficient differences mod q.</summary>
        /// <param name="f">A polynomial.</param>
        /// <param name="g">Another.</param>
        /// <returns>f - g.</returns>
        private static int[] Subtract(int[] f, int[] g) => f.Zip(g, (a, b) => Mod(a - b)).ToArray();

        /// <summary>x mod q in [0, q).</summary>
        /// <param name="x">The value.</param>
        /// <returns>Its residue.</returns>
        private static int Mod(int x) => ((x % Q) + Q) % Q;

        /// <summary>b^e mod q.</summary>
        /// <param name="b">The base.</param>
        /// <param name="e">The exponent (nonnegative).</param>
        /// <returns>The power.</returns>
        private static int Power(int b, int e)
        {
            int result = 1;
            for (int i = 0; i < e; i++)
            {
                result = result * b % Q;
            }

            return result;
        }

        /// <summary>BitRev7: the 7 bits of i in reverse order.</summary>
        /// <param name="i">0..127.</param>
        /// <returns>The reversed value.</returns>
        private static int BitReverse7(int i)
        {
            int r = 0;
            for (int bit = 0; bit < 7; bit++)
            {
                r = (r << 1) | ((i >> bit) & 1);
            }

            return r;
        }
    }
}
