using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_tls13_server_config_init (tls/config.asm): every refusal by its answer, the
/// Certificate message it builds octet for octet, the signature schemes it maps each key kind to
/// (RSA-PSS's encoding bound by the modulus' size, an RSASSA-PSS key's bound hash and minimum
/// salt), the library's defaults, and the sizes a connection needs, recomputed here.
/// </summary>
public sealed unsafe class TlsConfigTests
{
    /// <summary>A loaded private key in native memory, freed (and zeroed) with the object.</summary>
    private sealed class LoadedKey : IDisposable
    {
        /// <summary>The key.</summary>
        public PrivateKey* Key { get; }

        /// <summary>Loads a key file.</summary>
        /// <param name="file">The key's DER or PEM.</param>
        public LoadedKey(byte[] file)
        {
            Key = (PrivateKey*)NativeMemory.AllocZeroed((nuint)sizeof(PrivateKey));
            fixed (byte* f = file)
            {
                Assert.True(Native.PrivateKeyLoad(Key, f, (nuint)file.Length) > 0, "the key loads");
            }
        }

        /// <summary>Zeroes and frees the key.</summary>
        public void Dispose()
        {
            new Span<byte>(Key, sizeof(PrivateKey)).Clear();
            NativeMemory.Free(Key);
        }
    }

    /// <summary>A random source that is never called (a configuration only needs one set).</summary>
    /// <param name="context">Unused.</param>
    /// <param name="output">Unused.</param>
    /// <param name="length">Unused.</param>
    /// <returns>-1.</returns>
    [UnmanagedCallersOnly]
    private static int Never(void* context, byte* output, nuint length) => -1;

    /// <summary>Sets a configuration's "in" fields before init (a pointer type cannot be a
    /// generic argument, so not an Action).</summary>
    /// <param name="config">The configuration.</param>
    private delegate void Setter(TlsServerConfig* config);

    /// <summary>Runs init over a configuration set by the test, a buffer of the given size.</summary>
    /// <param name="key">The key (or null).</param>
    /// <param name="chain">The certificates.</param>
    /// <param name="set">Sets the "in" fields.</param>
    /// <param name="capacity">The buffer's octets.</param>
    /// <param name="config">The configuration after init.</param>
    /// <param name="message">The buffer's octets after init (the Certificate message).</param>
    /// <returns>init's answer.</returns>
    private static int Init(PrivateKey* key, IReadOnlyList<byte[]> chain, Setter? set, int capacity, out TlsServerConfig config, out byte[] message)
    {
        TlsServerConfig* c = (TlsServerConfig*)NativeMemory.AllocZeroed((nuint)sizeof(TlsServerConfig));
        byte* buffer = (byte*)NativeMemory.AllocZeroed((nuint)Math.Max(1, capacity));
        try
        {
            c->Key = key;
            c->Random = &Never;
            set?.Invoke(c);
            int answer = TlsServerHarness.InitConfig(c, chain, buffer, (nuint)capacity);
            config = *c;
            message = new ReadOnlySpan<byte>(buffer, capacity).ToArray();
            return answer;
        }
        finally
        {
            NativeMemory.Free(buffer);
            NativeMemory.Free(c);
        }
    }

    /// <summary>
    /// The refusals, each by its answer: no key, no random source, no chain, a list over its
    /// bound (17 groups, 5 suites), a group or suite the engine lacks, a max_message under 512
    /// (-1); a certificate that does not parse, a leaf whose key is not the configuration's
    /// (-2); a buffer too small (-3, certificate_length then the octets it needs). A max_message
    /// of 512 is taken.
    /// </summary>
    [Fact]
    public void RefusesWhatItMust()
    {
        Platform.RequireLinuxX64();
        TlsInteropTests.Credential p256 = TlsInteropTests.Make("p256");
        TlsInteropTests.Credential other = TlsInteropTests.Make("p256");
        using var key = new LoadedKey(p256.Key);
        byte[][] chain = [p256.Certificate];
        int room = p256.Certificate.Length + 64;
        Assert.Equal(-1, Init(null, chain, null, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, chain, c => c->Random = null, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, [], null, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, chain, c => c->GroupCount = 17, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, chain, c => { c->Groups[0] = 0x0200; c->GroupCount = 1; }, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, chain, c => c->SuiteCount = 5, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, chain, c => { c->Suites[0] = 0x1304; c->SuiteCount = 1; }, room, out _, out _));
        Assert.Equal(-1, Init(key.Key, chain, c => c->MaxMessage = 511, room, out _, out _));
        Assert.Equal(0, Init(key.Key, chain, c => c->MaxMessage = 512, room, out TlsServerConfig small, out _));
        Assert.Equal(512u, small.MaxMessage);
        Assert.Equal(-2, Init(key.Key, [[0x30, 0x03, 0x02, 0x01, 0x01]], null, room, out _, out _));
        Assert.Equal(-2, Init(key.Key, [other.Certificate], null, room, out _, out _));
        Assert.Equal(-2, Init(key.Key, [p256.Certificate, [0x30, 0x00]], null, room, out _, out _));   // a second that does not parse
        Assert.Equal(-3, Init(key.Key, chain, null, 10, out TlsServerConfig tooSmall, out _));
        Assert.Equal((nuint)(8 + p256.Certificate.Length + 5), tooSmall.CertificateLength);
    }

    /// <summary>
    /// What init fills: the Certificate message (RFC 9846 4.5.1: an empty context, each entry
    /// its cert_data and no extensions) octet for octet for a chain of three, the library's
    /// groups and suites in order, max_message's default, and the sizes: output_min recomputed
    /// here from the file's rule (the flight at 63-octet records, the largest share of the
    /// groups, the retry, the ServerHello, the reserve), memory its sum with max_message.
    /// </summary>
    [Fact]
    public void FillsWhatAConnectionNeeds()
    {
        Platform.RequireLinuxX64();
        TlsInteropTests.Credential leaf = TlsInteropTests.Make("p256");
        byte[] second = TlsInteropTests.Make("p384").Certificate;
        byte[] third = TlsInteropTests.Make("rsa2048").Certificate;
        using var key = new LoadedKey(leaf.Key);
        byte[][] chain = [leaf.Certificate, second, third];
        Assert.Equal(0, Init(key.Key, chain, null, 8000, out TlsServerConfig config, out byte[] buffer));
        byte[] entries = [.. chain.SelectMany(c => (byte[])[(byte)(c.Length >> 16), (byte)(c.Length >> 8), (byte)c.Length, .. c, 0, 0])];
        byte[] body = [0, (byte)(entries.Length >> 16), (byte)(entries.Length >> 8), (byte)entries.Length, .. entries];
        byte[] expected = TlsTestClient.Message(11, body);
        Assert.Equal((nuint)expected.Length, config.CertificateLength);
        Assert.Equal(expected, buffer[..expected.Length]);
        Assert.Equal((uint)TlsEngine.DefaultGroups.Length, config.GroupCount);
        for (int i = 0; i < TlsEngine.DefaultGroups.Length; i++)
        {
            Assert.Equal(TlsEngine.DefaultGroups[i], config.Groups[i]);
        }

        Assert.Equal(3u, config.SuiteCount);
        Assert.Equal(TlsEngine.DefaultSuites, new[] { config.Suites[0], config.Suites[1], config.Suites[2] });
        Assert.Equal(16384u, config.MaxMessage);
        Assert.Equal(1ul << 6, config.Schemes);

        // output_min, by the file's rule: the flight's plaintext (EncryptedExtensions and a
        // CertificateRequest with 64 octets of room each, the Certificate, a CertificateVerify of
        // the largest P-256 signature, Finished) at 63-octet records, then the retry (93), a
        // change_cipher_spec (6), the ServerHello (95 and the largest share: SecP384r1MLKEM1024's
        // 1665), the reserve (64), a KeyUpdate's record (27), rounded up to 64; memory adds
        // max_message, rounded to 16
        long plain = expected.Length + (4 + 2 + 64) + (4 + 1 + 2 + 64) + (72 + 8) + (4 + 48);
        long records = (plain + 62) / 63;
        long outputMin = (plain + 22 * records + 1665 + 93 + 6 + 95 + 64 + 27 + 63) & ~63L;
        Assert.Equal((nuint)outputMin, config.OutputMin);
        Assert.Equal((nuint)((outputMin + 16384 + 15) & ~15L), config.Memory);
    }

    /// <summary>
    /// The schemes each key kind makes (RFC 9846 4.3.3): an RSA key of 2048 bits all three
    /// rsa_pss_rsae ones, one of 1024 bits not SHA-512's (its encoding needs 2 hLen + 2 = 130
    /// octets: emLen is 128); an RSASSA-PSS key without parameters the three rsa_pss_pss ones,
    /// one bound to SHA-256 with a 32-octet minimum salt only SHA-256's, one bound to SHA-256
    /// with a 64-octet minimum salt none (init refuses: -1, TLS's salt is the hash's length);
    /// each curve its ECDSA scheme; Ed25519 and Ed448 theirs.
    /// </summary>
    [Fact]
    public void MapsEachKeyToTheSchemesItMakes()
    {
        Platform.RequireLinuxX64();
        static (int Answer, ulong Schemes) For(byte[] keyFile, byte[] certificate)
        {
            using var key = new LoadedKey(keyFile);
            int answer = Init(key.Key, [certificate], null, certificate.Length + 64, out TlsServerConfig config, out _);
            return (answer, config.Schemes);
        }

        using (RSA rsa = RSA.Create(1024))
        {
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            Assert.Equal((0, 0b011ul), For(rsa.ExportPkcs8PrivateKey(), cert.RawData));
        }

        TlsInteropTests.Credential rsa2048 = TlsOpenSslCliTests.Make("rsa");
        Assert.Equal((0, 0b111ul), For(rsa2048.Key, rsa2048.Certificate));
        TlsInteropTests.Credential pss = TlsOpenSslCliTests.Make("rsa-pss");
        Assert.Equal((0, 0b111000ul), For(pss.Key, pss.Certificate));
        TlsInteropTests.Credential pss256 = TlsOpenSslCliTests.Make("rsa-pss-sha256");
        Assert.Equal((0, 0b1000ul), For(pss256.Key, pss256.Certificate));
        TlsInteropTests.Credential pssBigSalt = TlsOpenSslCliTests.Make("rsa-pss-sha256-salt64");
        Assert.Equal(-1, For(pssBigSalt.Key, pssBigSalt.Certificate).Answer);
        foreach ((string kind, int bit) in new[] { ("p256", 6), ("p384", 7), ("p521", 8), ("ed25519", 9), ("ed448", 10) })
        {
            TlsInteropTests.Credential c = TlsOpenSslCliTests.Make(kind);
            Assert.Equal((0, 1ul << bit), For(c.Key, c.Certificate));
        }
    }
}
