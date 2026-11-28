using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_private_key_load (asn1/keys.asm) through the C ABI: keys .NET makes of every kind it
/// makes (RSA at 2048, 3072 and 4096 bits, P-256, P-384, P-521) in PKCS#8, PKCS#1 and SEC1, DER
/// and PEM, each loaded and then proven by a signature the library makes and .NET verifies;
/// RFC 8410's Ed25519 keys and RFC 8032's Ed448 key, proven by their RFCs' public keys; the BER
/// forms RFC 5958 makes receivers accept; PSS keys with and without RFC 4055's parameters; and
/// every refusal the loader documents, each leaving the key all zeros.
/// </summary>
public sealed unsafe class KeyTests
{
    /// <summary>Where the prepared key of the kind starts in httpasm_private_key (after kind, bits,
    /// the PSS fields, public_length, reserved and the 136-octet public key).</summary>
    private const int SecretOffset = 168;

    /// <summary>What a load returned: the answer and the key's octets.</summary>
    /// <param name="Kind">The answer (a kind, -1 or -2).</param>
    /// <param name="Key">httpasm_private_key's octets after the call.</param>
    private readonly record struct Loaded(int Kind, byte[] Key)
    {
        /// <summary>The key's bits field.</summary>
        public uint Bits => BitConverter.ToUInt32(Key, 4);

        /// <summary>The PSS hash field.</summary>
        public uint PssHash => BitConverter.ToUInt32(Key, 8);

        /// <summary>The PSS salt field.</summary>
        public uint PssSalt => BitConverter.ToUInt32(Key, 12);

        /// <summary>The public key the loader kept.</summary>
        public byte[] Public => Key[32..(32 + (int)BitConverter.ToUInt32(Key, 16))];
    }

    /// <summary>Loads a key from octets placed at the end of a page before a guard page (larger
    /// inputs: native memory), into a key filled with 0xEE first.</summary>
    /// <param name="data">The key's file.</param>
    /// <returns>The answer and the key's octets.</returns>
    private static Loaded Load(byte[] data)
    {
        byte[] key = new byte[sizeof(PrivateKey)];
        Array.Fill(key, (byte)0xEE);
        int kind;
        if (data.Length > GuardedBuffer.PageSize)
        {
            byte* block = (byte*)NativeMemory.Alloc((nuint)data.Length);
            try
            {
                data.CopyTo(new Span<byte>(block, data.Length));
                fixed (byte* k = key)
                {
                    kind = Native.PrivateKeyLoad((PrivateKey*)k, block, (nuint)data.Length);
                }
            }
            finally
            {
                NativeMemory.Free(block);
            }
        }
        else
        {
            using var guard = new GuardedBuffer();
            byte* at = guard.AtPageEnd(data);
            fixed (byte* k = key)
            {
                kind = Native.PrivateKeyLoad((PrivateKey*)k, at, (nuint)data.Length);
            }
        }

        if (kind < 0)
        {
            Assert.True(key.All(b => b == 0), "a refused key was not left all zeros");
        }

        return new Loaded(kind, key);
    }

    /// <summary>The same for text.</summary>
    /// <param name="pem">PEM text.</param>
    /// <returns>The answer and the key's octets.</returns>
    private static Loaded Load(string pem) => Load(Encoding.ASCII.GetBytes(pem));

    /// <summary>A DER element: tag, the fewest length octets, contents.</summary>
    /// <param name="tag">The identifier octet.</param>
    /// <param name="parts">The contents, joined.</param>
    /// <returns>The encoding.</returns>
    internal static byte[] Der(byte tag, params byte[][] parts)
    {
        byte[] content = [.. parts.SelectMany(p => p)];
        var o = new List<byte> { tag };
        if (content.Length < 128)
        {
            o.Add((byte)content.Length);
        }
        else
        {
            byte[] n = BitConverter.GetBytes(content.Length).Reverse().SkipWhile(b => b == 0).ToArray();
            o.Add((byte)(0x80 | n.Length));
            o.AddRange(n);
        }

        o.AddRange(content);
        return [.. o];
    }

    /// <summary>A BER element of indefinite length: tag | constructed, 0x80, contents, 00 00.</summary>
    /// <param name="tag">The identifier octet (its constructed bit is set here).</param>
    /// <param name="parts">The contents, joined.</param>
    /// <returns>The encoding.</returns>
    private static byte[] Indefinite(byte tag, params byte[][] parts) => [(byte)(tag | 0x20), 0x80, .. parts.SelectMany(p => p), 0, 0];

    /// <summary>An INTEGER's DER of an unsigned big-endian magnitude (a 00 octet put first when
    /// its top bit is set, so the value stays positive).</summary>
    /// <param name="magnitude">The value's octets.</param>
    /// <returns>The encoding.</returns>
    internal static byte[] Integer(byte[] magnitude)
    {
        byte[] m = magnitude.SkipWhile(b => b == 0).ToArray();
        if (m.Length == 0 || (m[0] & 0x80) != 0)
        {
            m = [0, .. m];
        }

        return Der(0x02, m);
    }

    /// <summary>A small INTEGER's DER.</summary>
    /// <param name="value">0 to 255.</param>
    /// <returns>The encoding.</returns>
    internal static byte[] Small(int value) => Integer([(byte)value]);

    // The identifiers the keys' and certificates' tests build structures of, as whole DER elements
    // (internal: CertificateTests builds public key infos of the same).

    /// <summary>rsaEncryption (PKCS#1): a key for both paddings; its parameters NULL.</summary>
    internal static readonly byte[] OidRsa = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    /// <summary>id-RSASSA-PSS (RFC 4055): a key for PSS only, its parameters optional.</summary>
    internal static readonly byte[] OidPss = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];

    /// <summary>id-mgf1: the only mask generation function the readers accept.</summary>
    internal static readonly byte[] OidMgf1 = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08];

    /// <summary>id-ecPublicKey (RFC 5480): its parameters must name the curve.</summary>
    internal static readonly byte[] OidEc = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    /// <summary>secp256r1 (P-256).</summary>
    internal static readonly byte[] OidP256 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// <summary>secp384r1 (P-384).</summary>
    internal static readonly byte[] OidP384 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

    /// <summary>secp521r1 (P-521).</summary>
    internal static readonly byte[] OidP521 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];

    /// <summary>secp256k1: a named curve the library has no arithmetic for (refused).</summary>
    internal static readonly byte[] OidSecp256k1 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];

    /// <summary>id-Ed25519 (RFC 8410): parameters must be absent.</summary>
    internal static readonly byte[] OidEd25519 = [0x06, 0x03, 0x2B, 0x65, 0x70];

    /// <summary>id-Ed448 (RFC 8410).</summary>
    internal static readonly byte[] OidEd448 = [0x06, 0x03, 0x2B, 0x65, 0x71];

    /// <summary>id-X25519 (RFC 8410): a key-agreement key, which signs nothing (refused).</summary>
    internal static readonly byte[] OidX25519 = [0x06, 0x03, 0x2B, 0x65, 0x6E];

    /// <summary>id-sha256.</summary>
    internal static readonly byte[] OidSha256 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    /// <summary>id-sha384.</summary>
    internal static readonly byte[] OidSha384 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

    /// <summary>id-sha512.</summary>
    internal static readonly byte[] OidSha512 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

    /// <summary>id-sha224: a hash no TLS 1.3 PSS scheme uses (refused in PSS parameters).</summary>
    internal static readonly byte[] OidSha224 = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];

    /// <summary>id-sha1: PSS's default hash, which TLS 1.3 never signs with (refused).</summary>
    internal static readonly byte[] OidSha1 = [0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];

    /// <summary>NULL's DER: RSA's and the hashes' parameters.</summary>
    internal static readonly byte[] Null = [0x05, 0x00];

    /// <summary>
    /// One RSASSA-PSS-params case (RFC 4055 3.1) that both readers of PSS keys must agree on: the
    /// private keys' (keys.asm, under BER) and the public key infos' (x509.asm, under DER).
    /// </summary>
    /// <param name="Name">What the case shows (the assertion's message).</param>
    /// <param name="Parameters">The AlgorithmIdentifier's parameters element, whole.</param>
    /// <param name="Hash">The hash the key is bound to (HTTPASM_HASH_*), or -1 when the
    /// parameters must be refused.</param>
    /// <param name="Salt">The salt length bound (only meaningful when accepted).</param>
    internal readonly record struct PssCase(string Name, byte[] Parameters, int Hash, uint Salt);

    /// <summary>
    /// The PSS parameters cases: every field present and absent, each hash TLS 1.3 signs with,
    /// salts at both ends of 0 to 2^31 - 1, and each way the parameters can break a rule (SHA-1 by
    /// name or by default, MGF1 over another hash or absent, another mask generation function, a
    /// trailer field other than 1, fields out of order, twice, unknown or primitive, an EXPLICIT
    /// tag holding no element or two, an AlgorithmIdentifier of the wrong shape, an INTEGER out of
    /// range, and an element that does not read at each depth). A refusal must hold whichever
    /// reader meets the parameters: a key bound to SHA-1 or to a mismatch could sign nothing TLS 1.3
    /// accepts, and a malformed one is not the key its writer meant.
    /// </summary>
    /// <returns>The cases.</returns>
    internal static PssCase[] PssCases()
    {
        byte[] Hash(byte[] oid) => Der(0x30, oid, Null);
        byte[] Mgf(byte[] hash) => Der(0x30, OidMgf1, hash);
        byte[] P(params byte[][] fields) => Der(0x30, fields);
        byte[] A(int n, params byte[][] content) => Der((byte)(0xA0 | n), content);
        byte[] h256 = Hash(OidSha256), h384 = Hash(OidSha384), h512 = Hash(OidSha512), h1 = Hash(OidSha1);
        byte[] m256 = A(1, Mgf(h256));
        return
        [
            new("SHA-256, MGF1 over SHA-256, salt 32", P(A(0, h256), m256, A(2, Small(32))), Abi.HashSha256, 32),
            new("SHA-384, MGF1 over SHA-384, salt 48", P(A(0, h384), A(1, Mgf(h384)), A(2, Small(48))), Abi.HashSha384, 48),
            new("SHA-512, MGF1 over SHA-512, salt 64, trailer 1", P(A(0, h512), A(1, Mgf(h512)), A(2, Small(64)), A(3, Small(1))), Abi.HashSha512, 64),
            new("hashes without their NULL, the default salt", P(A(0, Der(0x30, OidSha256)), A(1, Mgf(Der(0x30, OidSha256)))), Abi.HashSha256, 20),
            new("salt 0", P(A(0, h256), m256, A(2, Small(0))), Abi.HashSha256, 0),
            new("salt 2^31 - 1", P(A(0, h256), m256, A(2, Der(0x02, [0x7F, 0xFF, 0xFF, 0xFF]))), Abi.HashSha256, int.MaxValue),
            new("trailer 1 alone after the hashes", P(A(0, h256), m256, A(3, Small(1))), Abi.HashSha256, 20),
            new("every field absent: SHA-1", P(), -1, 0),
            new("SHA-1 named", P(A(0, h1), A(1, Mgf(h1))), -1, 0),
            new("SHA-256 with MGF1's default, SHA-1", P(A(0, h256)), -1, 0),
            new("SHA-256 with the salt alone after it", P(A(0, h256), A(2, Small(32))), -1, 0),
            new("MGF1 over SHA-256 with the hash's default, SHA-1", P(m256), -1, 0),
            new("MGF1 over another hash", P(A(0, h256), A(1, Mgf(h384))), -1, 0),
            new("an unknown hash (SHA-224)", P(A(0, Hash(OidSha224)), A(1, Mgf(Hash(OidSha224)))), -1, 0),
            new("a trailer field of 2", P(A(0, h256), m256, A(3, Small(2))), -1, 0),
            new("fields out of order", P(m256, A(0, h256)), -1, 0),
            new("the salt before the mask", P(A(0, h256), A(2, Small(32)), m256), -1, 0),
            new("a field twice", P(A(0, h256), A(0, h256), m256), -1, 0),
            new("the salt twice", P(A(0, h256), m256, A(2, Small(32)), A(2, Small(32))), -1, 0),
            new("a field after the trailer", P(A(0, h256), m256, A(3, Small(1)), A(3, Small(1))), -1, 0),
            new("an unknown field [4]", P(A(0, h256), m256, A(4, Small(1))), -1, 0),
            new("a field primitive (IMPLICIT)", P(A(0, h256), m256, Der(0x82, [32])), -1, 0),
            new("[0] empty", P(A(0), m256), -1, 0),
            new("[0] holding two elements", P(A(0, h256, Null), m256), -1, 0),
            new("[0] holding an identifier, not an AlgorithmIdentifier", P(A(0, OidSha256), m256), -1, 0),
            new("a hash's identifier not an OBJECT IDENTIFIER", P(A(0, Der(0x30, Small(1))), m256), -1, 0),
            new("a hash's parameters other than NULL", P(A(0, Der(0x30, OidSha256, Der(0x04, []))), m256), -1, 0),
            new("a hash's parameters followed by more", P(A(0, Der(0x30, OidSha256, Null, Null)), m256), -1, 0),
            new("[1] empty", P(A(0, h256), A(1)), -1, 0),
            new("[1] holding two elements", P(A(0, h256), A(1, Mgf(h256), Null)), -1, 0),
            new("[1] holding an identifier, not an AlgorithmIdentifier", P(A(0, h256), A(1, OidMgf1)), -1, 0),
            new("a mask generation function other than MGF1", P(A(0, h256), A(1, Der(0x30, OidSha256, h256))), -1, 0),
            new("the mask's identifier not an OBJECT IDENTIFIER", P(A(0, h256), A(1, Der(0x30, Small(1), h256))), -1, 0),
            new("MGF1 without its hash", P(A(0, h256), A(1, Der(0x30, OidMgf1))), -1, 0),
            new("MGF1's hash followed by more", P(A(0, h256), A(1, Der(0x30, OidMgf1, h256, Null))), -1, 0),
            new("MGF1's hash an identifier, not an AlgorithmIdentifier", P(A(0, h256), A(1, Der(0x30, OidMgf1, OidSha256))), -1, 0),
            new("a negative salt", P(A(0, h256), m256, A(2, Der(0x02, [0x80]))), -1, 0),
            new("a salt of 2^31 (five octets)", P(A(0, h256), m256, A(2, Der(0x02, [0x00, 0x80, 0x00, 0x00, 0x00]))), -1, 0),
            new("a salt not an INTEGER", P(A(0, h256), m256, A(2, Null)), -1, 0),
            new("[2] holding two INTEGERs", P(A(0, h256), m256, A(2, Small(32), Small(1))), -1, 0),
            new("[2] empty", P(A(0, h256), m256, A(2)), -1, 0),
            new("a trailer not an INTEGER", P(A(0, h256), m256, A(3, Null)), -1, 0),
            new("the parameters not a SEQUENCE", Null, -1, 0),
            new("a field that does not read", Der(0x30, [0xA0, 0x10, 0x30, 0x0D]), -1, 0),
            new("a field after the hash that does not read", Der(0x30, [.. A(0, h256), 0xA1, 0x10]), -1, 0),
            new("a field after the mask that does not read", Der(0x30, [.. A(0, h256), .. m256, 0xA2, 0x10]), -1, 0),
            new("a field after the salt that does not read", Der(0x30, [.. A(0, h256), .. m256, .. A(2, Small(32)), 0xA3, 0x10]), -1, 0),
            new("a hash that does not read", P(A(0, [0x30, 0x10]), m256), -1, 0),
            new("a hash's identifier that does not read", P(A(0, Der(0x30, [0x06, 0x10])), m256), -1, 0),
            new("a hash's parameters that do not read", P(A(0, Der(0x30, [.. OidSha256, 0x05, 0x10])), m256), -1, 0),
            new("a mask that does not read", P(A(0, h256), A(1, [0x30, 0x10])), -1, 0),
            new("the mask's identifier that does not read", P(A(0, h256), A(1, Der(0x30, [0x06, 0x10]))), -1, 0),
            new("MGF1's hash that does not read", P(A(0, h256), A(1, Der(0x30, [.. OidMgf1, 0x30, 0x10]))), -1, 0),
            new("a salt that does not read", P(A(0, h256), m256, A(2, [0x02, 0x10])), -1, 0),
        ];
    }

    /// <summary>
    /// The .NET copy of httpasm_private_key has the library's size, 6888 octets, under struct id
    /// 25 (the end of the registry is checked by the newest structures' tests: CertificateTests).
    /// </summary>
    [Fact]
    public void StructureMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(6888, sizeof(PrivateKey));
        Assert.Equal((uint)sizeof(PrivateKey), Native.StructSize(25));
    }

    /// <summary>
    /// RSA keys .NET makes, at 2048, 3072 and 4096 bits, in PKCS#8 and PKCS#1, DER and PEM: each
    /// loads as an RSA key of its size, and a PKCS#1 v1.5 signature and a PSS signature made with
    /// the prepared key verify under .NET's public key.
    /// </summary>
    /// <param name="bits">The modulus' size.</param>
    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    [Requirement("RFC7468-10-p2")]
    public void LoadsRsaKeysThatSign(int bits)
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(bits);
        byte[][] files =
        [
            rsa.ExportPkcs8PrivateKey(), rsa.ExportRSAPrivateKey(),
            Encoding.ASCII.GetBytes(rsa.ExportPkcs8PrivateKeyPem()), Encoding.ASCII.GetBytes(rsa.ExportRSAPrivateKeyPem()),
        ];
        foreach (byte[] file in files)
        {
            Loaded k = Load(file);
            Assert.Equal(Abi.KeyRsa, k.Kind);
            Assert.Equal((uint)bits, k.Bits);
            Assert.Empty(k.Public);
            SignsRsa(k, rsa);
        }
    }

    /// <summary>Signs a digest with a loaded RSA key's prepared key (both paddings) and verifies
    /// with .NET.</summary>
    /// <param name="k">The loaded key.</param>
    /// <param name="rsa">.NET's key.</param>
    private static void SignsRsa(Loaded k, RSA rsa)
    {
        byte[] digest = SHA256.HashData("signed by a loaded key"u8);
        byte[] signature = new byte[rsa.KeySize / 8];
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        fixed (byte* key = k.Key)
        fixed (byte* d = digest)
        fixed (byte* s = signature)
        fixed (byte* sa = salt)
        {
            var prepared = (RsaPrivateKey*)(key + SecretOffset);
            Assert.Equal(0, Native.RsaSignPkcs1(prepared, Abi.HashSha256, d, s, (nuint)signature.Length));
            Assert.True(rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Assert.Equal(0, Native.RsaSignPss(prepared, Abi.HashSha256, d, sa, 32, s, (nuint)signature.Length));
            Assert.True(rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
    }

    /// <summary>
    /// EC keys .NET makes on P-256, P-384 and P-521, in PKCS#8 (OpenSSL's shape: the curve in the
    /// algorithm, none in ECPrivateKey) and SEC1 (the curve in [0], the public key in [1]), DER
    /// and PEM: each loads as its curve's key, its public key .NET's, and a signature made with
    /// its scalar verifies under .NET's key.
    /// </summary>
    /// <param name="curve">"P-256", "P-384" or "P-521".</param>
    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    [Requirement("RFC5915-3-p1", "RFC5915-3-p3", "RFC5480-2.1-p2", "RFC5480-2.1.1-p7", "RFC5480-2.2-p3#1")]
    public void LoadsEcKeysThatSign(string curve)
    {
        Platform.RequireLinuxX64();
        (ECCurve named, int kind, int size, int bits) = curve switch
        {
            "P-256" => (ECCurve.NamedCurves.nistP256, Abi.KeyP256, 32, 256),
            "P-384" => (ECCurve.NamedCurves.nistP384, Abi.KeyP384, 48, 384),
            _ => (ECCurve.NamedCurves.nistP521, Abi.KeyP521, 66, 521),
        };
        using ECDsa ec = ECDsa.Create(named);
        ECParameters p = ec.ExportParameters(false);
        byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
        byte[][] files =
        [
            ec.ExportPkcs8PrivateKey(), ec.ExportECPrivateKey(),
            Encoding.ASCII.GetBytes(ec.ExportPkcs8PrivateKeyPem()), Encoding.ASCII.GetBytes(ec.ExportECPrivateKeyPem()),
        ];
        foreach (byte[] file in files)
        {
            Loaded k = Load(file);
            Assert.Equal(kind, k.Kind);
            Assert.Equal((uint)bits, k.Bits);
            Assert.Equal(point, k.Public);
            SignsEc(k, ec, size);
        }
    }

    /// <summary>Signs a digest with a loaded EC key's scalar and verifies with .NET.</summary>
    /// <param name="k">The loaded key.</param>
    /// <param name="ec">.NET's key.</param>
    /// <param name="size">The curve's octets.</param>
    private static void SignsEc(Loaded k, ECDsa ec, int size)
    {
        byte[] digest = SHA512.HashData("signed by a loaded key"u8);
        byte[] signature = new byte[2 * size];
        fixed (byte* key = k.Key)
        fixed (byte* d = digest)
        fixed (byte* s = signature)
        {
            byte* scalar = key + SecretOffset;
            int r = size switch
            {
                32 => Native.P256Sign(s, scalar, d, 32, null),
                48 => Native.P384Sign(s, scalar, d, 48, null),
                _ => Native.P521Sign(s, scalar, d, 64, null),
            };
            Assert.Equal(0, r);
        }

        Assert.True(ec.VerifyHash(digest[..(size == 66 ? 64 : size)], signature));
    }

    /// <summary>
    /// RFC 8410's Ed25519 private key (10.3), in PEM, and its second example with an attribute and
    /// the public key (v2); and RFC 8032's first Ed448 key (7.4, "blank") wrapped in PKCS#8: each
    /// loads with the public key its RFC gives.
    /// </summary>
    [Fact]
    [Requirement("RFC8410-7-p2#1", "RFC5958-2-p6#2", "RFC5958-2-p18#1")]
    public void LoadsEdwardsKeys()
    {
        Platform.RequireLinuxX64();
        const string ed25519Public = "19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1";
        Loaded k = Load("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n");
        Assert.Equal((Abi.KeyEd25519, 256u), (k.Kind, k.Bits));
        Assert.Equal(ed25519Public, Convert.ToHexString(k.Public));

        k = Load("-----BEGIN PRIVATE KEY-----\n" +
                 "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n" +
                 "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n" +
                 "Z9w7lshQhqowtrbLDFw4rXAxZuE=\n" +
                 "-----END PRIVATE KEY-----\n");
        Assert.Equal(Abi.KeyEd25519, k.Kind);
        Assert.Equal(ed25519Public, Convert.ToHexString(k.Public));

        byte[] seed = Convert.FromHexString("6C82A562CB808D10D632BE89C8513EBF6C929F34DDFA8C9F63C9960EF6E348A3528C8A3FCC2F044E39A3FC5B94492F8F032E7549A20098F95B");
        k = Load(Der(0x30, Small(0), Der(0x30, OidEd448), Der(0x04, Der(0x04, seed))));
        Assert.Equal((Abi.KeyEd448, 448u), (k.Kind, k.Bits));
        Assert.Equal("5FD7449B59B461FD2CE787EC616AD46A1DA1342485A70E1F8A0EA75D80E96778EDF124769B46C7061BD6783DF1E50F6CD1FA1ABEAFE8256180", Convert.ToHexString(k.Public));
    }

    /// <summary>
    /// BER, which RFC 5958 makes receivers support: a PKCS#8 key rewritten with indefinite lengths
    /// everywhere, its privateKey a constructed OCTET STRING of several segments, its lengths in
    /// longer forms than needed, loads as the same key as its DER (RSA, P-256, Ed25519 alike), and
    /// so does BER nested in BER (a segmented privateKey holding an ECPrivateKey whose scalar is
    /// segmented too); a segmented value longer than the loader's 16 KiB of room is refused.
    /// </summary>
    [Fact]
    [Requirement("RFC5958-2-p1#3", "RFC5915-4-p1#2", "X690-7.3")]
    public void LoadsBerEncodedKeys()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(2048);
        byte[] pkcs1 = rsa.ExportRSAPrivateKey();
        byte[] ber = Indefinite(0x30, Small(0), Indefinite(0x30, OidRsa, Null), Segments(pkcs1, 100));
        Loaded k = Load(ber);
        Assert.Equal(Abi.KeyRsa, k.Kind);
        SignsRsa(k, rsa);

        // the inner RSAPrivateKey in BER too, with a long-form length of leading zeros
        byte[] innerBer = LongForm(pkcs1);
        k = Load(Der(0x30, Small(0), Der(0x30, OidRsa, Null), Der(0x04, innerBer)));
        Assert.Equal(Abi.KeyRsa, k.Kind);

        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] sec1 = ec.ExportECPrivateKey();
        k = Load(Indefinite(0x30, Small(0), Der(0x30, OidEc, OidP256), Segments(sec1, 7)));
        Assert.Equal(Abi.KeyP256, k.Kind);
        SignsEc(k, ec, 32);

        byte[] seed = Convert.FromHexString("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");
        k = Load(Indefinite(0x30, Small(0), Der(0x30, OidEd25519), Segments(Indefinite(0x04, Der(0x04, seed[..10]), Der(0x04, seed[10..])), 5)));
        Assert.Equal(Abi.KeyEd25519, k.Kind);
        Assert.Equal("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1", Convert.ToHexString(k.Public));

        // BER inside BER: the privateKey's segments gathered, and inside them an ECPrivateKey
        // whose own scalar is segmented, gathered into the same buffer over the octets already
        // read (the copy runs behind the reading: the same key)
        byte[] segmentedD = Der(0x30, Small(1), Segments(ec.ExportParameters(true).D!, 5), Der(0xA0, OidP256));
        k = Load(Indefinite(0x30, Small(0), Der(0x30, OidEc, OidP256), Segments(segmentedD, 9)));
        Assert.Equal(Abi.KeyP256, k.Kind);
        SignsEc(k, ec, 32);

        // a segmented value longer than the loader's room for one (16 KiB), as a PKCS#8
        // privateKey and as an ECPrivateKey's scalar: refused, whatever its contents
        byte[] huge = new byte[17000];
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEc, OidP256), Segments(huge, 1000))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(1), Segments(huge, 1000), Der(0xA0, OidP256))).Kind);

        static byte[] Segments(byte[] value, int size) =>
            Indefinite(0x04, [.. value.Chunk(size).Select(c => Der(0x04, c))]);

        static byte[] LongForm(byte[] der)
        {
            // the outer SEQUENCE's length rewritten as 84 00 00 xx xx
            int headerLength = der[1] < 0x80 ? 2 : 2 + (der[1] & 0x7F);
            int contentLength = der.Length - headerLength;
            return [der[0], 0x84, 0, 0, (byte)(contentLength >> 8), (byte)contentLength, .. der[headerLength..]];
        }
    }

    /// <summary>
    /// RSASSA-PSS keys (RFC 4055 3.1): with no parameters, any hash (pss_hash 0); with SHA-256,
    /// MGF1 over SHA-256 and a 32-octet salt, bound to them (pss_hash, pss_salt); the keys sign.
    /// Parameters naming SHA-1 (explicitly or by default), MGF1 over another hash, or a trailer
    /// field other than 1 are refused: no TLS 1.3 PSS signature could use such a key. Then every
    /// case of <see cref="PssCases"/>, the table the public key infos' reader is held to as well
    /// (CertificateTests), each bound as the case says or refused.
    /// </summary>
    [Fact]
    [Requirement("RFC4055-3.1-p1#1", "RFC4055-3.1-p7#5", "RFC4055-3.1-p10", "RFC4055-3.1-p14#1", "RFC4055-3.1-p14#3")]
    public void LoadsPssKeysAndTheirParameters()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(2048);
        byte[] pkcs1 = rsa.ExportRSAPrivateKey();
        Loaded k = Load(Der(0x30, Small(0), Der(0x30, OidPss), Der(0x04, pkcs1)));
        Assert.Equal((Abi.KeyRsaPss, 0u, 0u), (k.Kind, k.PssHash, k.PssSalt));
        SignsRsa(k, rsa);

        byte[] sha256 = Der(0x30, OidSha256, Null);
        byte[] mgf = Der(0x30, OidMgf1, sha256);
        byte[] Params(params byte[][] fields) => Der(0x30, OidPss, Der(0x30, fields));
        k = Load(Der(0x30, Small(0), Params(Der(0xA0, sha256), Der(0xA1, mgf), Der(0xA2, Small(32))), Der(0x04, pkcs1)));
        Assert.Equal((Abi.KeyRsaPss, (uint)Abi.HashSha256, 32u), (k.Kind, k.PssHash, k.PssSalt));
        k = Load(Der(0x30, Small(0), Params(Der(0xA0, Der(0x30, OidSha256)), Der(0xA1, Der(0x30, OidMgf1, Der(0x30, OidSha256))), Der(0xA3, Small(1))), Der(0x04, pkcs1)));
        Assert.Equal((Abi.KeyRsaPss, (uint)Abi.HashSha256, 20u), (k.Kind, k.PssHash, k.PssSalt));

        byte[] sha1 = Der(0x30, OidSha1, Null);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Params(), Der(0x04, pkcs1))).Kind);                                 // all defaults: SHA-1
        Assert.Equal(-1, Load(Der(0x30, Small(0), Params(Der(0xA0, sha1)), Der(0x04, pkcs1))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Params(Der(0xA0, sha256)), Der(0x04, pkcs1))).Kind);                // MGF1-SHA-1
        Assert.Equal(-1, Load(Der(0x30, Small(0), Params(Der(0xA0, sha256), Der(0xA1, Der(0x30, OidMgf1, sha1))), Der(0x04, pkcs1))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Params(Der(0xA0, sha256), Der(0xA1, mgf), Der(0xA3, Small(2))), Der(0x04, pkcs1))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Params(Der(0xA1, mgf), Der(0xA0, sha256)), Der(0x04, pkcs1))).Kind); // out of order

        foreach (PssCase c in PssCases())
        {
            Loaded l = Load(Der(0x30, Small(0), Der(0x30, OidPss, c.Parameters), Der(0x04, pkcs1)));
            if (c.Hash < 0)
            {
                Assert.True(l.Kind == -1, $"{c.Name}: loaded as kind {l.Kind}");
            }
            else
            {
                Assert.True((Abi.KeyRsaPss, (uint)c.Hash, c.Salt) == (l.Kind, l.PssHash, l.PssSalt),
                    $"{c.Name}: kind {l.Kind}, hash {l.PssHash}, salt {l.PssSalt}");
            }
        }
    }

    /// <summary>
    /// The PEM files keys come in: a certificate before the key (a combined file), OpenSSL's
    /// "EC PARAMETERS" block before an "EC PRIVATE KEY", explanatory text; and an "ENCRYPTED
    /// PRIVATE KEY", which answers -2 alone and lets a plain key after it load.
    /// </summary>
    [Fact]
    [Requirement("RFC7468-2-p9", "RFC7468-11-p1")]
    public void FindsTheKeyInAFile()
    {
        Platform.RequireLinuxX64();
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string key = ec.ExportPkcs8PrivateKeyPem();
        var request = new CertificateRequest("CN=key.example", ec, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        string cert = certificate.ExportCertificatePem();
        Assert.Equal(Abi.KeyP256, Load(cert + "\n" + key).Kind);
        Assert.Equal(Abi.KeyP256, Load("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" + ec.ExportECPrivateKeyPem()).Kind);
        Assert.Equal(Abi.KeyP256, Load("Bag Attributes\n    friendlyName: x\n" + key).Kind);

        string encrypted = ec.ExportEncryptedPkcs8PrivateKeyPem("password", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));
        Assert.Equal(-2, Load(encrypted).Kind);
        Assert.Equal(-2, Load(cert + encrypted).Kind);
        Assert.Equal(Abi.KeyP256, Load(encrypted + key).Kind);
        Assert.Equal(-1, Load(cert).Kind);                                    // no key at all
        Assert.Equal(-1, Load("no key here").Kind);
        Assert.Equal(-1, Load([]).Kind);
    }

    /// <summary>
    /// An EC key whose scalar a writer stored without its leading zero octets (OpenSSL before
    /// 1.1.0 did, one key in 256) loads padded: the same key, its public key .NET's.
    /// </summary>
    [Fact]
    public void LoadsShortEcScalars()
    {
        Platform.RequireLinuxX64();
        for (int attempt = 0; attempt < 5000; attempt++)
        {
            using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECParameters p = ec.ExportParameters(true);
            if (p.D![0] != 0)
            {
                continue;
            }

            byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
            byte[] sec1 = Der(0x30, Small(1), Der(0x04, p.D[1..]), Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. point])));
            Loaded k = Load(sec1);
            Assert.Equal(Abi.KeyP256, k.Kind);
            Assert.Equal(point, k.Public);
            return;
        }

        Assert.Fail("no scalar with a leading zero octet in 5000 keys");
    }

    /// <summary>
    /// What the loader refuses, each with the key left all zeros: X25519 keys (they sign nothing),
    /// unknown algorithms, multi-prime RSA keys, RSA numbers that do not make a key, negative
    /// numbers, EC scalars empty, 0 or n and above, a public key that is not the key's (another
    /// point; compressed with a prefix below 02, an octet short or another x; uncompressed an
    /// octet short), curves named otherwise than by a known OID (implicitCurve, specifiedCurve,
    /// another curve), curves that disagree, a public key given twice (PKCS#8 v2's and the
    /// ECPrivateKey's) in two encodings, even of one point, a public key longer than any curve's
    /// point, Edwards keys with parameters, of the wrong length, with a public key an octet
    /// short, or a BER seed longer than either key's, versions outside v1 and v2, a v1 key with
    /// a public key, trailing elements or octets, and a PEM label naming another format than the
    /// block holds.
    /// </summary>
    [Fact]
    [Requirement("RFC8410-3-p7", "RFC5480-2.1.1-p4", "RFC5480-2.1.1-p5", "RFC5480-2.1.1-p8", "RFC5480-2.1.1-p9", "RFC5480-2.2-p5", "RFC5480-2.2-p3#3")]
    public void RefusesWhatItCannotUse()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(2048);
        RSAParameters r = rsa.ExportParameters(true);
        byte[] seed = new byte[32];
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidX25519), Der(0x04, Der(0x04, seed)))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, [0x06, 0x03, 0x2A, 0x03, 0x04]), Der(0x04, Der(0x04, seed)))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEd25519, Null), Der(0x04, Der(0x04, seed)))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed[..31])))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEd448), Der(0x04, Der(0x04, seed)))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(2), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)), Der(0x81, new byte[33]))).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)), Der(0x04, []))).Kind);
        byte[] good = Der(0x30, Small(0), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)));
        Assert.Equal(Abi.KeyEd25519, Load(good).Kind);
        Assert.Equal(-1, Load([.. good, 0]).Kind);                                                 // trailing octet
        Assert.Equal(-1, Load(Der(0x30, Small(1), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)), Der(0x81, [0, .. new byte[32]]))).Kind); // not its public key
        Assert.Equal(-1, Load(Der(0x30, Small(1), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)), Der(0x81, [0, .. new byte[31]]))).Kind); // a public key an octet short
        // a BER-constructed seed of 64 octets: more than either key's (the gather has room for 57)
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEd448), Der(0x04, Der(0x24, Der(0x04, new byte[32]), Der(0x04, new byte[32]))))).Kind);

        // RSA: two primes only, every number positive and consistent
        byte[] Rsa(int version, byte[] dp) => Der(0x30, Small(version), Integer(r.Modulus!), Integer(r.Exponent!), Integer(r.D!),
            Integer(r.P!), Integer(r.Q!), Integer(dp), Integer(r.DQ!), Integer(r.InverseQ!));
        Assert.Equal(Abi.KeyRsa, Load(Rsa(0, r.DP!)).Kind);
        Assert.Equal(-1, Load(Rsa(1, r.DP!)).Kind);
        Assert.Equal(-1, Load(Rsa(0, r.DQ!)).Kind);                                                // inconsistent
        byte[] negative = Der(0x30, Small(0), Integer(r.Modulus!), Integer(r.Exponent!), Integer(r.D!), Integer(r.P!), Integer(r.Q!),
            Der(0x02, [0x80, .. r.DP!]), Integer(r.DQ!), Integer(r.InverseQ!));
        Assert.Equal(-1, Load(negative).Kind);
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidRsa, Der(0x04, [])), Der(0x04, Rsa(0, r.DP!)))).Kind); // parameters not NULL
        Assert.Equal(Abi.KeyRsa, Load(Der(0x30, Small(0), Der(0x30, OidRsa), Der(0x04, Rsa(0, r.DP!)))).Kind);     // parameters absent

        // EC
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters p = ec.ExportParameters(true);
        byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
        byte[] Sec1(byte[] d, params byte[][] tail) => Der(0x30, [.. Small(1), .. Der(0x04, d), .. tail.SelectMany(t => t)]);
        Assert.Equal(Abi.KeyP256, Load(Sec1(p.D!, Der(0xA0, OidP256))).Kind);
        Assert.Equal(-1, Load(Sec1(p.D!)).Kind);                                                   // no curve anywhere
        Assert.Equal(-1, Load(Sec1(new byte[32], Der(0xA0, OidP256))).Kind);                       // d = 0
        byte[] n = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        Assert.Equal(-1, Load(Sec1(n, Der(0xA0, OidP256))).Kind);                                  // d = n
        Assert.Equal(-1, Load(Sec1(new byte[33], Der(0xA0, OidP256))).Kind);                       // too long
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, Null))).Kind);                                  // implicitCurve
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, Der(0x30, Small(1))))).Kind);                   // specifiedCurve
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]))).Kind); // secp256k1
        Assert.Equal(-1, Load(Der(0x30, Small(0), Der(0x30, OidEc, [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]), Der(0x04, Sec1(p.D!, Der(0xA0, OidP256))))).Kind); // curves disagree
        byte[] wrong = (byte[])point.Clone();
        wrong[^1] ^= 1;
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. wrong])))).Kind);
        Assert.Equal(Abi.KeyP256, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. point])))).Kind);
        byte[] compressed = [(byte)(2 + (point[^1] & 1)), .. p.Q.X!];
        Assert.Equal(Abi.KeyP256, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. compressed])))).Kind);
        compressed[0] ^= 1;
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. compressed])))).Kind);
        byte[] hybrid = [(byte)(6 + (point[^1] & 1)), .. point[1..]];                            // X9.62's hybrid form
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. hybrid])))).Kind);
        byte[] other = [5, .. point[1..]];
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. other])))).Kind);
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, 1, .. p.Q.X!])))).Kind);       // a prefix below 02
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, 0, .. p.Q.X!])))).Kind);
        byte[] shortX = [(byte)(2 + (point[^1] & 1)), .. p.Q.X![..^1]];
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. shortX])))).Kind);         // compressed, an octet short
        byte[] otherX = [(byte)(2 + (point[^1] & 1)), .. p.Q.X!];
        otherX[^1] ^= 1;
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. otherX])))).Kind);         // compressed, another x
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. point[..^1]])))).Kind);    // uncompressed, an octet short
        Assert.Equal(-1, Load(Sec1([], Der(0xA0, OidP256))).Kind);                                                    // no scalar at all
        // the public key given twice, in PKCS#8 v2's [1] and in the ECPrivateKey's [1]: the same
        // octets loads; another form of the same point, or another point, does not
        byte[] TwoPublics(byte[] inner) =>
            Der(0x30, Small(1), Der(0x30, OidEc, OidP256), Der(0x04, Sec1(p.D!, Der(0xA1, Der(0x03, [0, .. inner])))), Der(0x81, [0, .. point]));
        Assert.Equal(Abi.KeyP256, Load(TwoPublics(point)).Kind);
        Assert.Equal(-1, Load(TwoPublics([(byte)(2 + (point[^1] & 1)), .. p.Q.X!])).Kind);         // the same point, compressed
        Assert.Equal(-1, Load(TwoPublics(wrong)).Kind);
        // a public key longer than any curve's point (the loader keeps 136 octets)
        Assert.Equal(-1, Load(Der(0x30, Small(1), Der(0x30, OidEd25519), Der(0x04, Der(0x04, seed)), Der(0x81, [0, .. new byte[200]]))).Kind);
        Assert.Equal(-1, Load(Sec1(p.D!, Der(0xA0, OidP256), Der(0xA1, Der(0x03, [0, .. point])), Der(0x05, []))).Kind); // trailing
        Assert.Equal(-1, Load(Der(0x30, Small(2), Der(0x04, p.D!), Der(0xA0, OidP256))).Kind);     // ECPrivateKey version 2

        // a PEM label naming another format than its block holds
        string pkcs8 = new(PemEncoding.Write("RSA PRIVATE KEY", ec.ExportPkcs8PrivateKey()));
        Assert.Equal(-1, Load(pkcs8).Kind);
    }

    /// <summary>
    /// Every structural mutation (<see cref="DerMutations"/>: each element removed, doubled,
    /// trailed, replaced, retagged, made unreadable, its value changed) of key files of every
    /// format and kind: PKCS#8 RSA, a PSS key bound to its parameters, PKCS#1, PKCS#8 v2 P-256
    /// with attributes and its public key, SEC1 with its curve and public key, PKCS#8 v2 Ed25519
    /// with its public key, and Ed448. Each is refused with the key left all zeros (Load checks
    /// it), or loads a key that still holds together: the original's kind, its public key of
    /// the kind's length, and an RSA key signing what its own public part verifies. No mutation
    /// is allowed to load a different kind of key, or a key half made.
    /// </summary>
    [Fact]
    public void SurvivesEveryMutationOfItsElements()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(1024);
        byte[] pkcs1 = rsa.ExportRSAPrivateKey();
        byte[] sha256 = Der(0x30, OidSha256, Null);
        byte[] pssParameters = Der(0x30, Der(0xA0, sha256), Der(0xA1, Der(0x30, OidMgf1, sha256)), Der(0xA2, Small(32)));
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters p = ec.ExportParameters(true);
        byte[] point = [4, .. p.Q.X!, .. p.Q.Y!];
        byte[] attributes = Der(0xA0, Der(0x30, [0x06, 0x03, 0x2A, 0x03, 0x04], Der(0x31, Null)));
        byte[] edSeed = Convert.FromHexString("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");
        byte[] edPublic = Convert.FromHexString("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");
        byte[] ed448Seed = Convert.FromHexString("6C82A562CB808D10D632BE89C8513EBF6C929F34DDFA8C9F63C9960EF6E348A3528C8A3FCC2F044E39A3FC5B94492F8F032E7549A20098F95B");
        byte[][] files =
        [
            rsa.ExportPkcs8PrivateKey(),
            Der(0x30, Small(0), Der(0x30, OidPss, pssParameters), Der(0x04, pkcs1)),
            pkcs1,
            Der(0x30, Small(1), Der(0x30, OidEc, OidP256), Der(0x04, ec.ExportECPrivateKey()), attributes, Der(0x81, [0, .. point])),
            ec.ExportECPrivateKey(),
            Der(0x30, Small(1), Der(0x30, OidEd25519), Der(0x04, Der(0x04, edSeed)), Der(0x81, [0, .. edPublic])),
            Der(0x30, Small(0), Der(0x30, OidEd448), Der(0x04, Der(0x04, ed448Seed))),
        ];
        int mutations = 0, loaded = 0;
        byte[] digest = SHA256.HashData("signed by a mutated key"u8);
        foreach (byte[] file in files)
        {
            Loaded original = Load(file);
            Assert.True(original.Kind > 0, "a fixture that does not load");
            foreach ((string name, byte[] mutated) in DerMutations.Of(file))
            {
                mutations++;
                Loaded k = Load(mutated);
                if (k.Kind < 0)
                {
                    continue;                   // refused, all zeros (Load asserted it)
                }

                loaded++;
                Assert.True(k.Kind == original.Kind, $"{name}: kind {k.Kind}, not {original.Kind}");
                Assert.True(k.Public.Length == original.Public.Length, $"{name}: a public key of {k.Public.Length} octets");
                if (k.Kind <= Abi.KeyRsaPss)
                {
                    byte[] signature = new byte[(k.Bits + 7) / 8];
                    fixed (byte* key = k.Key)
                    fixed (byte* d = digest)
                    fixed (byte* s = signature)
                    {
                        var prepared = (RsaPrivateKey*)(key + SecretOffset);
                        Assert.True(Native.RsaSignPkcs1(prepared, Abi.HashSha256, d, s, (nuint)signature.Length) == 0, $"{name}: does not sign");
                        Assert.True(Native.RsaVerifyPkcs1((RsaPublicKey*)prepared, Abi.HashSha256, d, s, (nuint)signature.Length) == 0,
                            $"{name}: its signature does not verify under its own public part");
                    }
                }
            }
        }

        // the mutations reached every file deeply (a parser change that stopped walking into
        // the nested DER would leave a handful)
        Assert.True(mutations > 700, $"{mutations} mutations");             // 788 when written
        Assert.True(loaded < mutations / 4, $"{loaded} of {mutations} loaded");
    }

    /// <summary>Every prefix of real key files is refused, never read past: each is placed at the
    /// end of a page before a guard page.</summary>
    [Fact]
    public void NeverReadsPastTheFile()
    {
        Platform.RequireLinuxX64();
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[][] files = [ec.ExportPkcs8PrivateKey(), ec.ExportECPrivateKey(), Encoding.ASCII.GetBytes(ec.ExportPkcs8PrivateKeyPem())];
        foreach (byte[] file in files)
        {
            Assert.Equal(Abi.KeyP256, Load(file).Kind);
            for (int n = 0; n < file.Length; n++)
            {
                Assert.True(Load(file[..n]).Kind < 0, $"a prefix of {n} octets loaded");
            }
        }
    }
}
