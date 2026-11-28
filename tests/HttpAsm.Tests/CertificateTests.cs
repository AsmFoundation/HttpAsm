using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static HttpAsm.Tests.KeyTests;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_certificate_read, httpasm_public_key_read and httpasm_private_key_matches
/// (asn1/x509.asm) through the C ABI: certificates .NET makes (RSA, the three curves, with and
/// without extensions, times on both sides of 2050) read field for field as .NET's X509Certificate2
/// reads them, their public keys prepared and paired with the private keys .NET exported;
/// OpenSSL's Ed25519 certificate and RFC 8410's X25519 one; the unique identifiers of v2 and v3;
/// public key infos of every kind (the PSS parameters by the table the private keys' reader is
/// held to, KeyTests.PssCases); every pairing of keys of every kind; and every structural refusal
/// of a certificate and of a public key info, each element in turn unreadable, retagged, missing,
/// doubled or trailed.
/// </summary>
public sealed unsafe class CertificateTests
{
    /// <summary>What a certificate read returned, as offsets into its DER.</summary>
    /// <param name="Status">0 or -1.</param>
    /// <param name="Fields">The structure's fields (pointers made offsets; -1 for a NULL one).</param>
    /// <param name="NotBefore">The validity's start, in seconds since 1970.</param>
    /// <param name="NotAfter">Its end.</param>
    /// <param name="Version">1, 2 or 3.</param>
    private readonly record struct ReadCertificate(int Status, Dictionary<string, (long Offset, long Length)> Fields, long NotBefore, long NotAfter, uint Version);

    /// <summary>Reads a certificate placed at the end of a page before a guard page.</summary>
    /// <param name="der">The certificate.</param>
    /// <returns>The status and the fields.</returns>
    private static ReadCertificate Read(byte[] der)
    {
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(der);
        Certificate c;
        int status = Native.CertificateRead(&c, at, (nuint)der.Length);
        var fields = new Dictionary<string, (long, long)>();
        if (status == 0)
        {
            (long, long) Of(byte* p, nuint n) => p == null ? (-1, 0) : (p - at, (long)n);
            fields["tbs"] = Of(c.Tbs, c.TbsLength);
            fields["serial"] = Of(c.Serial, c.SerialLength);
            fields["issuer"] = Of(c.Issuer, c.IssuerLength);
            fields["subject"] = Of(c.Subject, c.SubjectLength);
            fields["spki"] = Of(c.Spki, c.SpkiLength);
            fields["extensions"] = Of(c.Extensions, c.ExtensionsLength);
            fields["signatureAlgorithm"] = Of(c.SignatureAlgorithm, c.SignatureAlgorithmLength);
            fields["signature"] = Of(c.Signature, c.SignatureLength);
        }

        return new ReadCertificate(status, fields, c.NotBefore, c.NotAfter, c.Version);
    }

    /// <summary>The octets of a field of a read certificate.</summary>
    /// <param name="der">The certificate.</param>
    /// <param name="r">The read.</param>
    /// <param name="name">The field.</param>
    /// <returns>Its octets.</returns>
    private static byte[] Field(byte[] der, ReadCertificate r, string name) =>
        der[(int)r.Fields[name].Offset..(int)(r.Fields[name].Offset + r.Fields[name].Length)];

    /// <summary>Reads a public key info: the answer and the key's octets.</summary>
    /// <param name="spki">The SubjectPublicKeyInfo.</param>
    /// <returns>The kind (or -1) and the structure's octets.</returns>
    private static (int Kind, byte[] Key) ReadKey(byte[] spki)
    {
        byte[] key = new byte[sizeof(PublicKey)];
        Array.Fill(key, (byte)0xEE);
        using var guard = new GuardedBuffer();
        byte* at = guard.AtPageEnd(spki);
        int kind;
        fixed (byte* k = key)
        {
            kind = Native.PublicKeyRead((PublicKey*)k, at, (nuint)spki.Length);
        }

        if (kind < 0)
        {
            Assert.True(key.All(b => b == 0), "a refused public key was not left all zeros");
        }

        return (kind, key);
    }

    /// <summary>Whether a private key's file and a public key info are one pair, by the library.</summary>
    /// <param name="privateFile">The private key's file.</param>
    /// <param name="spki">The public key info.</param>
    /// <returns>httpasm_private_key_matches's answer.</returns>
    private static int Matches(byte[] privateFile, byte[] spki)
    {
        var key = new PrivateKey();
        var pub = new PublicKey();
        fixed (byte* f = privateFile)
        fixed (byte* s = spki)
        {
            Assert.True(Native.PrivateKeyLoad(&key, f, (nuint)privateFile.Length) > 0);
            Assert.True(Native.PublicKeyRead(&pub, s, (nuint)spki.Length) > 0);
            return Native.PrivateKeyMatches(&key, &pub);
        }
    }

    /// <summary>
    /// The .NET copies of httpasm_certificate and httpasm_public_key have the library's sizes,
    /// 152 and 2248 octets, under struct ids 26 and 27, the registry's last: id 28 answers 0, as
    /// any id past the registry does (the end check moves to the newest structure's tests each
    /// time one is added).
    /// </summary>
    [Fact]
    public void StructuresMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(152, sizeof(Certificate));
        Assert.Equal(2248, sizeof(PublicKey));
        Assert.Equal((uint)sizeof(Certificate), Native.StructSize(26));
        Assert.Equal((uint)sizeof(PublicKey), Native.StructSize(27));
        Assert.Equal(0u, Native.StructSize(28));
    }

    /// <summary>A self-signed certificate .NET makes with a key, its validity given, with or
    /// without extensions (basic constraints, key usage, a subject alternative name).</summary>
    /// <param name="key">The RSA or ECDSA key.</param>
    /// <param name="notBefore">The validity's start.</param>
    /// <param name="notAfter">Its end.</param>
    /// <param name="extensions">Whether to add the extensions.</param>
    /// <returns>The certificate's DER.</returns>
    /// <exception cref="ArgumentException">The key is neither RSA nor ECDSA.</exception>
    private static byte[] SelfSigned(AsymmetricAlgorithm key, DateTimeOffset notBefore, DateTimeOffset notAfter, bool extensions)
    {
        var name = new X500DistinguishedName("CN=cert.example, O=HttpAsm, C=US");
        CertificateRequest request = key switch
        {
            RSA rsa => new CertificateRequest(name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ec => new CertificateRequest(name, ec, HashAlgorithmName.SHA384),
            _ => throw new ArgumentException("an RSA or ECDSA key", nameof(key)),
        };
        if (extensions)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("cert.example");
            request.CertificateExtensions.Add(san.Build());
        }

        using X509Certificate2 certificate = request.CreateSelfSigned(notBefore, notAfter);
        return certificate.RawData;
    }

    /// <summary>
    /// Certificates .NET makes, RSA and ECDSA on each curve, with and without extensions, valid
    /// from before 1970's epoch to after 2050 (UTCTime and GeneralizedTime both): each reads
    /// field for field as X509Certificate2 reads it (version, serial number, issuer and subject,
    /// public key info, the outer signature algorithm and signature, the times as seconds), its
    /// public key prepared, its kind and size the key's, and paired with the private key .NET
    /// exports and with no other.
    /// </summary>
    /// <param name="algorithm">"rsa", "p256", "p384" or "p521".</param>
    [Theory]
    [InlineData("rsa")]
    [InlineData("p256")]
    [InlineData("p384")]
    [InlineData("p521")]
    [Requirement("RFC5280-4.1.2.1-p2#2", "RFC5280-4.1.2.5-p2#3", "RFC5280-4.1.2.5.1-p3", "RFC5280-4.1.2.5.1-p4", "RFC7468-5.1-p1")]
    public void ReadsCertificatesAsDotNetDoes(string algorithm)
    {
        Platform.RequireLinuxX64();
        ECCurve curve = algorithm switch
        {
            "p384" => ECCurve.NamedCurves.nistP384,
            "p521" => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256,
        };
        using AsymmetricAlgorithm key = algorithm == "rsa" ? RSA.Create(2048) : ECDsa.Create(curve);
        (int kind, uint bits) = algorithm switch
        {
            "rsa" => (Abi.KeyRsa, 2048u),
            "p256" => (Abi.KeyP256, 256u),
            "p384" => (Abi.KeyP384, 384u),
            _ => (Abi.KeyP521, 521u),
        };
        var validities = new (DateTimeOffset, DateTimeOffset)[]
        {
            (new DateTimeOffset(2024, 2, 29, 12, 34, 56, TimeSpan.Zero), new DateTimeOffset(2049, 12, 31, 23, 59, 59, TimeSpan.Zero)),
            (new DateTimeOffset(1955, 3, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2050, 1, 1, 0, 0, 0, TimeSpan.Zero)),
            (new DateTimeOffset(2026, 11, 28, 1, 2, 3, TimeSpan.Zero), new DateTimeOffset(2400, 2, 29, 0, 0, 0, TimeSpan.Zero)),
        };
        foreach ((DateTimeOffset from, DateTimeOffset to) in validities)
        {
            foreach (bool extensions in new[] { false, true })
            {
                byte[] der = SelfSigned(key, from, to, extensions);
                using var dotnet = X509CertificateLoader.LoadCertificate(der);
                ReadCertificate r = Read(der);
                Assert.Equal(0, r.Status);
                Assert.Equal((uint)dotnet.Version, r.Version);
                Assert.Equal(dotnet.SerialNumberBytes.ToArray(), Field(der, r, "serial"));
                Assert.Equal(dotnet.IssuerName.RawData, Field(der, r, "issuer"));
                Assert.Equal(dotnet.SubjectName.RawData, Field(der, r, "subject"));
                Assert.Equal(dotnet.PublicKey.ExportSubjectPublicKeyInfo(), Field(der, r, "spki"));
                Assert.Equal(from.ToUnixTimeSeconds(), r.NotBefore);
                Assert.Equal(to.ToUnixTimeSeconds(), r.NotAfter);
                Assert.Equal(extensions ? 1 : -1, Math.Sign(r.Fields["extensions"].Offset));

                // the TBS is what the signature covers: .NET's key verifies it over these octets
                byte[] tbs = Field(der, r, "tbs");
                byte[] signature = Field(der, r, "signature");
                Assert.True(key switch
                {
                    RSA rsa => rsa.VerifyData(tbs, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                    ECDsa ec => ec.VerifyData(tbs, signature, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence),
                    _ => false,
                });

                (int k, byte[] pub) = ReadKey(Field(der, r, "spki"));
                Assert.Equal(kind, k);
                Assert.Equal(bits, BitConverter.ToUInt32(pub, 4));
            }
        }

        byte[] one = SelfSigned(key, validities[0].Item1, validities[0].Item2, false);
        byte[] spki = Field(one, Read(one), "spki");
        byte[] own = key switch { RSA rsa => rsa.ExportPkcs8PrivateKey(), ECDsa ec => ec.ExportPkcs8PrivateKey(), _ => [] };
        Assert.Equal(0, Matches(own, spki));
        using AsymmetricAlgorithm other = algorithm == "rsa" ? RSA.Create(2048) : ECDsa.Create(curve);
        byte[] otherFile = other switch { RSA rsa => rsa.ExportPkcs8PrivateKey(), ECDsa ec => ec.ExportPkcs8PrivateKey(), _ => [] };
        Assert.Equal(-1, Matches(otherFile, spki));
    }

    /// <summary>
    /// RFC 8410's example certificate (10.2: an X25519 key signed with Ed25519) reads, while its
    /// key, one that signs nothing, is refused by httpasm_public_key_read; and an Ed25519
    /// certificate of RFC 8410's private key, built here and signed by the library (.NET makes no
    /// Ed25519 certificate), reads with its times (UTCTime and GeneralizedTime), its TBS the
    /// signed octets, its key Ed25519's 32 octets, paired with the private key.
    /// </summary>
    [Fact]
    public void ReadsEdwardsAndRfc8410Certificates()
    {
        Platform.RequireLinuxX64();
        byte[] rfc8410 = Convert.FromBase64String(
            "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZXN0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQDDA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAgBgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cgw1AH9efZBw==");
        Assert.Equal(-1, Read(rfc8410).Status);
        // its keyUsage and subjectKeyIdentifier encode critical FALSE, the DEFAULT, which DER
        // omits (X.690 11.5): with the two FALSE BOOLEANs taken out (and the lengths around
        // them), it reads, and its key, an X25519 key, which signs nothing, is refused
        byte[] fixedCert = WithoutFalseCritical(rfc8410);
        ReadCertificate r = Read(fixedCert);
        Assert.Equal((0, 3u), (r.Status, r.Version));
        Assert.Equal(-1, ReadKey(Field(fixedCert, r, "spki")).Kind);

        // an Ed25519 certificate of RFC 8410's key, signed by the library (.NET makes none)
        byte[] seed = Convert.FromHexString("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");
        byte[] publicKey = Convert.FromHexString("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");
        byte[] algorithm = KeyTests.Der(0x30, [0x06, 0x03, 0x2B, 0x65, 0x70]);
        byte[] name = KeyTests.Der(0x30, KeyTests.Der(0x31, KeyTests.Der(0x30, [0x06, 0x03, 0x55, 0x04, 0x03], KeyTests.Der(0x0C, Encoding.ASCII.GetBytes("ed.example")))));
        byte[] validity = KeyTests.Der(0x30, KeyTests.Der(0x17, Encoding.ASCII.GetBytes("260101000000Z")), KeyTests.Der(0x18, Encoding.ASCII.GetBytes("20500101000000Z")));
        byte[] spki = KeyTests.Der(0x30, algorithm, KeyTests.Der(0x03, [0, .. publicKey]));
        byte[] tbs = KeyTests.Der(0x30, KeyTests.Der(0xA0, [0x02, 0x01, 0x02]), [0x02, 0x01, 0x07], algorithm, name, validity, name, spki);
        byte[] signature = new byte[64];
        Ed25519PrivateKey prepared;
        fixed (byte* s = seed)
        fixed (byte* t = tbs)
        fixed (byte* sig = signature)
        {
            Native.Ed25519PrivateKeyInit(&prepared, s);
            Native.Ed25519Sign(sig, &prepared, t, (nuint)tbs.Length);
        }

        byte[] certificate = KeyTests.Der(0x30, tbs, algorithm, KeyTests.Der(0x03, [0, .. signature]));
        r = Read(certificate);
        Assert.Equal((0, 3u), (r.Status, r.Version));
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds(), r.NotBefore);
        Assert.Equal(new DateTimeOffset(2050, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds(), r.NotAfter);
        Assert.Equal(tbs, Field(certificate, r, "tbs"));
        fixed (byte* pk = publicKey)
        fixed (byte* t = tbs)
        fixed (byte* sig = signature)
        {
            Assert.Equal(0, Native.Ed25519Verify(pk, t, (nuint)tbs.Length, sig));
        }

        (int kind, byte[] key) = ReadKey(Field(certificate, r, "spki"));
        Assert.Equal(Abi.KeyEd25519, kind);
        Assert.Equal(publicKey, key[32..64]);
        byte[] pkcs8 = KeyTests.Der(0x30, [0x02, 0x01, 0x00], algorithm, KeyTests.Der(0x04, KeyTests.Der(0x04, seed)));
        Assert.Equal(0, Matches(pkcs8, spki));
    }

    /// <summary>RFC 8410 10.3's Ed25519 private key (the seed).</summary>
    private static readonly byte[] Ed25519Seed = Convert.FromHexString("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842");

    /// <summary>Its public key (RFC 8410 10.1's).</summary>
    private static readonly byte[] Ed25519Public = Convert.FromHexString("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");

    /// <summary>RFC 8032 7.4's first Ed448 private key (the seed, 57 octets).</summary>
    private static readonly byte[] Ed448Seed = Convert.FromHexString("6C82A562CB808D10D632BE89C8513EBF6C929F34DDFA8C9F63C9960EF6E348A3528C8A3FCC2F044E39A3FC5B94492F8F032E7549A20098F95B");

    /// <summary>Its public key.</summary>
    private static readonly byte[] Ed448Public = Convert.FromHexString("5FD7449B59B461FD2CE787EC616AD46A1DA1342485A70E1F8A0EA75D80E96778EDF124769B46C7061BD6783DF1E50F6CD1FA1ABEAFE8256180");

    /// <summary>A SubjectPublicKeyInfo: SEQUENCE { the algorithm, BIT STRING of whole octets }.</summary>
    /// <param name="algorithm">The AlgorithmIdentifier's whole encoding.</param>
    /// <param name="key">The subjectPublicKey's octets.</param>
    /// <returns>The DER.</returns>
    private static byte[] Spki(byte[] algorithm, byte[] key) => Der(0x30, algorithm, Der(0x03, [0, .. key]));

    /// <summary>An RSA key's RSAPublicKey { n, e } from its numbers.</summary>
    /// <param name="n">The modulus' magnitude.</param>
    /// <param name="e">The exponent's.</param>
    /// <returns>The DER.</returns>
    private static byte[] RsaKeyDer(byte[] n, byte[] e) => Der(0x30, Integer(n), Integer(e));

    /// <summary>
    /// Public key infos of every kind the reader takes: .NET's RSA keys at 2048 and 4096 bits as
    /// rsaEncryption (parameters NULL) and the same keys as id-RSASSA-PSS (no parameters: any
    /// hash), each prepared so that .NET's PKCS#1 signature verifies under it and a changed one
    /// does not; .NET's keys on the three curves, the point kept as the info's octets; RFC 8410's
    /// Ed25519 key and RFC 8032's Ed448 key. Each read twice into the same structure gives the
    /// same octets (nothing of a former read remains).
    /// </summary>
    [Fact]
    [Requirement("RFC4055-1.2-p3#1", "RFC4055-1.2-p6#1", "RFC4055-1.2-p9", "RFC5480-2.1.1-p7", "RFC5480-2.2-p3#1", "RFC8410-3-p7")]
    public void ReadsPublicKeyInfos()
    {
        Platform.RequireLinuxX64();
        byte[] digest = SHA256.HashData("public key infos"u8);
        foreach (int size in new[] { 2048, 4096 })
        {
            using RSA rsa = RSA.Create(size);
            byte[] signature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var infos = new (byte[] Spki, int Kind)[]
            {
                (rsa.ExportSubjectPublicKeyInfo(), Abi.KeyRsa),
                (Spki(Der(0x30, OidPss), rsa.ExportRSAPublicKey()), Abi.KeyRsaPss),
            };
            foreach ((byte[] spki, int kind) in infos)
            {
                (int k, byte[] key) = ReadKey(spki);
                Assert.Equal((kind, (uint)size, 0u, 0u), (k, BitConverter.ToUInt32(key, 4), BitConverter.ToUInt32(key, 8), BitConverter.ToUInt32(key, 16)));
                Assert.Equal(key, ReadKey(spki).Key);
                byte[] changed = (byte[])signature.Clone();
                changed[^1] ^= 1;
                fixed (byte* p = key)
                fixed (byte* d = digest)
                fixed (byte* s = signature)
                fixed (byte* c = changed)
                {
                    // the prepared key starts after the 168 octets of kind, sizes and point
                    Assert.Equal(0, Native.RsaVerifyPkcs1((RsaPublicKey*)(p + 168), Abi.HashSha256, d, s, (nuint)signature.Length));
                    Assert.Equal(-1, Native.RsaVerifyPkcs1((RsaPublicKey*)(p + 168), Abi.HashSha256, d, c, (nuint)changed.Length));
                }
            }
        }

        var curves = new (ECCurve Curve, int Kind, uint Bits)[]
        {
            (ECCurve.NamedCurves.nistP256, Abi.KeyP256, 256),
            (ECCurve.NamedCurves.nistP384, Abi.KeyP384, 384),
            (ECCurve.NamedCurves.nistP521, Abi.KeyP521, 521),
        };
        foreach ((ECCurve curve, int kind, uint bits) in curves)
        {
            using ECDsa ec = ECDsa.Create(curve);
            ECParameters q = ec.ExportParameters(false);
            byte[] point = [4, .. q.Q.X!, .. q.Q.Y!];
            (int k, byte[] key) = ReadKey(ec.ExportSubjectPublicKeyInfo());
            Assert.Equal((kind, bits, (uint)point.Length), (k, BitConverter.ToUInt32(key, 4), BitConverter.ToUInt32(key, 16)));
            Assert.Equal(point, key[32..(32 + point.Length)]);
        }

        (int ed, byte[] edKey) = ReadKey(Spki(Der(0x30, OidEd25519), Ed25519Public));
        Assert.Equal((Abi.KeyEd25519, 256u, 32u), (ed, BitConverter.ToUInt32(edKey, 4), BitConverter.ToUInt32(edKey, 16)));
        Assert.Equal(Ed25519Public, edKey[32..64]);
        (ed, edKey) = ReadKey(Spki(Der(0x30, OidEd448), Ed448Public));
        Assert.Equal((Abi.KeyEd448, 448u, 57u), (ed, BitConverter.ToUInt32(edKey, 4), BitConverter.ToUInt32(edKey, 16)));
        Assert.Equal(Ed448Public, edKey[32..89]);
    }

    /// <summary>
    /// id-RSASSA-PSS public key infos with each case of <see cref="KeyTests.PssCases"/> as their
    /// parameters: bound to the hash and salt the case names, or refused, exactly as the private
    /// keys' reader answers (KeyTests.LoadsPssKeysAndTheirParameters), so a key pair's two halves
    /// can never disagree on what they sign.
    /// </summary>
    [Fact]
    [Requirement("RFC4055-1.2-p6#2", "RFC4055-3.1-p1#1")]
    public void ReadsPssPublicKeysAndTheirParameters()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(2048);
        byte[] rsaPublicKey = rsa.ExportRSAPublicKey();
        foreach (PssCase c in PssCases())
        {
            (int kind, byte[] key) = ReadKey(Spki(Der(0x30, OidPss, c.Parameters), rsaPublicKey));
            if (c.Hash < 0)
            {
                Assert.True(kind == -1, $"{c.Name}: read as kind {kind}");
            }
            else
            {
                (uint hash, uint salt) = (BitConverter.ToUInt32(key, 8), BitConverter.ToUInt32(key, 12));
                Assert.True((Abi.KeyRsaPss, (uint)c.Hash, c.Salt) == (kind, hash, salt), $"{c.Name}: kind {kind}, hash {hash}, salt {salt}");
            }
        }
    }

    /// <summary>
    /// What a public key info must not be, each refused with the structure left all zeros: the
    /// outer shape (not a SEQUENCE, empty, a trailing octet or element, the algorithm or the key
    /// missing, unreadable, or of another type, the key's BIT STRING with unused bits), the
    /// algorithm's (not a SEQUENCE, its identifier not an OBJECT IDENTIFIER, three elements,
    /// unknown, X25519), RSA's (rsaEncryption's parameters absent or not NULL, RSAPublicKey of
    /// the wrong shape, a number negative, unreadable or of another type, numbers the preparation
    /// refuses: an even modulus or exponent, an exponent of 1 or over 2^64 - 1, a modulus of 1023
    /// or 8200 bits), the curves' (no curve, implicitCurve, specifiedCurve, another curve, a point
    /// compressed, hybrid, of another first octet, of the wrong length, another curve's point)
    /// and the Edwards keys' (parameters, a key a octet short or long, one curve's key under the
    /// other's identifier).
    /// </summary>
    [Fact]
    [Requirement("RFC4055-1.2-p3#2", "RFC5480-2.1.1-p4", "RFC5480-2.1.1-p5", "RFC5480-2.1.1-p8", "RFC5480-2.1.1-p9", "RFC5480-2.1.1-p11", "RFC5480-2.2-p3#3", "RFC5480-2.2-p5", "RFC8410-3-p7")]
    public void RefusesPublicKeyInfosThatBreakARule()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(2048);
        RSAParameters r = rsa.ExportParameters(false);
        byte[] n = r.Modulus!, e = r.Exponent!;
        byte[] rsaAlg = Der(0x30, OidRsa, Null);
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters q = ec.ExportParameters(false);
        byte[] point = [4, .. q.Q.X!, .. q.Q.Y!];
        byte[] ecAlg = Der(0x30, OidEc, OidP256);
        byte[] bits = Der(0x03, [0, .. point]);
        byte[] good = Der(0x30, ecAlg, bits);
        Assert.Equal(Abi.KeyP256, ReadKey(good).Kind);
        Assert.Equal(Abi.KeyRsa, ReadKey(Spki(rsaAlg, RsaKeyDer(n, e))).Kind);

        byte[] even = (byte[])n.Clone();
        even[^1] &= 0xFE;
        byte[] short1023 = [0x7F, .. Enumerable.Repeat((byte)0xFF, 127)];
        byte[] long8200 = [.. Enumerable.Repeat((byte)0xFF, 1025)];
        byte[] unusedBits = [1, .. point[..^1], (byte)(point[^1] & 0xFE)];
        var cases = new Dictionary<string, byte[]>
        {
            ["not a SEQUENCE"] = Der(0x31, ecAlg, bits),
            ["empty"] = [],
            ["a trailing octet"] = [.. good, 0],
            ["an element after the key"] = Der(0x30, ecAlg, bits, Null),
            ["the key missing"] = Der(0x30, ecAlg),
            ["the algorithm missing"] = Der(0x30, bits),
            ["the key not a BIT STRING"] = Der(0x30, ecAlg, Der(0x04, point)),
            ["the key's unused bits"] = Der(0x30, ecAlg, Der(0x03, unusedBits)),
            ["the key that does not read"] = Der(0x30, ecAlg, [0x03, 0x10]),
            ["the algorithm that does not read"] = Der(0x30, [0x30, 0x10], bits),
            ["the algorithm not a SEQUENCE"] = Der(0x30, Der(0x31, OidEc, OidP256), bits),
            ["the algorithm's identifier not an OBJECT IDENTIFIER"] = Der(0x30, Der(0x30, Null, OidP256), bits),
            ["the algorithm's identifier that does not read"] = Der(0x30, Der(0x30, [0x06, 0x10]), bits),
            ["the algorithm's parameters that do not read"] = Der(0x30, Der(0x30, [.. OidEc, 0x06, 0x10]), bits),
            ["the algorithm of three elements"] = Der(0x30, Der(0x30, OidEc, OidP256, Null), bits),
            ["an unknown algorithm"] = Spki(Der(0x30, [0x06, 0x03, 0x2A, 0x03, 0x04]), point),
            ["an X25519 key"] = Spki(Der(0x30, OidX25519), Ed25519Public),
            ["rsaEncryption without parameters"] = Spki(Der(0x30, OidRsa), RsaKeyDer(n, e)),
            ["rsaEncryption's parameters not NULL"] = Spki(Der(0x30, OidRsa, Der(0x04, [])), RsaKeyDer(n, e)),
            ["RSAPublicKey not a SEQUENCE"] = Spki(rsaAlg, Der(0x31, Integer(n), Integer(e))),
            ["RSAPublicKey followed by more"] = Spki(rsaAlg, [.. RsaKeyDer(n, e), .. Null]),
            ["RSAPublicKey that does not read"] = Spki(rsaAlg, [0x30, 0x10]),
            ["RSAPublicKey of one INTEGER"] = Spki(rsaAlg, Der(0x30, Integer(n))),
            ["RSAPublicKey of three INTEGERs"] = Spki(rsaAlg, Der(0x30, Integer(n), Integer(e), Small(1))),
            ["a modulus that does not read"] = Spki(rsaAlg, Der(0x30, [0x02, 0x10])),
            ["an exponent that does not read"] = Spki(rsaAlg, Der(0x30, [.. Integer(n), 0x02, 0x10])),
            ["a modulus not an INTEGER"] = Spki(rsaAlg, Der(0x30, Der(0x04, n), Integer(e))),
            ["an exponent not an INTEGER"] = Spki(rsaAlg, Der(0x30, Integer(n), Der(0x04, e))),
            ["a negative modulus"] = Spki(rsaAlg, Der(0x30, Der(0x02, [0x80, .. n[1..]]), Integer(e))),   // (0x80 first: DER's fewest octets still)
            ["a negative exponent"] = Spki(rsaAlg, Der(0x30, Integer(n), Der(0x02, [0x80, 0x01]))),
            ["an even modulus"] = Spki(rsaAlg, RsaKeyDer(even, e)),
            ["an even exponent"] = Spki(rsaAlg, RsaKeyDer(n, [1, 0, 0])),
            ["an exponent of 1"] = Spki(rsaAlg, RsaKeyDer(n, [1])),
            ["an exponent over 2^64 - 1"] = Spki(rsaAlg, RsaKeyDer(n, [1, 0, 0, 0, 0, 0, 0, 0, 1])),
            ["a modulus of 1023 bits"] = Spki(rsaAlg, RsaKeyDer(short1023, e)),
            ["a modulus of 8200 bits"] = Spki(rsaAlg, RsaKeyDer(long8200, e)),
            ["id-ecPublicKey without a curve"] = Spki(Der(0x30, OidEc), point),
            ["implicitCurve"] = Spki(Der(0x30, OidEc, Null), point),
            ["specifiedCurve"] = Spki(Der(0x30, OidEc, Der(0x30, Small(1))), point),
            ["another curve (secp256k1)"] = Spki(Der(0x30, OidEc, OidSecp256k1), point),
            ["a compressed point"] = Spki(ecAlg, [(byte)(2 + (point[^1] & 1)), .. q.Q.X!]),
            ["a hybrid point"] = Spki(ecAlg, [(byte)(6 + (point[^1] & 1)), .. point[1..]]),
            ["a point of another first octet"] = Spki(ecAlg, [5, .. point[1..]]),
            ["a point an octet short"] = Spki(ecAlg, point[..^1]),
            ["a point an octet long"] = Spki(ecAlg, [.. point, 0]),
            ["a P-256 point named P-384"] = Spki(Der(0x30, OidEc, OidP384), point),
            ["a P-256 point named P-521"] = Spki(Der(0x30, OidEc, OidP521), point),
            ["Ed25519 with parameters"] = Spki(Der(0x30, OidEd25519, Null), Ed25519Public),
            ["an Ed25519 key an octet short"] = Spki(Der(0x30, OidEd25519), Ed25519Public[..31]),
            ["an Ed25519 key an octet long"] = Spki(Der(0x30, OidEd25519), [.. Ed25519Public, 0]),
            ["an Ed448 key an octet short"] = Spki(Der(0x30, OidEd448), Ed448Public[..56]),
            ["an Ed448 key named Ed25519"] = Spki(Der(0x30, OidEd25519), Ed448Public),
            ["an Ed25519 key named Ed448"] = Spki(Der(0x30, OidEd448), Ed25519Public),
        };
        foreach ((string name, byte[] spki) in cases)
        {
            Assert.True(ReadKey(spki).Kind == -1, $"{name}: read");
        }
    }

    /// <summary>
    /// httpasm_private_key_matches over every pairing of six private keys (RSA as rsaEncryption
    /// and as id-RSASSA-PSS, one key; P-256; P-384; Ed25519; Ed448) with their six public key
    /// infos: a pair exactly when both halves are one key (RSA's two identifiers pair either way:
    /// TLS picks the schemes by the certificate); and the structures a caller could pass that the
    /// library never fills: a refused private key's (all zeros), a refused public key's, and a
    /// public key whose length does not fit its kind, each never a pair.
    /// </summary>
    [Fact]
    public void PairsOnlyTheHalvesOfOneKey()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(2048);
        using ECDsa p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        // (the private key's file, the public key info, which key they are)
        var keys = new (byte[] File, byte[] Spki, int Key)[]
        {
            (rsa.ExportPkcs8PrivateKey(), rsa.ExportSubjectPublicKeyInfo(), 0),
            (Der(0x30, Small(0), Der(0x30, OidPss), Der(0x04, rsa.ExportRSAPrivateKey())), Spki(Der(0x30, OidPss), rsa.ExportRSAPublicKey()), 0),
            (p256.ExportPkcs8PrivateKey(), p256.ExportSubjectPublicKeyInfo(), 1),
            (p384.ExportPkcs8PrivateKey(), p384.ExportSubjectPublicKeyInfo(), 2),
            (Der(0x30, Small(0), Der(0x30, OidEd25519), Der(0x04, Der(0x04, Ed25519Seed))), Spki(Der(0x30, OidEd25519), Ed25519Public), 3),
            (Der(0x30, Small(0), Der(0x30, OidEd448), Der(0x04, Der(0x04, Ed448Seed))), Spki(Der(0x30, OidEd448), Ed448Public), 4),
        };
        foreach ((byte[] file, _, int key) in keys)
        {
            foreach ((_, byte[] spki, int other) in keys)
            {
                Assert.Equal(key == other ? 0 : -1, Matches(file, spki));
            }
        }

        var zeroKey = default(PrivateKey);
        var zeroPublic = default(PublicKey);
        var loaded = default(PrivateKey);
        var read = default(PublicKey);
        byte[] p256File = keys[2].File, p256Spki = keys[2].Spki, rsaFile = keys[0].File;
        fixed (byte* f = p256File)
        fixed (byte* s = p256Spki)
        fixed (byte* rf = rsaFile)
        {
            Assert.Equal(Abi.KeyP256, Native.PrivateKeyLoad(&loaded, f, (nuint)p256File.Length));
            Assert.Equal(Abi.KeyP256, Native.PublicKeyRead(&read, s, (nuint)p256Spki.Length));
            Assert.Equal(0, Native.PrivateKeyMatches(&loaded, &read));
            Assert.Equal(-1, Native.PrivateKeyMatches(&zeroKey, &read));
            Assert.Equal(-1, Native.PrivateKeyMatches(&loaded, &zeroPublic));
            Assert.Equal(-1, Native.PrivateKeyMatches(&zeroKey, &zeroPublic));
            read.PointLength = 64;                  // a P-256 key's length is 65: a structure the library never fills
            Assert.Equal(-1, Native.PrivateKeyMatches(&loaded, &read));
            Assert.Equal(Abi.KeyRsa, Native.PrivateKeyLoad(&loaded, rf, (nuint)rsaFile.Length));
            Assert.Equal(-1, Native.PrivateKeyMatches(&loaded, &zeroPublic));
        }
    }

    /// <summary>
    /// The unique identifiers (RFC 5280 4.1.2.8: applications SHOULD parse them): a v2
    /// certificate with issuerUniqueID and subjectUniqueID, a v2 one with the subject's alone, and
    /// a v3 one with both before its extensions, each read with its version and fields in place.
    /// </summary>
    [Fact]
    [Requirement("RFC5280-4.1.2.8-p1#1", "RFC5280-4.1.2.8-p1#4")]
    public void ReadsUniqueIdentifiers()
    {
        Platform.RequireLinuxX64();
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] good = SelfSigned(ec, DateTimeOffset.UnixEpoch.AddYears(56), DateTimeOffset.UnixEpoch.AddYears(57), true);
        foreach (string change in new[] { "v2 with both unique ids", "v2 with the subject's unique id", "v3 with both unique ids" })
        {
            byte[] der = Rewrite(good, change);
            ReadCertificate r = Read(der);
            Assert.Equal((0, change.StartsWith("v2", StringComparison.Ordinal) ? 2u : 3u), (r.Status, r.Version));
            Assert.Equal(change.StartsWith("v2", StringComparison.Ordinal) ? -1 : 1, Math.Sign(r.Fields["extensions"].Offset));
            Assert.Equal(Abi.KeyP256, ReadKey(Field(der, r, "spki")).Kind);
        }
    }

    /// <summary>A certificate re-encoded with every extension's explicit critical FALSE removed
    /// (the DEFAULT DER omits), the rest as it was: the TBS rebuilt by .NET's AsnWriter.</summary>
    /// <param name="der">The certificate.</param>
    /// <returns>The re-encoded certificate (its signature no longer covers it).</returns>
    private static byte[] WithoutFalseCritical(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.BER);
        AsnReader certificate = reader.ReadSequence();
        AsnReader tbs = certificate.ReadSequence();
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                while (tbs.HasData)
                {
                    Asn1Tag tag = tbs.PeekTag();
                    if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue != 3)
                    {
                        writer.WriteEncodedValue(tbs.ReadEncodedValue().Span);
                        continue;
                    }

                    AsnReader extensions = tbs.ReadSequence(tag).ReadSequence();
                    using (writer.PushSequence(tag))
                    {
                        using (writer.PushSequence())
                        {
                            while (extensions.HasData)
                            {
                                AsnReader extension = extensions.ReadSequence();
                                using (writer.PushSequence())
                                {
                                    writer.WriteObjectIdentifier(extension.ReadObjectIdentifier());
                                    if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                                    {
                                        bool critical = extension.ReadBoolean();
                                        if (critical)
                                        {
                                            writer.WriteBoolean(true);
                                        }
                                    }

                                    writer.WriteOctetString(extension.ReadOctetString());
                                }
                            }
                        }
                    }
                }
            }

            writer.WriteEncodedValue(certificate.ReadEncodedValue().Span);
            writer.WriteEncodedValue(certificate.ReadEncodedValue().Span);
        }

        return writer.Encode();
    }

    /// <summary>
    /// A certificate rewritten by a change that breaks one rule: the read refuses it. The changes
    /// take each element of the certificate and of its TBS in turn (unreadable, retagged, missing,
    /// doubled, trailed), each field's own rules (the version's form and values, the inner
    /// signature's octets and length, the names' RDNSequence shape, the validity's two times, the
    /// unique identifiers' order and versions, the extensions' shape), so every refusal the reader
    /// makes is reached by a certificate that differs from a good one in that one place.
    /// </summary>
    /// <param name="change">The rule broken.</param>
    [Theory]
    [InlineData("explicit v1")]
    [InlineData("version 4")]
    [InlineData("extensions in v2")]
    [InlineData("no extension")]
    [InlineData("critical FALSE")]
    [InlineData("inner signature differs")]
    [InlineData("inner signature longer")]
    [InlineData("trailing element in TBS")]
    [InlineData("trailing octet")]
    [InlineData("signature unused bits")]
    [InlineData("empty RDN")]
    [InlineData("RDN not sorted")]
    [InlineData("fractional seconds")]
    [InlineData("time not a time")]
    [InlineData("unique id in v1")]
    [InlineData("not a SEQUENCE")]
    [InlineData("TBS not a SEQUENCE")]
    [InlineData("TBS does not read")]
    [InlineData("signature algorithm not a SEQUENCE")]
    [InlineData("signature algorithm does not read")]
    [InlineData("signature not a BIT STRING")]
    [InlineData("signature does not read")]
    [InlineData("no signature")]
    [InlineData("element after the signature")]
    [InlineData("version of two elements")]
    [InlineData("version not an INTEGER")]
    [InlineData("version of two octets")]
    [InlineData("version empty")]
    [InlineData("version does not read")]
    [InlineData("TBS of the version alone")]
    [InlineData("serial not an INTEGER")]
    [InlineData("serial does not read")]
    [InlineData("inner signature does not read")]
    [InlineData("issuer does not read")]
    [InlineData("issuer not a SEQUENCE")]
    [InlineData("RDN not a SET")]
    [InlineData("RDN does not read")]
    [InlineData("attribute not a SEQUENCE")]
    [InlineData("attribute type not an OID")]
    [InlineData("attribute type does not read")]
    [InlineData("attribute value does not read")]
    [InlineData("attribute without a value")]
    [InlineData("attribute of three elements")]
    [InlineData("validity does not read")]
    [InlineData("validity not a SEQUENCE")]
    [InlineData("validity of one time")]
    [InlineData("validity of three times")]
    [InlineData("first time does not read")]
    [InlineData("second time does not read")]
    [InlineData("second time not a time")]
    [InlineData("subject does not read")]
    [InlineData("subject not a SEQUENCE")]
    [InlineData("spki does not read")]
    [InlineData("spki not a SEQUENCE")]
    [InlineData("TBS without spki")]
    [InlineData("optional field does not read")]
    [InlineData("unknown field [4]")]
    [InlineData("extensions twice")]
    [InlineData("extensions of two SEQUENCEs")]
    [InlineData("extensions holding a SET")]
    [InlineData("extensions empty")]
    [InlineData("extension not a SEQUENCE")]
    [InlineData("extension does not read")]
    [InlineData("extension id not an OID")]
    [InlineData("extension id does not read")]
    [InlineData("extension id alone")]
    [InlineData("extension second element does not read")]
    [InlineData("extension value not an OCTET STRING")]
    [InlineData("extension critical then nothing")]
    [InlineData("extension critical then unreadable")]
    [InlineData("extension with a trailing element")]
    [InlineData("unique id after the extensions")]
    [InlineData("subjectUniqueID before issuerUniqueID")]
    [InlineData("issuerUniqueID twice")]
    [InlineData("unique id constructed")]
    [InlineData("unique id with unused bits set")]
    [InlineData("unique id empty")]
    [Requirement("RFC5280-4.1.1.2-p5", "RFC5280-4.1.2.1-p1#1", "RFC5280-4.1.2.5.2-p2#3", "RFC5280-4.1.2.8-p1#2", "RFC5280-4.1.2.9-p1", "X690-11.5", "X690-11.6")]
    public void RefusesCertificatesThatBreakARule(string change)
    {
        Platform.RequireLinuxX64();
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] good = SelfSigned(ec, DateTimeOffset.UnixEpoch.AddYears(56), DateTimeOffset.UnixEpoch.AddYears(57), true);
        Assert.Equal(0, Read(good).Status);
        byte[] bad = Rewrite(good, change);
        Assert.NotEqual(Convert.ToHexString(good), Convert.ToHexString(bad));
        Assert.Equal(-1, Read(bad).Status);
    }

    /// <summary>A certificate with one change (a rule broken, or a fixture's shape: the unique
    /// identifiers of <see cref="ReadsUniqueIdentifiers"/>, or v1 without version and extensions
    /// for <see cref="SurvivesEveryMutationOfItsElements"/>): its TBS rebuilt from .NET's
    /// AsnReader's view with the change, and the whole re-encoded (the signature no longer
    /// matters).</summary>
    /// <param name="der">The certificate: a v3 one with extensions, as SelfSigned makes it.</param>
    /// <param name="change">The change, by its name in the theories.</param>
    /// <returns>The changed DER.</returns>
    /// <exception cref="ArgumentException">An unknown change (a typo in a theory's data must fail
    /// loudly, not test the good certificate).</exception>
    private static byte[] Rewrite(byte[] der, string change)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        AsnReader certificate = reader.ReadSequence();
        AsnReader tbs = certificate.ReadSequence();
        byte[] algorithm = certificate.ReadEncodedValue().ToArray();
        byte[] signature = certificate.ReadEncodedValue().ToArray();
        var parts = new List<byte[]>();
        while (tbs.HasData)
        {
            parts.Add(tbs.ReadEncodedValue().ToArray());
        }

        // parts: [0] version, serial, signature, issuer, validity, subject, spki, [3] extensions
        static byte[] Seq(byte tag, params byte[][] content) => KeyTests.Der(tag, content);
        byte[] Tbs() => Seq(0x30, [.. parts.SelectMany(p => p)]);
        byte[] cn = [0x06, 0x03, 0x55, 0x04, 0x03];
        byte[] value = Seq(0x0C, Encoding.ASCII.GetBytes("x"));
        byte[] Name(byte[] attribute) => Seq(0x30, Seq(0x31, attribute));
        byte[] t1 = Seq(0x17, Encoding.ASCII.GetBytes("260101000000Z")), t2 = Seq(0x17, Encoding.ASCII.GetBytes("270101000000Z"));
        byte[] basic = [0x06, 0x03, 0x55, 0x1D, 0x13];
        byte[] Extensions(params byte[][] extensions) => Seq(0xA3, Seq(0x30, extensions));
        byte[] issuerId = [0x81, 0x02, 0x00, 0x01], subjectId = [0x82, 0x02, 0x00, 0x02];
        switch (change)
        {
            case "explicit v1": parts[0] = Seq(0xA0, [0x02, 0x01, 0x00]); break;
            case "version 4": parts[0] = Seq(0xA0, [0x02, 0x01, 0x03]); break;
            case "extensions in v2": parts[0] = Seq(0xA0, [0x02, 0x01, 0x01]); break;
            case "no extension": parts[^1] = Seq(0xA3, Seq(0x30)); break;
            case "critical FALSE":
                {
                    byte[] ext = Seq(0x30, [0x06, 0x03, 0x55, 0x1D, 0x13], [0x01, 0x01, 0x00], Seq(0x04, Seq(0x30)));
                    parts[^1] = Seq(0xA3, Seq(0x30, ext));
                    break;
                }

            case "inner signature differs": parts[2] = Seq(0x30, [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]); break;
            case "inner signature longer": parts[2] = Seq(0x30, [.. parts[2][2..], 0x05, 0x00]); break;
            case "trailing element in TBS": parts.Add([0x05, 0x00]); break;
            case "trailing octet": return [.. Seq(0x30, Tbs(), algorithm, signature), 0x00];
            case "signature unused bits": signature = [0x03, (byte)(signature[1]), 0x01, .. signature[3..]]; break;
            case "empty RDN": parts[3] = Seq(0x30, Seq(0x31)); break;
            case "RDN not sorted":
                {
                    byte[] a = Seq(0x30, [0x06, 0x03, 0x55, 0x04, 0x03], Seq(0x0C, Encoding.ASCII.GetBytes("b")));
                    byte[] b = Seq(0x30, [0x06, 0x03, 0x55, 0x04, 0x03], Seq(0x0C, Encoding.ASCII.GetBytes("a")));
                    parts[3] = Seq(0x30, Seq(0x31, a, b));
                    break;
                }

            case "fractional seconds":
                parts[4] = Seq(0x30, Seq(0x18, Encoding.ASCII.GetBytes("20260101000000.5Z")), Seq(0x18, Encoding.ASCII.GetBytes("20270101000000Z")));
                break;
            case "time not a time":
                parts[4] = Seq(0x30, Seq(0x13, Encoding.ASCII.GetBytes("20260101000000Z")), Seq(0x18, Encoding.ASCII.GetBytes("20270101000000Z")));
                break;
            case "unique id in v1":
                parts.RemoveAt(parts.Count - 1);
                parts.RemoveAt(0);
                parts.Add([0x81, 0x02, 0x00, 0x01]);
                break;

            // the outer structure, element by element
            case "not a SEQUENCE": return Seq(0x31, Tbs(), algorithm, signature);
            case "TBS not a SEQUENCE": return Seq(0x30, Seq(0x31, [.. parts.SelectMany(p => p)]), algorithm, signature);
            case "TBS does not read": return Seq(0x30, [0x30, 0x10]);
            case "signature algorithm not a SEQUENCE": algorithm = [0x31, .. algorithm[1..]]; break;
            case "signature algorithm does not read": return Seq(0x30, Tbs(), [0x30, 0x10]);
            case "signature not a BIT STRING": signature = [0x04, .. signature[1..]]; break;
            case "signature does not read": return Seq(0x30, Tbs(), algorithm, [0x03, 0x10]);
            case "no signature": return Seq(0x30, Tbs(), algorithm);
            case "element after the signature": return Seq(0x30, Tbs(), algorithm, signature, [0x05, 0x00]);

            // the TBS's fields
            case "version of two elements": parts[0] = Seq(0xA0, [0x02, 0x01, 0x02], [0x05, 0x00]); break;
            case "version not an INTEGER": parts[0] = Seq(0xA0, [0x04, 0x01, 0x02]); break;
            case "version of two octets": parts[0] = Seq(0xA0, [0x02, 0x02, 0x01, 0x02]); break;
            case "version empty": parts[0] = Seq(0xA0); break;
            case "version does not read": parts[0] = Seq(0xA0, [0x02, 0x10]); break;
            case "TBS of the version alone": parts.RemoveRange(1, parts.Count - 1); break;
            case "serial not an INTEGER": parts[1] = [0x04, .. parts[1][1..]]; break;
            case "serial does not read": parts.RemoveRange(1, parts.Count - 1); parts.Add([0x02, 0x10]); break;
            case "inner signature does not read": parts.RemoveRange(2, parts.Count - 2); parts.Add([0x30, 0x10]); break;
            case "issuer does not read": parts.RemoveRange(3, parts.Count - 3); parts.Add([0x30, 0x10]); break;
            case "issuer not a SEQUENCE": parts[3] = [0x31, .. parts[3][1..]]; break;
            case "RDN not a SET": parts[3] = Seq(0x30, Seq(0x30, Seq(0x30, cn, value))); break;
            case "RDN does not read": parts[3] = Seq(0x30, [0x31, 0x10]); break;
            case "attribute not a SEQUENCE": parts[3] = Name(Seq(0x31, cn, value)); break;
            case "attribute type not an OID": parts[3] = Name(Seq(0x30, value, value)); break;
            case "attribute type does not read": parts[3] = Name(Seq(0x30, [0x06, 0x10])); break;
            case "attribute value does not read": parts[3] = Name(Seq(0x30, [.. cn, 0x0C, 0x10])); break;
            case "attribute without a value": parts[3] = Name(Seq(0x30, cn)); break;
            case "attribute of three elements": parts[3] = Name(Seq(0x30, cn, value, value)); break;
            case "validity does not read": parts.RemoveRange(4, parts.Count - 4); parts.Add([0x30, 0x10]); break;
            case "validity not a SEQUENCE": parts[4] = Seq(0x31, t1, t2); break;
            case "validity of one time": parts[4] = Seq(0x30, t1); break;
            case "validity of three times": parts[4] = Seq(0x30, t1, t2, t2); break;
            case "first time does not read": parts[4] = Seq(0x30, [0x17, 0x10]); break;
            case "second time does not read": parts[4] = Seq(0x30, [.. t1, 0x17, 0x10]); break;
            case "second time not a time": parts[4] = Seq(0x30, t1, Seq(0x13, Encoding.ASCII.GetBytes("270101000000Z"))); break;
            case "subject does not read": parts.RemoveRange(5, parts.Count - 5); parts.Add([0x30, 0x10]); break;
            case "subject not a SEQUENCE": parts[5] = [0x31, .. parts[5][1..]]; break;
            case "spki does not read": parts.RemoveRange(6, parts.Count - 6); parts.Add([0x30, 0x10]); break;
            case "spki not a SEQUENCE": parts[6] = [0x31, .. parts[6][1..]]; break;
            case "TBS without spki": parts.RemoveRange(6, parts.Count - 6); break;
            case "optional field does not read": parts.Add([0xA3, 0x10]); break;
            case "unknown field [4]": parts.Add(Seq(0xA4, [0x05, 0x00])); break;

            // the extensions
            case "extensions twice": parts.Add(parts[7]); break;
            case "extensions of two SEQUENCEs": parts[7] = Seq(0xA3, Seq(0x30, Seq(0x30, basic, Seq(0x04))), Seq(0x30, Seq(0x30, basic, Seq(0x04)))); break;
            case "extensions holding a SET": parts[7] = Seq(0xA3, Seq(0x31, Seq(0x30, basic, Seq(0x04)))); break;
            case "extensions empty": parts[7] = Seq(0xA3); break;
            case "extension not a SEQUENCE": parts[7] = Extensions(Seq(0x31, basic, Seq(0x04))); break;
            case "extension does not read": parts[7] = Seq(0xA3, Seq(0x30, [0x30, 0x10])); break;
            case "extension id not an OID": parts[7] = Extensions(Seq(0x30, [0x05, 0x00], Seq(0x04))); break;
            case "extension id does not read": parts[7] = Extensions(Seq(0x30, [0x06, 0x10])); break;
            case "extension id alone": parts[7] = Extensions(Seq(0x30, basic)); break;
            case "extension second element does not read": parts[7] = Extensions(Seq(0x30, [.. basic, 0x04, 0x10])); break;
            case "extension value not an OCTET STRING": parts[7] = Extensions(Seq(0x30, basic, Seq(0x03, [0x00]))); break;
            case "extension critical then nothing": parts[7] = Extensions(Seq(0x30, basic, [0x01, 0x01, 0xFF])); break;
            case "extension critical then unreadable": parts[7] = Extensions(Seq(0x30, [.. basic, 0x01, 0x01, 0xFF, 0x04, 0x10])); break;
            case "extension with a trailing element": parts[7] = Extensions(Seq(0x30, basic, Seq(0x04), [0x05, 0x00])); break;

            // the unique identifiers (v2 and v3), in order, once each, before the extensions
            case "unique id after the extensions": parts.Add(issuerId); break;
            case "subjectUniqueID before issuerUniqueID": parts.InsertRange(7, [subjectId, issuerId]); break;
            case "issuerUniqueID twice": parts.InsertRange(7, [issuerId, issuerId]); break;
            case "unique id constructed": parts.Insert(7, Seq(0xA1, [0x03, 0x02, 0x00, 0x01])); break;
            case "unique id with unused bits set": parts.Insert(7, [0x81, 0x02, 0x01, 0x01]); break;
            case "unique id empty": parts.Insert(7, [0x81, 0x00]); break;
            case "v2 with both unique ids":
                parts[0] = Seq(0xA0, [0x02, 0x01, 0x01]);
                parts.RemoveAt(7);
                parts.AddRange([issuerId, subjectId]);
                break;
            case "v2 with the subject's unique id":
                parts[0] = Seq(0xA0, [0x02, 0x01, 0x01]);
                parts.RemoveAt(7);
                parts.Add(subjectId);
                break;
            case "v3 with both unique ids": parts.InsertRange(7, [issuerId, subjectId]); break;
            case "v1": parts.RemoveAt(7); parts.RemoveAt(0); break;
            default: throw new ArgumentException($"no change named {change}", nameof(change));
        }

        return Seq(0x30, Tbs(), algorithm, signature);
    }

    /// <summary>
    /// Every structural mutation (<see cref="DerMutations"/>: each element removed, doubled,
    /// trailed, replaced, retagged, made unreadable, its value changed, the public key's own DER
    /// included) of certificates (.NET's RSA and P-256 ones with extensions, the latter as v1
    /// and as v2 with both unique identifiers too) and of public key infos of every kind. A certificate that still reads has
    /// every part inside the input and its public key info reads as the original's kind or not
    /// at all; a public key info that still reads is of the original's kind with the kind's point
    /// length; a refused one is all zeros (ReadKey checks it). No mutation reads past its input.
    /// </summary>
    [Fact]
    public void SurvivesEveryMutationOfItsElements()
    {
        Platform.RequireLinuxX64();
        using RSA rsa = RSA.Create(1024);
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DateTimeOffset from = DateTimeOffset.UnixEpoch.AddYears(56), to = DateTimeOffset.UnixEpoch.AddYears(57);
        byte[] good = SelfSigned(ec, from, to, true);
        byte[][] certificates = [SelfSigned(rsa, from, to, true), good, Rewrite(good, "v1"), Rewrite(good, "v2 with both unique ids")];
        int mutations = 0;
        foreach (byte[] certificate in certificates)
        {
            ReadCertificate original = Read(certificate);
            Assert.Equal(0, original.Status);
            int originalKind = ReadKey(Field(certificate, original, "spki")).Kind;
            foreach ((string name, byte[] mutated) in DerMutations.Of(certificate))
            {
                mutations++;
                ReadCertificate r = Read(mutated);
                if (r.Status != 0)
                {
                    continue;
                }

                foreach ((string field, (long offset, long length)) in r.Fields)
                {
                    Assert.True(field == "extensions" && offset == -1 || offset >= 0 && offset + length <= mutated.Length,
                        $"{name}: {field} at {offset}, {length} octets, outside {mutated.Length}");
                }

                int kind = ReadKey(Field(mutated, r, "spki")).Kind;
                Assert.True(kind == -1 || kind == originalKind, $"{name}: a public key of kind {kind}");
            }
        }

        byte[] ed25519 = Convert.FromHexString("19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");
        byte[] sha256 = Der(0x30, OidSha256, Null);
        byte[][] infos =
        [
            rsa.ExportSubjectPublicKeyInfo(),
            Spki(Der(0x30, OidPss, Der(0x30, Der(0xA0, sha256), Der(0xA1, Der(0x30, OidMgf1, sha256)), Der(0xA2, Small(32)))), rsa.ExportRSAPublicKey()),
            ec.ExportSubjectPublicKeyInfo(),
            Spki(Der(0x30, OidEd25519), ed25519),
            Spki(Der(0x30, OidEd448), Ed448Public),
        ];
        foreach (byte[] info in infos)
        {
            (int originalKind, byte[] originalKey) = ReadKey(info);
            Assert.True(originalKind > 0);
            foreach ((string name, byte[] mutated) in DerMutations.Of(info))
            {
                mutations++;
                (int kind, byte[] key) = ReadKey(mutated);
                Assert.True(kind == -1 || kind == originalKind && BitConverter.ToUInt32(key, 16) == BitConverter.ToUInt32(originalKey, 16),
                    $"{name}: kind {kind}");
            }
        }

        Assert.True(mutations > 800, $"{mutations} mutations");
    }

    /// <summary>Every prefix of a certificate is refused without reading past it (each placed at
    /// the end of a page before a guard page).</summary>
    [Fact]
    public void NeverReadsPastTheCertificate()
    {
        Platform.RequireLinuxX64();
        using ECDsa ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] der = SelfSigned(ec, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), true);
        for (int n = 0; n < der.Length; n++)
        {
            Assert.Equal(-1, Read(der[..n]).Status);
        }
    }
}
