using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HttpAsm.Tests;

/// <summary>
/// One key share's private side (RFC 9846 4.3.8, RFC 10024), made by the test client: its public
/// share and, from the server's, the shared secret. The NIST curves are .NET's own
/// (ECDiffieHellman); X25519, X448, the finite fields and ML-KEM, which .NET does not offer on
/// Linux, are the library's primitives, each proven against its own vectors elsewhere - what this
/// client checks is the engine around them.
/// </summary>
internal sealed unsafe class TlsShare : IDisposable
{
    /// <summary>The group.</summary>
    public ushort Group { get; }

    /// <summary>The client's key_exchange.</summary>
    public byte[] Public { get; }

    /// <summary>The X25519 or X448 scalar, or the finite field's exponent.</summary>
    private readonly byte[] scalar = [];

    /// <summary>The NIST curve's key.</summary>
    private readonly ECDiffieHellman? ec;

    /// <summary>ML-KEM's decapsulation key.</summary>
    private readonly byte[] dk = [];

    /// <summary>Makes a share of a group.</summary>
    /// <param name="group">The NamedGroup.</param>
    /// <exception cref="ArgumentException">A group this client lacks.</exception>
    public TlsShare(ushort group)
    {
        Group = group;
        switch (group)
        {
            case TlsEngine.X25519:
                scalar = RandomNumberGenerator.GetBytes(32);
                Public = X25519Public(scalar);
                break;
            case TlsEngine.X448:
                scalar = RandomNumberGenerator.GetBytes(56);
                Public = new byte[56];
                fixed (byte* o = Public, s = scalar)
                {
                    Native.X448PublicKey(o, s);
                }

                break;
            case TlsEngine.Secp256r1:
            case TlsEngine.Secp384r1:
            case TlsEngine.Secp521r1:
                ec = ECDiffieHellman.Create(Curve(group));
                Public = Point(ec, group);
                break;
            case >= 0x0100 and <= 0x0104:
                scalar = RandomNumberGenerator.GetBytes(64);
                Public = new byte[(int)Native.FfdheSize(group)];
                fixed (byte* o = Public, s = scalar)
                {
                    Assert.Equal(0, Native.FfdhePublicKey(group, o, s, 64));
                }

                break;
            case TlsEngine.X25519MlKem768:
                {
                    byte[] ek = MlKemKeypair(768, out dk);
                    scalar = RandomNumberGenerator.GetBytes(32);
                    Public = [.. ek, .. X25519Public(scalar)];
                    break;
                }

            case TlsEngine.Secp256r1MlKem768:
                {
                    byte[] ek = MlKemKeypair(768, out dk);
                    ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                    Public = [.. Point(ec, TlsEngine.Secp256r1), .. ek];
                    break;
                }

            case TlsEngine.Secp384r1MlKem1024:
                {
                    byte[] ek = MlKemKeypair(1024, out dk);
                    ec = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
                    Public = [.. Point(ec, TlsEngine.Secp384r1), .. ek];
                    break;
                }

            default:
                throw new ArgumentException($"no share for group {group:X4}", nameof(group));
        }
    }

    /// <summary>The NIST curve of a group.</summary>
    /// <param name="group">secp256r1, secp384r1 or secp521r1.</param>
    /// <returns>Its curve.</returns>
    private static ECCurve Curve(ushort group) => group switch
    {
        TlsEngine.Secp256r1 => ECCurve.NamedCurves.nistP256,
        TlsEngine.Secp384r1 => ECCurve.NamedCurves.nistP384,
        _ => ECCurve.NamedCurves.nistP521,
    };

    /// <summary>The coordinates' octets of a group's curve.</summary>
    /// <param name="group">The group.</param>
    /// <returns>32, 48 or 66.</returns>
    private static int Size(ushort group) => group switch { TlsEngine.Secp256r1 => 32, TlsEngine.Secp384r1 => 48, _ => 66 };

    /// <summary>A key's public point, uncompressed (04 || x || y: 4.3.8.2).</summary>
    /// <param name="key">The key.</param>
    /// <param name="group">Its group.</param>
    /// <returns>The point.</returns>
    private static byte[] Point(ECDiffieHellman key, ushort group)
    {
        ECParameters p = key.ExportParameters(false);
        int size = Size(group);
        return [4, .. Pad(p.Q.X!, size), .. Pad(p.Q.Y!, size)];
    }

    /// <summary>Left-pads a big-endian value to a size.</summary>
    /// <param name="value">The value.</param>
    /// <param name="size">The octets wanted.</param>
    /// <returns>The padded value.</returns>
    private static byte[] Pad(byte[] value, int size) => [.. new byte[size - value.Length], .. value];

    /// <summary>X25519's public key of a scalar (the library's).</summary>
    /// <param name="s">The scalar.</param>
    /// <returns>The public key.</returns>
    private static byte[] X25519Public(byte[] s)
    {
        byte[] o = new byte[32];
        fixed (byte* op = o, sp = s)
        {
            Native.X25519PublicKey(op, sp);
        }

        return o;
    }

    /// <summary>An ML-KEM key pair from a random seed (the library's).</summary>
    /// <param name="level">768 or 1024.</param>
    /// <param name="decapsulation">Receives the decapsulation key.</param>
    /// <returns>The encapsulation key.</returns>
    private static byte[] MlKemKeypair(int level, out byte[] decapsulation)
    {
        byte[] seed = RandomNumberGenerator.GetBytes(64);
        byte[] ek = new byte[level == 768 ? 1184 : 1568];
        decapsulation = new byte[level == 768 ? 2400 : 3168];
        fixed (byte* e = ek, d = decapsulation, s = seed)
        {
            if (level == 768)
            {
                Native.MlKem768Keypair(e, d, s);
            }
            else
            {
                Native.MlKem1024Keypair(e, d, s);
            }
        }

        return ek;
    }

    /// <summary>The shared secret from the server's key_exchange (RFC 10024's orders for the
    /// hybrids), or null when the server's share does not make one (a wrong length, a point off
    /// the curve, an all-zero X25519 or X448 secret).</summary>
    /// <param name="server">The server's key_exchange.</param>
    /// <returns>The secret.</returns>
    public byte[]? Secret(byte[] server)
    {
        switch (Group)
        {
            case TlsEngine.X25519:
                return server.Length == 32 ? X25519(scalar, server) : null;
            case TlsEngine.X448:
                {
                    if (server.Length != 56)
                    {
                        return null;
                    }

                    byte[] o = new byte[56];
                    fixed (byte* op = o, s = scalar, pt = server)
                    {
                        return Native.X448(op, s, pt) == 0 ? o : null;
                    }
                }

            case TlsEngine.Secp256r1:
            case TlsEngine.Secp384r1:
            case TlsEngine.Secp521r1:
                return Ecdh(ec!, Group, server);
            case >= 0x0100 and <= 0x0104:
                {
                    byte[] o = new byte[Public.Length];
                    if (server.Length != Public.Length)
                    {
                        return null;
                    }

                    fixed (byte* op = o, s = scalar, pt = server)
                    {
                        return Native.FfdheShared(Group, op, s, 64, pt) == 0 ? o : null;
                    }
                }

            case TlsEngine.X25519MlKem768:
                {
                    if (server.Length != 1088 + 32)
                    {
                        return null;
                    }

                    byte[]? x = X25519(scalar, server[1088..]);
                    return x is null ? null : [.. Decaps(768, server[..1088]), .. x];
                }

            case TlsEngine.Secp256r1MlKem768:
                {
                    if (server.Length != 65 + 1088)
                    {
                        return null;
                    }

                    byte[]? e = Ecdh(ec!, TlsEngine.Secp256r1, server[..65]);
                    return e is null ? null : [.. e, .. Decaps(768, server[65..])];
                }

            default:
                {
                    if (server.Length != 97 + 1568)
                    {
                        return null;
                    }

                    byte[]? e = Ecdh(ec!, TlsEngine.Secp384r1, server[..97]);
                    return e is null ? null : [.. e, .. Decaps(1024, server[97..])];
                }
        }
    }

    /// <summary>X25519 with the library's primitive.</summary>
    /// <param name="s">Our scalar.</param>
    /// <param name="point">The peer's u-coordinate.</param>
    /// <returns>The secret, or null when it is all zeros.</returns>
    private static byte[]? X25519(byte[] s, byte[] point)
    {
        byte[] o = new byte[32];
        fixed (byte* op = o, sp = s, pp = point)
        {
            return Native.X25519(op, sp, pp) == 0 ? o : null;
        }
    }

    /// <summary>ECDH with .NET: the x-coordinate of our key times the peer's point.</summary>
    /// <param name="key">Our key.</param>
    /// <param name="group">The curve's group.</param>
    /// <param name="point">The peer's 04 || x || y.</param>
    /// <returns>The secret, or null when the point is not one of the curve's.</returns>
    private static byte[]? Ecdh(ECDiffieHellman key, ushort group, byte[] point)
    {
        int size = Size(group);
        if (point.Length != 1 + 2 * size || point[0] != 4)
        {
            return null;
        }

        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = Curve(group),
                Q = new ECPoint { X = point[1..(1 + size)], Y = point[(1 + size)..] },
            });
            return key.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>ML-KEM's decapsulation with the library's primitive.</summary>
    /// <param name="level">768 or 1024.</param>
    /// <param name="ciphertext">The server's ciphertext.</param>
    /// <returns>The shared secret.</returns>
    private byte[] Decaps(int level, byte[] ciphertext)
    {
        byte[] o = new byte[32];
        fixed (byte* op = o, d = dk, c = ciphertext)
        {
            Assert.Equal(0, level == 768 ? Native.MlKem768Decaps(op, d, c) : Native.MlKem1024Decaps(op, d, c));
        }

        return o;
    }

    /// <summary>Frees the NIST curve's key.</summary>
    public void Dispose() => ec?.Dispose();
}

/// <summary>
/// A TLS 1.3 client written for the tests, apart from the engine: its own ClientHello (every
/// field and extension the test chooses, broken ones too), key schedule (.NET's HKDF), transcript
/// (the HelloRetryRequest rule included), record protection (.NET's AES-GCM and
/// ChaCha20-Poly1305) and readers of the server's messages, with the server's CertificateVerify
/// and Finished verified (.NET's RSA-PSS and ECDSA, the library's EdDSA). What the engine's server
/// says is checked by something that is not the engine; what a test sends can be anything.
/// </summary>
internal sealed class TlsTestClient : IDisposable
{
    /// <summary>The suites offered, in order.</summary>
    public ushort[] Suites { get; set; } = [0x1301, 0x1302, 0x1303];

    /// <summary>supported_groups, in order.</summary>
    public ushort[] Groups { get; set; } = [TlsEngine.X25519, TlsEngine.Secp256r1];

    /// <summary>The groups key_share carries a share for, in order.</summary>
    public ushort[] ShareGroups { get; set; } = [TlsEngine.X25519];

    /// <summary>signature_algorithms, in order.</summary>
    public ushort[] SignatureAlgorithms { get; set; } = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806];

    /// <summary>legacy_session_id (not empty: middlebox compatibility).</summary>
    public byte[] SessionId { get; set; } = [];

    /// <summary>server_name's host, or null for none.</summary>
    public string? ServerName { get; set; } = "localhost";

    /// <summary>supported_versions' list.</summary>
    public ushort[] Versions { get; set; } = [0x0304];

    /// <summary>legacy_version (0x0303 for a TLS 1.3 hello: 4.2.2).</summary>
    public ushort LegacyVersion { get; set; } = 0x0303;

    /// <summary>Extension types left out of the ClientHello.</summary>
    public HashSet<ushort> Omit { get; } = [];

    /// <summary>Extensions added after the standard ones (type, data).</summary>
    public List<(ushort Type, byte[] Data)> Extra { get; } = [];

    /// <summary>Replaces a share's key_exchange as sent (a broken share), by group.</summary>
    public Dictionary<ushort, byte[]> ShareOverride { get; } = [];

    /// <summary>The groups the second hello shares, when a test breaks 4.2.2's rule (null: the
    /// retry's group alone, as a client must).</summary>
    public ushort[]? RetryShareGroups { get; set; }

    /// <summary>The client random.</summary>
    private readonly byte[] random = RandomNumberGenerator.GetBytes(32);

    /// <summary>The shares of the hello last built.</summary>
    private readonly List<TlsShare> shares = [];

    /// <summary>The handshake messages so far, whole (header and body), in order.</summary>
    private readonly List<byte[]> messages = [];

    /// <summary>Whether a HelloRetryRequest came (the transcript's first message is then
    /// message_hash's).</summary>
    public bool Retried { get; private set; }

    /// <summary>The suite the server chose.</summary>
    public ushort Suite { get; private set; }

    /// <summary>The group of the server's share (a HelloRetryRequest's selected_group before).</summary>
    public ushort Group { get; private set; }

    /// <summary>The scheme of the server's CertificateVerify.</summary>
    public ushort Scheme { get; private set; }

    /// <summary>The server's EncryptedExtensions body.</summary>
    public byte[] EncryptedExtensions { get; private set; } = [];

    /// <summary>The server's leaf certificate.</summary>
    public byte[] Certificate { get; private set; } = [];

    /// <summary>Whether the server's Finished verified.</summary>
    public bool ServerFinished { get; private set; }

    /// <summary>The alerts the server sent (level, description).</summary>
    public List<(byte Level, byte Description)> Alerts { get; } = [];

    /// <summary>Application data the server sent, record by record.</summary>
    public List<byte[]> Data { get; } = [];

    /// <summary>Change_cipher_spec records the server sent.</summary>
    public int ChangeCipherSpecs { get; private set; }

    /// <summary>The server's KeyUpdates (their request_update), in order.</summary>
    public List<int> KeyUpdates { get; } = [];

    /// <summary>The hash's name and length, by the suite.</summary>
    private (HashAlgorithmName Name, int Length) Hash => Suite == 0x1302 ? (HashAlgorithmName.SHA384, 48) : (HashAlgorithmName.SHA256, 32);

    /// <summary>The secrets as the handshake makes them.</summary>
    private byte[] handshakeSecret = [], clientHandshake = [], serverHandshake = [], master = [];

    /// <summary>The application traffic secrets (the current ones).</summary>
    public byte[] ClientApplication { get; private set; } = [];

    /// <summary>The server's.</summary>
    public byte[] ServerApplication { get; private set; } = [];

    /// <summary>The record keys: (key, iv, sequence) for reading the server and writing ours.</summary>
    private (byte[] Key, byte[] Iv, ulong Sequence) read, write;

    /// <summary>Whether the server's records are protected (after its ServerHello).</summary>
    private bool reading;

    /// <summary>A handshake message the server cut across records, gathered so far.</summary>
    private readonly List<byte> partial = [];

    /// <summary>The certificates the client answers a CertificateRequest with (DER, the leaf
    /// first); null or empty: an empty Certificate (RFC 9846 4.5.1: the client declines).</summary>
    public IReadOnlyList<byte[]>? ClientChain { get; set; }

    /// <summary>The scheme the client's CertificateVerify names, and its signer (what was
    /// signed in, the signature out): <see cref="ClientSigner"/> makes the pair for a key.</summary>
    public (ushort Scheme, Func<byte[], byte[]> Sign)? ClientKey { get; set; }

    /// <summary>The certificate_request_context the Certificate carries (null: the request's,
    /// as it must).</summary>
    public byte[]? AnswerContext { get; set; }

    /// <summary>The extensions block (its content, no length) of the leaf's CertificateEntry
    /// (null: none, as an answer to a request that asked for none must).</summary>
    public byte[]? LeafExtensions { get; set; }

    /// <summary>The scheme the CertificateVerify names instead of the key's (null: the key's).</summary>
    public ushort? AnswerScheme { get; set; }

    /// <summary>When set, the CertificateVerify's signature's last octet is flipped.</summary>
    public bool CorruptSignature { get; set; }

    /// <summary>When set, no CertificateVerify follows a Certificate with certificates.</summary>
    public bool OmitCertificateVerify { get; set; }

    /// <summary>When set, a CertificateVerify follows even an empty Certificate.</summary>
    public bool VerifyEmpty { get; set; }

    /// <summary>The server's CertificateRequest's context, once one came (null: none came).</summary>
    public byte[]? RequestContext { get; private set; }

    /// <summary>The schemes the server's CertificateRequest listed (signature_algorithms), in its order.</summary>
    public ushort[] RequestedSchemes { get; private set; } = [];

    /// <summary>
    /// A client key's CertificateVerify scheme and signer: ECDSA (P-256/384/521, DER as TLS sends
    /// it) and RSA-PSS (rsaEncryption keys: rsa_pss_rsae_sha256; an RSASSA-PSS key's
    /// RSAPrivateKey read out of its PKCS#8: rsa_pss_pss_sha256) by .NET, Ed25519 and Ed448 by the
    /// library (.NET has no EdDSA).
    /// </summary>
    /// <param name="kind">"p256", "p384", "p521", "rsa2048" or "rsa", "rsa-pss" (and its
    /// "rsa-pss-sha256" variants), "ed25519", "ed448".</param>
    /// <param name="key">The key's PKCS#8, DER (.NET's credentials) or PEM (openssl's).</param>
    /// <returns>The scheme and the signer.</returns>
    /// <exception cref="ArgumentException">Another kind.</exception>
    public static (ushort Scheme, Func<byte[], byte[]> Sign) ClientSigner(string kind, byte[] key)
    {
        byte[] pkcs8 = key;
        if (key.Length > 0 && key[0] == (byte)'-')
        {
            // PEM: its base64 between the BEGIN and END lines is the DER (RFC 7468)
            string text = System.Text.Encoding.ASCII.GetString(key);
            PemFields pem = PemEncoding.Find(text);
            pkcs8 = Convert.FromBase64String(text[pem.Base64Data]);
        }

        switch (kind)
        {
            case "p256":
            case "p384":
            case "p521":
                {
                    ECDsa ec = ECDsa.Create();
                    ec.ImportPkcs8PrivateKey(pkcs8, out _);
                    (ushort scheme, HashAlgorithmName hash) = kind switch
                    {
                        "p256" => ((ushort)0x0403, HashAlgorithmName.SHA256),
                        "p384" => ((ushort)0x0503, HashAlgorithmName.SHA384),
                        _ => ((ushort)0x0603, HashAlgorithmName.SHA512),
                    };
                    return (scheme, content => ec.SignData(content, hash, DSASignatureFormat.Rfc3279DerSequence));
                }

            case "rsa2048":
            case "rsa":
                {
                    RSA rsa = RSA.Create();
                    rsa.ImportPkcs8PrivateKey(pkcs8, out _);
                    return (0x0804, content => rsa.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                }

            case "rsa-pss":
            case "rsa-pss-sha256":
            case "rsa-pss-sha256-salt64":
                {
                    // PKCS#8's privateKey OCTET STRING holds the RSAPrivateKey whatever the
                    // algorithm's parameters (RFC 4055 1.2): .NET imports that, not the OID
                    var reader = new System.Formats.Asn1.AsnReader(pkcs8, System.Formats.Asn1.AsnEncodingRules.DER);
                    System.Formats.Asn1.AsnReader info = reader.ReadSequence();
                    _ = info.ReadInteger();
                    _ = info.ReadSequence();
                    byte[] inner = info.ReadOctetString();
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(inner, out _);
                    return (0x0809, content => rsa.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                }

            case "ed25519":
            case "ed448":
                {
                    // the seed: the innermost OCTET STRING (RFC 8410 7: CurvePrivateKey)
                    var reader = new System.Formats.Asn1.AsnReader(pkcs8, System.Formats.Asn1.AsnEncodingRules.DER);
                    System.Formats.Asn1.AsnReader info = reader.ReadSequence();
                    _ = info.ReadInteger();
                    _ = info.ReadSequence();
                    byte[] seed = new System.Formats.Asn1.AsnReader(info.ReadOctetString(), System.Formats.Asn1.AsnEncodingRules.DER).ReadOctetString();
                    return kind == "ed25519" ? (0x0807, content => SignEd25519(seed, content)) : (0x0808, content => SignEd448(seed, content));
                }

            default:
                throw new ArgumentException($"no signer for {kind}", nameof(kind));
        }
    }

    /// <summary>Ed25519 by the library (a key prepared from the seed for the one signature).</summary>
    /// <param name="seed">The 32-octet private key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 64-octet signature.</returns>
    private static unsafe byte[] SignEd25519(byte[] seed, byte[] message)
    {
        byte[] signature = new byte[64];
        Ed25519PrivateKey key;
        fixed (byte* s = seed, m = message, o = signature)
        {
            Native.Ed25519PrivateKeyInit(&key, s);
            Native.Ed25519Sign(o, &key, m, (nuint)message.Length);
        }

        new Span<byte>(&key, sizeof(Ed25519PrivateKey)).Clear();
        return signature;
    }

    /// <summary>Ed448 by the library, no context (TLS 1.3's).</summary>
    /// <param name="seed">The 57-octet private key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 114-octet signature.</returns>
    /// <exception cref="InvalidOperationException">The library refused (it never does without a context).</exception>
    private static unsafe byte[] SignEd448(byte[] seed, byte[] message)
    {
        byte[] signature = new byte[114];
        Ed448PrivateKey key;
        fixed (byte* s = seed, m = message, o = signature)
        {
            Native.Ed448PrivateKeyInit(&key, s);
            if (Native.Ed448Sign(o, &key, m, (nuint)message.Length, null, 0) != 0)
            {
                throw new InvalidOperationException("Ed448 refused to sign");
            }
        }

        new Span<byte>(&key, sizeof(Ed448PrivateKey)).Clear();
        return signature;
    }

    /// <summary>
    /// The ClientHello as a record: the first, or the second after a HelloRetryRequest (its
    /// share then the retry's group only; the cookie, if one came, echoed). The message joins
    /// the transcript.
    /// </summary>
    /// <returns>The record.</returns>
    public byte[] Hello()
    {
        foreach (TlsShare s in shares)
        {
            s.Dispose();
        }

        shares.Clear();
        ushort[] shareGroups = Retried ? RetryShareGroups ?? [Group] : ShareGroups;
        foreach (ushort g in shareGroups)
        {
            shares.Add(new TlsShare(g));
        }

        var e = new List<(ushort, byte[])>();
        void Add(ushort type, byte[] data)
        {
            if (!Omit.Contains(type))
            {
                e.Add((type, data));
            }
        }

        if (ServerName is { } name)
        {
            byte[] host = System.Text.Encoding.ASCII.GetBytes(name);
            Add(0, V16([0, .. V16(host)]));
        }

        Add(10, V16([.. Groups.SelectMany(U16)]));
        Add(13, V16([.. SignatureAlgorithms.SelectMany(U16)]));
        Add(43, V8([.. Versions.SelectMany(U16)]));
        Add(45, V8(1));
        Add(51, V16([.. shares.SelectMany(s => (byte[])[.. U16(s.Group), .. V16(ShareOverride.TryGetValue(s.Group, out byte[]? o) ? o : s.Public)])]));
        foreach ((ushort type, byte[] data) in Extra)
        {
            e.Add((type, data));
        }

        byte[] block = [.. e.SelectMany(x => (byte[])[.. U16(x.Item1), .. V16(x.Item2)])];
        byte[] body = [.. U16(LegacyVersion), .. random, .. V8(SessionId), .. V16([.. Suites.SelectMany(U16)]), 1, 0, .. V16(block)];
        byte[] message = Message(1, body);
        messages.Add(message);
        return Plain(22, message);
    }

    /// <summary>
    /// Takes what the server sent: its records one by one (a ServerHello or HelloRetryRequest in
    /// the clear, change_cipher_spec, alerts, then protected records: the flight's messages,
    /// verified as they come, later application data and KeyUpdates).
    /// </summary>
    /// <param name="octets">The server's output.</param>
    /// <exception cref="InvalidDataException">Something the server sent does not parse or verify.</exception>
    public void Take(ReadOnlySpan<byte> octets)
    {
        while (octets.Length > 0)
        {
            if (octets.Length < 5)
            {
                throw new InvalidDataException("a record cut short");
            }

            int length = (octets[3] << 8) | octets[4];
            byte[] record = octets[..(5 + length)].ToArray();
            octets = octets[(5 + length)..];
            byte type = record[0];
            if (type == 20)
            {
                ChangeCipherSpecs++;
                continue;
            }

            byte[] content = record[5..];
            if (type == 23 && reading)
            {
                (type, content) = Open(record);
            }

            switch (type)
            {
                case 21:
                    Alerts.Add((content[0], content[1]));
                    break;
                case 22:
                    partial.AddRange(content);
                    while (partial.Count >= 4)
                    {
                        int n = (partial[1] << 16) | (partial[2] << 8) | partial[3];
                        if (partial.Count < 4 + n)
                        {
                            break;
                        }

                        byte[] message = [.. partial.Take(4 + n)];
                        partial.RemoveRange(0, 4 + n);
                        Handshake(message);
                    }

                    break;
                case 23:
                    Data.Add(content);
                    break;
                default:
                    throw new InvalidDataException($"a record of type {type}");
            }
        }
    }

    /// <summary>One handshake message of the server's, by its type.</summary>
    /// <param name="message">The message.</param>
    /// <exception cref="InvalidDataException">It does not parse or verify.</exception>
    private void Handshake(byte[] message)
    {
        byte[] body = message[4..];
        switch (message[0])
        {
            case 2:
                ServerHello(message, body);
                break;
            case 8:
                EncryptedExtensions = body;
                messages.Add(message);
                break;
            case 13:
                {
                    // CertificateRequest (4.4.2): its context, and signature_algorithms' list
                    // from its extensions (the only one this client reads)
                    int context = body[0];
                    RequestContext = body[1..(1 + context)];
                    int at = 1 + context + 2;
                    var schemes = new List<ushort>();
                    while (at < body.Length)
                    {
                        int type = (body[at] << 8) | body[at + 1];
                        int n = (body[at + 2] << 8) | body[at + 3];
                        if (type == 13)
                        {
                            for (int i = at + 6; i < at + 4 + n; i += 2)
                            {
                                schemes.Add((ushort)((body[i] << 8) | body[i + 1]));
                            }
                        }

                        at += 4 + n;
                    }

                    RequestedSchemes = [.. schemes];
                    messages.Add(message);
                    break;
                }

            case 11:
                {
                    // the leaf: the first entry's cert_data, past the context and the list's length
                    int at = 4 + body[0];
                    int n = (body[at] << 16) | (body[at + 1] << 8) | body[at + 2];
                    Certificate = body[(at + 3)..(at + 3 + n)];
                    messages.Add(message);
                    break;
                }

            case 15:
                {
                    Scheme = (ushort)((body[0] << 8) | body[1]);
                    byte[] signature = body[4..];
                    byte[] content = [.. Enumerable.Repeat((byte)0x20, 64), .. "TLS 1.3, server CertificateVerify"u8, 0, .. TranscriptHash()];
                    if (!Verify(Scheme, content, signature))
                    {
                        throw new InvalidDataException($"the CertificateVerify does not verify ({Scheme:X4})");
                    }

                    messages.Add(message);
                    break;
                }

            case 20:
                {
                    byte[] expected = FinishedMac(serverHandshake, TranscriptHash());
                    if (!CryptographicOperations.FixedTimeEquals(expected, body))
                    {
                        throw new InvalidDataException("the server's Finished does not verify");
                    }

                    messages.Add(message);
                    ServerFinished = true;
                    // the master secret and the application secrets, over CH .. server Finished
                    byte[] derived = DeriveSecret(handshakeSecret, "derived", Digest([]));
                    master = HKDF.Extract(Hash.Name, new byte[Hash.Length], derived);
                    byte[] h = TranscriptHash();
                    ClientApplication = DeriveSecret(master, "c ap traffic", h);
                    ServerApplication = DeriveSecret(master, "s ap traffic", h);
                    read = Keys(ServerApplication);
                    break;
                }

            case 24:
                KeyUpdates.Add(body[0]);
                ServerApplication = ExpandLabel(ServerApplication, "traffic upd", [], Hash.Length);
                read = Keys(ServerApplication);
                break;
            default:
                throw new InvalidDataException($"a handshake message of type {message[0]}");
        }
    }

    /// <summary>The ServerHello, or a HelloRetryRequest: the suite and group taken, the secrets
    /// computed (the retry: the transcript turned into message_hash).</summary>
    /// <param name="message">The message.</param>
    /// <param name="body">Its body.</param>
    /// <exception cref="InvalidDataException">It does not parse, or its share makes no secret.</exception>
    private void ServerHello(byte[] message, byte[] body)
    {
        byte[] retryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
        bool retry = body.AsSpan(2, 32).SequenceEqual(retryRandom);
        int at = 34;
        int sid = body[at];
        if (!body.AsSpan(at + 1, sid).SequenceEqual(SessionId))
        {
            throw new InvalidDataException("the session id is not echoed");
        }

        at += 1 + sid;
        Suite = (ushort)((body[at] << 8) | body[at + 1]);
        at += 3;
        int end = at + 2 + ((body[at] << 8) | body[at + 1]);
        at += 2;
        byte[]? share = null;
        while (at < end)
        {
            int type = (body[at] << 8) | body[at + 1];
            int n = (body[at + 2] << 8) | body[at + 3];
            byte[] data = body[(at + 4)..(at + 4 + n)];
            if (type == 51)
            {
                Group = (ushort)((data[0] << 8) | data[1]);
                share = retry ? null : data[4..];
            }

            at += 4 + n;
        }

        if (retry)
        {
            // 4.1: the transcript's first hello becomes message_hash(Hash(ClientHello1))
            byte[] first = Digest(messages[0]);
            messages[0] = [254, 0, 0, (byte)first.Length, .. first];
            messages.Add(message);
            Retried = true;
            return;
        }

        messages.Add(message);
        TlsShare? mine = shares.FirstOrDefault(s => s.Group == Group) ?? throw new InvalidDataException($"a share for {Group:X4}, which was not offered");
        byte[] secret = mine.Secret(share!) ?? throw new InvalidDataException("the server's share makes no secret");
        byte[] early = HKDF.Extract(Hash.Name, new byte[Hash.Length], new byte[Hash.Length]);
        handshakeSecret = HKDF.Extract(Hash.Name, secret, DeriveSecret(early, "derived", Digest([])));
        byte[] h = TranscriptHash();
        clientHandshake = DeriveSecret(handshakeSecret, "c hs traffic", h);
        serverHandshake = DeriveSecret(handshakeSecret, "s hs traffic", h);
        read = Keys(serverHandshake);
        write = Keys(clientHandshake);
        reading = true;
    }

    /// <summary>
    /// Our second flight, protected under the client's handshake key (a change_cipher_spec before
    /// it in middlebox compatibility mode), each message in a record of its own: when the server
    /// asked (<see cref="RequestContext"/>), our Certificate (<see cref="ClientChain"/>, empty when
    /// there is none) and, for one with certificates, our CertificateVerify over the transcript so
    /// far (<see cref="ClientKey"/>); then our Finished; then the application keys. The refusal
    /// tests' knobs shape the answer (<see cref="AnswerContext"/>, <see cref="LeafExtensions"/>,
    /// <see cref="AnswerScheme"/>, <see cref="CorruptSignature"/>, <see cref="OmitCertificateVerify"/>,
    /// <see cref="VerifyEmpty"/>).
    /// </summary>
    /// <returns>The records.</returns>
    /// <exception cref="InvalidOperationException">The server's Finished has not come, or a
    /// CertificateVerify is due and <see cref="ClientKey"/> is not set.</exception>
    public byte[] Finished()
    {
        if (!ServerFinished)
        {
            throw new InvalidOperationException("no server Finished yet");
        }

        var records = new List<byte>();
        if (SessionId.Length > 0)
        {
            records.AddRange(Plain(20, [1]));
        }

        if (RequestContext is { } asked)
        {
            byte[] context = AnswerContext ?? asked;
            IReadOnlyList<byte[]> chain = ClientChain ?? [];
            byte[] entries = [.. chain.SelectMany((c, i) => (byte[])[.. U24(c.Length), .. c, .. V16(i == 0 && LeafExtensions is { } e ? e : [])])];
            byte[] certificate = Message(11, [.. V8(context), .. U24(entries.Length), .. entries]);
            messages.Add(certificate);
            records.AddRange(Seal(22, certificate));
            if ((chain.Count > 0 && !OmitCertificateVerify) || VerifyEmpty)
            {
                (ushort scheme, Func<byte[], byte[]> sign) = ClientKey ?? throw new InvalidOperationException("no ClientKey for the CertificateVerify");
                byte[] content = [.. Enumerable.Repeat((byte)0x20, 64), .. "TLS 1.3, client CertificateVerify"u8, 0, .. TranscriptHash()];
                byte[] signature = sign(content);
                if (CorruptSignature)
                {
                    signature[^1] ^= 1;
                }

                byte[] verify = Message(15, [.. U16(AnswerScheme ?? scheme), .. V16(signature)]);
                messages.Add(verify);
                records.AddRange(Seal(22, verify));
            }
        }

        byte[] mac = FinishedMac(clientHandshake, TranscriptHash());
        byte[] message = Message(20, mac);
        messages.Add(message);
        records.AddRange(Seal(22, message));
        write = Keys(ClientApplication);
        return [.. records];
    }

    /// <summary>A uint24, big-endian.</summary>
    /// <param name="v">The value (under 2^24).</param>
    /// <returns>Its three octets.</returns>
    public static byte[] U24(int v) => [(byte)(v >> 16), (byte)(v >> 8), (byte)v];

    /// <summary>A protected record under our current write key (the handshake key before our
    /// Finished, the application key after).</summary>
    /// <param name="type">The inner content type.</param>
    /// <param name="content">The content.</param>
    /// <param name="padding">Zero octets after the type.</param>
    /// <returns>The record.</returns>
    public byte[] Seal(byte type, byte[] content, int padding = 0)
    {
        byte[] inner = [.. content, type, .. new byte[padding]];
        int length = inner.Length + 16;
        byte[] header = [23, 3, 3, (byte)(length >> 8), (byte)length];
        byte[] nonce = Nonce(write.Iv, write.Sequence++);
        byte[] cipher = new byte[inner.Length];
        byte[] tag = new byte[16];
        if (Suite == 0x1303)
        {
            using var c = new ChaCha20Poly1305(write.Key);
            c.Encrypt(nonce, inner, cipher, tag, header);
        }
        else
        {
            using var g = new AesGcm(write.Key, 16);
            g.Encrypt(nonce, inner, cipher, tag, header);
        }

        return [.. header, .. cipher, .. tag];
    }

    /// <summary>Application data, protected.</summary>
    /// <param name="data">The data.</param>
    /// <returns>The record.</returns>
    public byte[] SealData(byte[] data) => Seal(23, data);

    /// <summary>Sets the sequence number the server's next record is opened under: the
    /// counterpart of a test moving the server's own (<see cref="TlsServerHarness.WriteSequence"/>),
    /// so the two keep agreeing.</summary>
    /// <param name="sequence">The server's next record's sequence number.</param>
    public void SetReadSequence(ulong sequence) => read.Sequence = sequence;

    /// <summary>Our KeyUpdate, protected under the current key, then our next key (7.2).</summary>
    /// <param name="request">update_requested.</param>
    /// <returns>The record.</returns>
    public byte[] KeyUpdate(bool request)
    {
        byte[] record = Seal(22, Message(24, [(byte)(request ? 1 : 0)]));
        ClientApplication = ExpandLabel(ClientApplication, "traffic upd", [], Hash.Length);
        write = Keys(ClientApplication);
        return record;
    }

    /// <summary>A plaintext record.</summary>
    /// <param name="type">Its content type.</param>
    /// <param name="content">Its content.</param>
    /// <returns>The record.</returns>
    public static byte[] Plain(byte type, byte[] content) => [type, 3, 3, (byte)(content.Length >> 8), (byte)content.Length, .. content];

    /// <summary>A handshake message: type, uint24 length, body.</summary>
    /// <param name="type">HandshakeType.</param>
    /// <param name="body">The body.</param>
    /// <returns>The message.</returns>
    public static byte[] Message(byte type, byte[] body) => [type, (byte)(body.Length >> 16), (byte)(body.Length >> 8), (byte)body.Length, .. body];

    /// <summary>Opens one of the server's protected records.</summary>
    /// <param name="record">The record.</param>
    /// <returns>The inner type and content.</returns>
    /// <exception cref="InvalidDataException">It does not open.</exception>
    private (byte Type, byte[] Content) Open(byte[] record)
    {
        int length = record.Length - 5;
        byte[] nonce = Nonce(read.Iv, read.Sequence++);
        byte[] inner = new byte[length - 16];
        try
        {
            if (Suite == 0x1303)
            {
                using var c = new ChaCha20Poly1305(read.Key);
                c.Decrypt(nonce, record.AsSpan(5, length - 16), record.AsSpan(record.Length - 16), inner, record.AsSpan(0, 5));
            }
            else
            {
                using var g = new AesGcm(read.Key, 16);
                g.Decrypt(nonce, record.AsSpan(5, length - 16), record.AsSpan(record.Length - 16), inner, record.AsSpan(0, 5));
            }
        }
        catch (CryptographicException e)
        {
            throw new InvalidDataException("a server record does not open", e);
        }

        int last = Array.FindLastIndex(inner, b => b != 0);
        return (inner[last], inner[..last]);
    }

    /// <summary>The nonce of a record: the IV xor the sequence number (5.3).</summary>
    /// <param name="iv">The IV.</param>
    /// <param name="sequence">The sequence number.</param>
    /// <returns>The nonce.</returns>
    private static byte[] Nonce(byte[] iv, ulong sequence)
    {
        byte[] n = (byte[])iv.Clone();
        for (int i = 0; i < 8; i++)
        {
            n[11 - i] ^= (byte)(sequence >> (8 * i));
        }

        return n;
    }

    /// <summary>A traffic secret's key and IV (7.3), sequence 0.</summary>
    /// <param name="secret">The secret.</param>
    /// <returns>The keys.</returns>
    private (byte[] Key, byte[] Iv, ulong Sequence) Keys(byte[] secret) =>
        (ExpandLabel(secret, "key", [], Suite == 0x1301 ? 16 : 32), ExpandLabel(secret, "iv", [], 12), 0);

    /// <summary>HKDF-Expand-Label (7.1).</summary>
    /// <param name="secret">The secret.</param>
    /// <param name="label">The label, "tls13 " added.</param>
    /// <param name="context">The context.</param>
    /// <param name="length">The octets.</param>
    /// <returns>The expansion.</returns>
    private byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length)
    {
        byte[] full = System.Text.Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = [(byte)(length >> 8), (byte)length, (byte)full.Length, .. full, (byte)context.Length, .. context];
        return HKDF.Expand(Hash.Name, secret, length, info);
    }

    /// <summary>Derive-Secret (7.1).</summary>
    /// <param name="secret">The secret.</param>
    /// <param name="label">The label.</param>
    /// <param name="transcriptHash">The messages' hash.</param>
    /// <returns>The secret.</returns>
    private byte[] DeriveSecret(byte[] secret, string label, byte[] transcriptHash) => ExpandLabel(secret, label, transcriptHash, Hash.Length);

    /// <summary>A Finished MAC (4.5.3).</summary>
    /// <param name="baseKey">The sender's traffic secret.</param>
    /// <param name="transcriptHash">The transcript's hash.</param>
    /// <returns>verify_data.</returns>
    private byte[] FinishedMac(byte[] baseKey, byte[] transcriptHash)
    {
        byte[] key = ExpandLabel(baseKey, "finished", [], Hash.Length);
        return Hash.Length == 48 ? HMACSHA384.HashData(key, transcriptHash) : HMACSHA256.HashData(key, transcriptHash);
    }

    /// <summary>The suite's hash of octets.</summary>
    /// <param name="data">The octets.</param>
    /// <returns>The digest.</returns>
    private byte[] Digest(byte[] data) => Hash.Length == 48 ? SHA384.HashData(data) : SHA256.HashData(data);

    /// <summary>The transcript's hash so far (4.1).</summary>
    /// <returns>The hash.</returns>
    public byte[] TranscriptHash() => Digest([.. messages.SelectMany(m => m)]);

    /// <summary>Verifies a CertificateVerify signature under the server's leaf key.</summary>
    /// <param name="scheme">The SignatureScheme.</param>
    /// <param name="content">The signed content.</param>
    /// <param name="signature">The signature.</param>
    /// <returns>Whether it verifies.</returns>
    private unsafe bool Verify(ushort scheme, byte[] content, byte[] signature)
    {
        using var cert = X509CertificateLoader.LoadCertificate(Certificate);
        switch (scheme)
        {
            case 0x0804:
            case 0x0805:
            case 0x0806:
                {
                    using RSA rsa = cert.GetRSAPublicKey()!;
                    HashAlgorithmName h = scheme switch { 0x0804 => HashAlgorithmName.SHA256, 0x0805 => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
                    return rsa.VerifyData(content, signature, h, RSASignaturePadding.Pss);
                }

            case 0x0403:
            case 0x0503:
            case 0x0603:
                {
                    using ECDsa ec = cert.GetECDsaPublicKey()!;
                    HashAlgorithmName h = scheme switch { 0x0403 => HashAlgorithmName.SHA256, 0x0503 => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
                    return ec.VerifyData(content, signature, h, DSASignatureFormat.Rfc3279DerSequence);
                }

            case 0x0807:
            case 0x0808:
                {
                    byte[] key = cert.PublicKey.EncodedKeyValue.RawData;
                    fixed (byte* k = key, c = content, s = signature)
                    {
                        return scheme == 0x0807
                            ? signature.Length == 64 && Native.Ed25519Verify(k, c, (nuint)content.Length, s) == 0
                            : signature.Length == 114 && Native.Ed448Verify(k, c, (nuint)content.Length, null, 0, s) == 0;
                    }
                }

            default:
                return false;
        }
    }

    /// <summary>A uint16 big-endian.</summary>
    /// <param name="v">The value.</param>
    /// <returns>Two octets.</returns>
    public static byte[] U16(ushort v) => [(byte)(v >> 8), (byte)v];

    /// <summary>A vector with a uint16 length.</summary>
    /// <param name="c">The contents.</param>
    /// <returns>The vector.</returns>
    public static byte[] V16(params byte[] c) => [(byte)(c.Length >> 8), (byte)c.Length, .. c];

    /// <summary>A vector with a uint8 length.</summary>
    /// <param name="c">The contents.</param>
    /// <returns>The vector.</returns>
    public static byte[] V8(params byte[] c) => [(byte)c.Length, .. c];

    /// <summary>Frees the shares' keys.</summary>
    public void Dispose()
    {
        foreach (TlsShare s in shares)
        {
            s.Dispose();
        }
    }
}
