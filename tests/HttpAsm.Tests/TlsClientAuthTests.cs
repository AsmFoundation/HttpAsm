using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HttpAsm.Tests;

/// <summary>
/// Client authentication on the engine's server (RFC 9846 4.4.2, 4.5; M2 step 4c4): the
/// CertificateRequest the flight carries, the client's Certificate and CertificateVerify judged
/// and verified against the leaf's key for every kind of key the request names, the chain kept for
/// the caller (httpasm_tls13_peer_certificates), and every refusal by its alert; against the tests'
/// own client (<see cref="TlsTestClient"/>), .NET's SslStream and openssl s_client.
/// </summary>
public sealed unsafe class TlsClientAuthTests
{
    /// <summary>The server's credential (P-256), shared by the tests.</summary>
    private static readonly TlsInteropTests.Credential Server = TlsInteropTests.Make("p256");

    /// <summary>The client credentials made so far, by kind (each made once for the class).</summary>
    private static readonly Dictionary<string, TlsInteropTests.Credential> Clients = [];

    /// <summary>The schemes the CertificateRequest lists, in its order (tls/sign.asm's ha_tls_request).</summary>
    private static readonly ushort[] Requested = [0x0403, 0x0807, 0x0503, 0x0808, 0x0603, 0x0804, 0x0805, 0x0806, 0x0809, 0x080A, 0x080B];

    /// <summary>A client credential of a kind, made on first use (.NET's for the NIST curves and
    /// RSA, openssl's for RSASSA-PSS and EdDSA).</summary>
    /// <param name="kind">The kind (TlsInteropTests.Make's or TlsOpenSslCliTests.Make's names).</param>
    /// <returns>The credential.</returns>
    private static TlsInteropTests.Credential Client(string kind)
    {
        lock (Clients)
        {
            if (!Clients.TryGetValue(kind, out TlsInteropTests.Credential? c))
            {
                c = kind is "p256" or "p384" or "p521" or "rsa2048" ? TlsInteropTests.Make(kind) : TlsOpenSslCliTests.Make(kind);
                Clients[kind] = c;
            }

            return c;
        }
    }

    /// <summary>A test client that answers a CertificateRequest with a credential's certificate
    /// (and the extra chain) and signs with its key.</summary>
    /// <param name="kind">The credential's kind.</param>
    /// <param name="extra">Certificates after the leaf.</param>
    /// <returns>The client.</returns>
    private static TlsTestClient ClientWith(string kind, params byte[][] extra)
    {
        TlsInteropTests.Credential c = Client(kind);
        return new TlsTestClient { ClientChain = [c.Certificate, .. extra], ClientKey = TlsTestClient.ClientSigner(kind, c.Key) };
    }

    /// <summary>Every kind of client key the request names, each kind of signature verified.</summary>
    /// <returns>The kinds.</returns>
    public static TheoryData<string> Kinds() => ["p256", "p384", "p521", "rsa2048", "rsa-pss", "ed25519", "ed448"];

    /// <summary>
    /// A client of each key kind authenticates (HTTPASM_TLS_CLIENT_AUTH_REQUIRE): the server's
    /// flight carried a CertificateRequest right after EncryptedExtensions with an empty context
    /// and signature_algorithms listing the 11 schemes the engine verifies; the client's
    /// Certificate (its leaf and a second certificate after it) and CertificateVerify (ECDSA
    /// DER, RSA-PSS rsae and pss, Ed25519, Ed448) are taken, its Finished over all of them
    /// verifies, and the connection keeps the chain as the client sent it (2 entries, walked by
    /// the library's own reader, octet for octet). Before the client's Certificate the chain is
    /// not there (-1); data flows after.
    /// </summary>
    /// <param name="kind">The client key's kind.</param>
    [Theory]
    [MemberData(nameof(Kinds))]
    [Requirement("RFC9846-4.4.2-1#2", "RFC9846-4.4.2-4.2.1#2", "RFC9846-4.4.2-4.4.1#1", "RFC9846-4.5.1-3#1", "RFC9846-4.5.2-15", "RFC9846-4.5.2-17")]
    public void AuthenticatesEveryKindOfClientKey(string kind)
    {
        Platform.RequireLinuxX64();
        byte[] second = TlsInteropTests.Make("p384").Certificate;
        using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequire);
        using TlsTestClient client = ClientWith(kind, second);
        Assert.True(server.Receive(client.Hello()).Answer > 0);
        client.Take(server.TakeOutput());
        Assert.True(client.ServerFinished);
        Assert.Empty(client.RequestContext!);
        Assert.Equal(Requested, client.RequestedSchemes);
        Assert.Equal(-1, server.PeerCertificates().Count);
        foreach (TlsServerHarness.Received f in server.ReceiveAll(client.Finished()))
        {
            Assert.True(f.Answer > 0, $"{kind}: the client's flight: alert {f.Event.Alert}");
        }

        Assert.Equal(2, server.Progress());
        Assert.Equal(2, server.PeerCertificates().Count);
        Assert.Equal(2, server.PeerCount());                              // (the out pointers NULL)
        Assert.Equal([Client(kind).Certificate, second], server.PeerChain());
        byte[] data = RandomNumberGenerator.GetBytes(300);
        Assert.Equal(data, server.Receive(client.SealData(data)).Data);
    }

    /// <summary>
    /// A client that declines (an empty Certificate, then its Finished, no CertificateVerify:
    /// RFC 9846 4.5.1-3#2, -3#3) is taken under HTTPASM_TLS_CLIENT_AUTH_REQUEST: the connection
    /// completes, its chain is empty (0 entries); under HTTPASM_TLS_CLIENT_AUTH_REQUIRE it is
    /// certificate_required (4.5.1.3-3#1). Without client authentication configured the flight
    /// asks nothing and the chain is never there (-1); a configuration that turns client
    /// authentication on after the connection started (no peer-chain span) asks nothing either.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.5.1-3#2", "RFC9846-4.5.1-3#3", "RFC9846-4.5.1.3-3#1")]
    public void TakesOrRefusesAClientThatDeclines()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest))
        using (var client = new TlsTestClient())
        {
            TlsServerRulesTests.Complete(server, client);
            Assert.NotNull(client.RequestContext);
            Assert.Equal(0, server.PeerCertificates().Count);
            Assert.Empty(server.PeerCertificates().List);
            Assert.Empty(server.PeerChain());
        }

        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequire))
        using (var client = new TlsTestClient())
        {
            Assert.True(server.Receive(client.Hello()).Answer > 0);
            client.Take(server.TakeOutput());
            byte[] flight = client.Finished();
            TlsServerHarness.Received r = server.ReceiveAll(flight).Last();
            TlsServerRulesTests.Refused(server, client, r, 116, "an empty Certificate when one is required");
        }

        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate]))
        using (var client = new TlsTestClient())
        {
            TlsServerRulesTests.Complete(server, client);
            Assert.Null(client.RequestContext);
            Assert.Equal(-1, server.PeerCertificates().Count);
            Assert.Equal(-1, server.PeerCount());
        }

        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate]))
        using (var client = new TlsTestClient())
        {
            server.EditConfig(c => c->Flags = TlsEngine.ClientAuthRequire);
            TlsServerRulesTests.Complete(server, client);
            Assert.Null(client.RequestContext);
        }
    }

    /// <summary>A DER ECDSA-Sig-Value { r, s } of the given INTEGER encodings (each its tag,
    /// length and contents as given), in a SEQUENCE of the given length form.</summary>
    /// <param name="integers">The INTEGERs' encodings.</param>
    /// <param name="longForm">Whether the SEQUENCE's length takes the long form (81 n).</param>
    /// <returns>The encoding.</returns>
    private static byte[] Der(byte[] integers, bool longForm = false) =>
        longForm ? [0x30, 0x81, (byte)integers.Length, .. integers] : [0x30, (byte)integers.Length, .. integers];

    /// <summary>
    /// What a client's authentication may not be, each by the alert RFC 9846 names, the server
    /// requiring a certificate: a context other than the request's (illegal_parameter); an
    /// extension in an entry, which the request did not ask for (unsupported_extension,
    /// 4.5.1-6.6.1#2); a cert_data that is no certificate, first or second (bad_certificate); a
    /// leaf with a key the engine has no verifier for, X25519's (unsupported_certificate); a
    /// CertificateVerify naming a scheme the request did not list (rsa_pkcs1_sha256), or one the
    /// key does not make (P-384's with a P-256 key, rsae with an RSASSA-PSS key, pss with an
    /// rsaEncryption key, pss_sha384 with a key bound to SHA-256, any with a key whose minimum salt
    /// passes the hash's length) (illegal_parameter, 4.5.2-15, -16#1); a signature that does not
    /// verify, for every kind of key (decrypt_error, 4.5.2-19); ECDSA DER that is not strict
    /// (a 00 the sign does not need, a negative INTEGER, an empty one, r longer than the curve's,
    /// a long-form length for a short content, a SEQUENCE shorter or longer than the signature,
    /// a third INTEGER, the wrong tag) and EdDSA signatures of the wrong length (decrypt_error);
    /// a CertificateVerify left out (the Finished then unexpected_message); a Certificate or
    /// CertificateVerify that does not parse (decode_error); a Finished in place of the
    /// Certificate (unexpected_message). Each alert sealed under the handshake key.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.5.1-6.6.1#2", "RFC9846-4.5.2-1#2", "RFC9846-4.5.2-15", "RFC9846-4.5.2-16#1", "RFC9846-4.5.2-19")]
    public void RefusesWhatAClientsAuthenticationMayNotBe()
    {
        Platform.RequireLinuxX64();
        // an X25519 key in a leaf (RFC 8410), signed by a P-256 issuer
        using ECDsa issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x25519 = new System.Security.Cryptography.X509Certificates.PublicKey(new Oid("1.3.101.110"), null, new AsnEncodedData(RandomNumberGenerator.GetBytes(32)));
        var request = new CertificateRequest(new X500DistinguishedName("CN=client"), x25519, HashAlgorithmName.SHA256);
        using X509Certificate2 x25519Leaf = request.Create(new X500DistinguishedName("CN=issuer"), X509SignatureGenerator.CreateForECDsa(issuer),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), [7]);

        byte[] r32 = [0x02, 0x20, 0x11, .. new byte[31]];             // a 32-octet INTEGER, positive
        var cases = new (string What, Func<TlsTestClient> Make, uint Alert)[]
        {
            ("another context", () => { TlsTestClient c = ClientWith("p256"); c.AnswerContext = [1]; return c; }, 47),
            ("an extension in the leaf's entry", () => { TlsTestClient c = ClientWith("p256"); c.LeafExtensions = [0, 18, 0, 0]; return c; }, 110),
            ("a leaf that is no certificate", () => new TlsTestClient { ClientChain = [[0x30, 0x03, 0x02, 0x01, 0x01]], ClientKey = TlsTestClient.ClientSigner("p256", Client("p256").Key) }, 42),
            ("a second that is no certificate", () => ClientWith("p256", new byte[] { 0x30, 0x00 }), 42),
            ("a leaf with an X25519 key", () => new TlsTestClient { ClientChain = [x25519Leaf.RawData], ClientKey = TlsTestClient.ClientSigner("p256", Client("p256").Key) }, 43),
            ("a scheme not requested", () => { TlsTestClient c = ClientWith("p256"); c.AnswerScheme = 0x0401; return c; }, 47),
            ("P-384's scheme with a P-256 key", () => { TlsTestClient c = ClientWith("p256"); c.AnswerScheme = 0x0503; return c; }, 47),
            ("Ed448's scheme with an Ed25519 key", () => { TlsTestClient c = ClientWith("ed25519"); c.AnswerScheme = 0x0808; return c; }, 47),
            ("P-521's scheme with a P-384 key", () => { TlsTestClient c = ClientWith("p384"); c.AnswerScheme = 0x0603; return c; }, 47),
            ("Ed25519's scheme with a P-256 key", () => { TlsTestClient c = ClientWith("p256"); c.AnswerScheme = 0x0807; return c; }, 47),
            ("ECDSA's scheme with an Ed25519 key", () => { TlsTestClient c = ClientWith("ed25519"); c.AnswerScheme = 0x0403; return c; }, 47),
            ("rsae with an RSASSA-PSS key", () => { TlsTestClient c = ClientWith("rsa-pss"); c.AnswerScheme = 0x0804; return c; }, 47),
            ("pss with an rsaEncryption key", () => { TlsTestClient c = ClientWith("rsa2048"); c.AnswerScheme = 0x0809; return c; }, 47),
            ("pss_sha384 with a key bound to SHA-256", () => { TlsTestClient c = ClientWith("rsa-pss-sha256"); c.AnswerScheme = 0x080A; return c; }, 47),
            ("a key whose minimum salt passes the hash's", () => ClientWith("rsa-pss-sha256-salt64"), 47),
            ("an RSA scheme with a P-256 key", () => { TlsTestClient c = ClientWith("p256"); c.AnswerScheme = 0x0805; return c; }, 47),
            ("ECDSA P-256: a signature that does not verify", () => { TlsTestClient c = ClientWith("p256"); c.CorruptSignature = true; return c; }, 51),
            ("ECDSA P-384: likewise", () => { TlsTestClient c = ClientWith("p384"); c.CorruptSignature = true; return c; }, 51),
            ("ECDSA P-521: likewise", () => { TlsTestClient c = ClientWith("p521"); c.CorruptSignature = true; return c; }, 51),
            ("RSA-PSS rsae: likewise", () => { TlsTestClient c = ClientWith("rsa2048"); c.CorruptSignature = true; return c; }, 51),
            ("RSA-PSS pss: likewise", () => { TlsTestClient c = ClientWith("rsa-pss"); c.CorruptSignature = true; return c; }, 51),
            ("Ed25519: likewise", () => { TlsTestClient c = ClientWith("ed25519"); c.CorruptSignature = true; return c; }, 51),
            ("Ed448: likewise", () => { TlsTestClient c = ClientWith("ed448"); c.CorruptSignature = true; return c; }, 51),
            ("Ed25519: 63 octets", () => Signed("ed25519", 0x0807, s => s[..63]), 51),
            ("Ed448: 113 octets", () => Signed("ed448", 0x0808, s => s[..113]), 51),
            ("DER: a 00 the sign does not need", () => Signed("p256", 0x0403, _ => Der([0x02, 0x21, 0x00, 0x11, .. new byte[31], .. r32])), 51),
            ("DER: a negative INTEGER", () => Signed("p256", 0x0403, _ => Der([0x02, 0x20, 0x91, .. new byte[31], .. r32])), 51),
            ("DER: an empty INTEGER", () => Signed("p256", 0x0403, _ => Der([0x02, 0x00, .. r32])), 51),
            ("DER: r longer than the curve's", () => Signed("p256", 0x0403, _ => Der([0x02, 0x21, 0x11, .. new byte[32], .. r32])), 51),
            ("DER: a long-form length for a short content", () => Signed("p256", 0x0403, _ => Der([.. r32, .. r32], longForm: true)), 51),
            ("DER: the SEQUENCE shorter than the signature", () => Signed("p256", 0x0403, _ => [.. Der([.. r32, .. r32]), 0]), 51),
            ("DER: the SEQUENCE longer than the signature", () => Signed("p256", 0x0403, _ => Der([.. r32, .. r32])[..^1]), 51),
            ("DER: a third INTEGER", () => Signed("p256", 0x0403, _ => Der([.. r32, .. r32, 0x02, 0x01, 0x01])), 51),
            ("DER: the wrong tag", () => Signed("p256", 0x0403, _ => [0x31, .. Der([.. r32, .. r32])[1..]]), 51),
            ("DER: an INTEGER of the wrong tag", () => Signed("p256", 0x0403, _ => Der([0x03, .. r32[1..], .. r32])), 51),
            ("DER: an INTEGER cut by the end", () => Signed("p256", 0x0403, _ => Der([.. r32, 0x02, 0x20, 0x11])), 51),
            ("DER: a long-form length of 81 with nothing after", () => Signed("p256", 0x0403, _ => [0x30, 0x81]), 51),
            ("DER: an INTEGER's tag alone", () => Signed("p256", 0x0403, _ => Der([0x02])), 51),
            ("DER: an INTEGER's long-form length", () => Signed("p256", 0x0403, _ => Der([0x02, 0x81, 0x20, 0x11, .. new byte[31], .. r32])), 51),
            ("DER: r of one octet (strict, and it does not verify)", () => Signed("p256", 0x0403, _ => Der([0x02, 0x01, 0x01, .. r32])), 51),
            ("DER: s missing", () => Signed("p256", 0x0403, _ => Der(r32)), 51),
            ("DER: one octet", () => Signed("p256", 0x0403, _ => [0x30]), 51),
            ("DER: a long form of two octets", () => Signed("p256", 0x0403, _ => [0x30, 0x82, 0x00, 0x44, .. r32, .. r32]), 51),
            ("no CertificateVerify", () => { TlsTestClient c = ClientWith("p256"); c.OmitCertificateVerify = true; return c; }, 10),
        };
        foreach ((string what, Func<TlsTestClient> make, uint alert) in cases)
        {
            using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequire);
            using TlsTestClient client = make();
            Assert.True(server.Receive(client.Hello()).Answer > 0, what);
            client.Take(server.TakeOutput());
            TlsServerHarness.Received r = server.ReceiveAll(client.Finished()).Last();
            TlsServerRulesTests.Refused(server, client, r, alert, what);
        }

        // messages out of place or not parsing, sent by hand into the waiting states
        var raw = new (string What, bool AfterCertificate, Func<TlsTestClient, byte[]> Make, uint Alert)[]
        {
            ("a Finished in place of the Certificate", false, c => c.Seal(22, TlsTestClient.Message(20, new byte[32])), 10),
            ("a Certificate that does not parse", false, c => c.Seal(22, TlsTestClient.Message(11, [0, 0, 0, 5])), 50),
            ("a CertificateVerify that does not parse", true, c => c.Seal(22, TlsTestClient.Message(15, [4, 3])), 50),
            ("a second Certificate in place of the CertificateVerify", true, c => c.Seal(22, TlsTestClient.Message(11, [0, 0, 0, 0])), 10),
        };
        foreach ((string what, bool after, Func<TlsTestClient, byte[]> make, uint alert) in raw)
        {
            using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequire);
            using TlsTestClient client = ClientWith("p256");
            Assert.True(server.Receive(client.Hello()).Answer > 0, what);
            client.Take(server.TakeOutput());
            if (after)
            {
                // a Certificate with the client's leaf, sealed by hand under the client's
                // handshake key (Finished() would move the client to its application key), then
                // the case under the same key
                byte[] leaf = Client("p256").Certificate;
                byte[] certificate = TlsTestClient.Message(11, [0, .. TlsTestClient.U24(leaf.Length + 5), .. TlsTestClient.U24(leaf.Length), .. leaf, 0, 0]);
                Assert.True(server.Receive(client.Seal(22, certificate)).Answer > 0, what);
            }

            TlsServerRulesTests.Refused(server, client, server.Receive(make(client)), alert, what);
        }
    }

    /// <summary>A client of a key kind whose CertificateVerify carries a signature reshaped by the
    /// test (the real one in, what is sent out).</summary>
    /// <param name="kind">The key kind.</param>
    /// <param name="scheme">The scheme named.</param>
    /// <param name="shape">The reshaping.</param>
    /// <returns>The client.</returns>
    private static TlsTestClient Signed(string kind, ushort scheme, Func<byte[], byte[]> shape)
    {
        TlsInteropTests.Credential c = Client(kind);
        (ushort _, Func<byte[], byte[]> sign) = TlsTestClient.ClientSigner(kind, c.Key);
        return new TlsTestClient { ClientChain = [c.Certificate], ClientKey = (scheme, content => shape(sign(content))) };
    }

    /// <summary>
    /// The CertificateRequest held to the output's room like every flight message: an
    /// output_min edited down (and max_message beside it, so the reassembly and peer-chain spans
    /// with it still fit server_init's bounds) to one octet short of the request's put after the
    /// ServerHello (95 octets: x25519, no session id) and EncryptedExtensions - internal_error, its
    /// alert in the reserve under the handshake key, nothing written past the spans.
    /// </summary>
    [Fact]
    public void KeepsInsideItsSpansWhenTheRequestDoesNotFit()
    {
        Platform.RequireLinuxX64();
        int ee;
        using (var whole = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest))
        using (var client = new TlsTestClient())
        {
            TlsServerRulesTests.Complete(whole, client);
            ee = 4 + client.EncryptedExtensions.Length;
        }

        // the output span: 95 + EncryptedExtensions + the request (35) + a record's 22 + the
        // reserve's 64, less one; max_message halves what is left (the two spans its size)
        int octets = 95 + ee + 35 + 22 + 64 - 1;
        octets += octets & 1;                                               // (an even rest to halve)
        octets -= 2;                                                        // (still short of the put)
        using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest, beforeStart: c =>
        {
            c->MaxMessage = (uint)((c->Memory - (nuint)octets) / 2);
            c->OutputMin = (nuint)octets;
        });
        using var asked = new TlsTestClient();
        TlsServerHarness.Received r = server.Receive(asked.Hello());
        Assert.True(r.Answer == -1 && r.Event.Alert == 80, $"the request's put: answer {r.Answer}, alert {r.Event.Alert}");
        asked.Take(server.TakeOutput());
        Assert.Equal([((byte)2, (byte)80)], asked.Alerts);
        Assert.Null(asked.RequestContext);
    }

    /// <summary>
    /// A CertificateVerify after an empty Certificate (the client declined, then signed anyway:
    /// 4.5.2-1#2 sends one only with certificates) is unexpected_message, under
    /// HTTPASM_TLS_CLIENT_AUTH_REQUEST.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.5.2-1#2")]
    public void RefusesAVerifyForNoCertificate()
    {
        Platform.RequireLinuxX64();
        using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest);
        using var client = new TlsTestClient { VerifyEmpty = true, ClientKey = TlsTestClient.ClientSigner("p256", Client("p256").Key) };
        Assert.True(server.Receive(client.Hello()).Answer > 0);
        client.Take(server.TakeOutput());
        TlsServerRulesTests.Refused(server, client, server.ReceiveAll(client.Finished()).Last(), 10, "a CertificateVerify for no certificate");
    }

    /// <summary>
    /// .NET's SslStream as the client (OpenSSL 3 on Linux), its certificate given: RSA (it signs
    /// rsa_pss_rsae_sha256), P-256, P-384 and P-521 keys each authenticate under
    /// HTTPASM_TLS_CLIENT_AUTH_REQUIRE, the engine keeping the certificate SslStream sent. Without
    /// a certificate: under REQUEST the handshake completes with no chain (0 entries); under
    /// REQUIRE SslStream's handshake fails (the engine sent certificate_required).
    /// </summary>
    /// <param name="kind">The client key's kind, or "none".</param>
    /// <param name="require">REQUIRE (or REQUEST).</param>
    [Theory]
    [InlineData("rsa2048", true)]
    [InlineData("p256", true)]
    [InlineData("p384", true)]
    [InlineData("p521", true)]
    [InlineData("none", false)]
    [InlineData("none", true)]
    public void AuthenticatesSslStreamsCertificate(string kind, bool require)
    {
        Platform.RequireLinuxX64();
        using X509Certificate2? certificate = kind == "none" ? null : WithKey(kind);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: require ? TlsEngine.ClientAuthRequire : TlsEngine.ClientAuthRequest);
        var served = new TlsInteropTests.Served();
        var pump = new Thread(() =>
        {
            using Socket s = listener.AcceptSocket();
            TlsInteropTests.Serve(server, s, 0, served);
        }) { IsBackground = true };
        pump.Start();

        Exception? failure = SslClient(port, certificate);
        Assert.True(pump.Join(TimeSpan.FromSeconds(30)), "the server pump did not finish");
        if (kind == "none" && require)
        {
            Assert.NotNull(failure);
            Assert.True(served.Failure is not null && served.Failure.Contains("116", StringComparison.Ordinal), served.Failure);
            return;
        }

        Assert.True(failure is null, $"{kind}: {failure}\n{served.Failure}");
        Assert.Null(served.Failure);
        if (certificate is null)
        {
            Assert.Equal(0, server.PeerCertificates().Count);
        }
        else
        {
            Assert.Equal([certificate.RawData], server.PeerChain());
        }
    }

    /// <summary>
    /// SslStream's side of a client-authenticated handshake: connect, authenticate (the client's
    /// certificate given, or none), then one octet both ways (TLS 1.3's client finishes before the
    /// server has judged its certificate: the echo proves the server took it), and both
    /// close_notifys.
    /// </summary>
    /// <param name="port">The server's port.</param>
    /// <param name="certificate">The client's certificate with its key, or null.</param>
    /// <returns>Null when all of it went through; the exception when the handshake or the echo
    /// failed (an alert from the server).</returns>
    private static Exception? SslClient(int port, X509Certificate2? certificate)
    {
        using var tcp = new TcpClient();
        tcp.NoDelay = true;
        tcp.Connect(IPAddress.Loopback, port);
        using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, c, _, _) => c is not null && c.GetRawCertData().AsSpan().SequenceEqual(Server.Certificate),
            ClientCertificates = certificate is null ? [] : [certificate],
        };
        try
        {
            tls.AuthenticateAsClient(options);
            tls.Write([42]);
            tls.Flush();
            byte[] one = new byte[1];
            if (tls.Read(one, 0, 1) != 1)
            {
                return new IOException("no echo");
            }

            tls.ShutdownAsync().GetAwaiter().GetResult();               // close_notify
            _ = tls.Read(new byte[16], 0, 16);
            return null;
        }
        catch (Exception e) when (e is AuthenticationException or IOException)
        {
            return e;
        }
    }

    /// <summary>A .NET certificate with its private key, for SslStream's ClientCertificates.</summary>
    /// <param name="kind">"rsa2048", "p256", "p384" or "p521".</param>
    /// <returns>The certificate (the caller disposes it).</returns>
    private static X509Certificate2 WithKey(string kind)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (kind == "rsa2048")
        {
            using RSA rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using X509Certificate2 self = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
            return X509CertificateLoader.LoadPkcs12(self.Export(X509ContentType.Pfx), null);
        }

        ECCurve curve = kind switch { "p256" => ECCurve.NamedCurves.nistP256, "p384" => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 };
        using ECDsa ec = ECDsa.Create(curve);
        var ecRequest = new CertificateRequest("CN=client", ec, HashAlgorithmName.SHA256);
        using X509Certificate2 ecSelf = ecRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        // (a PKCS#12 round trip: SslStream on Linux wants a key it can hand OpenSSL)
        return X509CertificateLoader.LoadPkcs12(ecSelf.Export(X509ContentType.Pfx), null);
    }

    /// <summary>
    /// openssl s_client as the client, its certificate and key given (-cert, -key): RSA
    /// (rsa_pss_rsae), RSASSA-PSS (rsa_pss_pss), P-256, P-384, P-521, Ed25519 and Ed448 keys each
    /// authenticate under HTTPASM_TLS_CLIENT_AUTH_REQUIRE, the line comes back, and the engine
    /// keeps the certificate s_client sent.
    /// </summary>
    /// <param name="kind">The client key's kind (TlsOpenSslCliTests.Make's).</param>
    [Theory]
    [InlineData("rsa")]
    [InlineData("rsa-pss")]
    [InlineData("p256")]
    [InlineData("p384")]
    [InlineData("p521")]
    [InlineData("ed25519")]
    [InlineData("ed448")]
    public void AuthenticatesOpenSslsCertificate(string kind)
    {
        Platform.RequireLinuxX64();
        TlsInteropTests.Credential client = kind is "p256" or "p384" or "p521" ? TlsOpenSslCliTests.Make(kind) : Client(kind);
        string directory = Directory.CreateTempSubdirectory("httpasm-client-").FullName;
        try
        {
            string cert = Path.Combine(directory, "client.der"), key = Path.Combine(directory, "client.pem");
            File.WriteAllBytes(cert, client.Certificate);
            File.WriteAllBytes(key, client.Key);
            List<byte[]> chain = [];
            TlsOpenSslCliTests.SClientRun run = TlsOpenSslCliTests.SClient(Server, $"-cert {cert} -certform DER -key {key}", ["hello\n"],
                flags: TlsEngine.ClientAuthRequire, inspect: s => chain = s.PeerChain());
            Assert.Contains("hello", run.Out, StringComparison.Ordinal);
            Assert.Equal([client.Certificate], chain);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
