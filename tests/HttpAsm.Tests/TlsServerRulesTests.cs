using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// The engine's server against the tests' own TLS 1.3 client (<see cref="TlsTestClient"/>,
/// written apart from the engine): every group (the post-quantum hybrids OpenSSL 3.0 lacks among
/// them), retries, and the rules: each message the state machine may not take where it comes,
/// each refusal of a hello, a share or a record by the alert its document names.
/// </summary>
public sealed class TlsServerRulesTests
{
    /// <summary>A P-256 credential shared by the tests (made once: key generation is the slow part).</summary>
    private static readonly TlsInteropTests.Credential P256 = TlsInteropTests.Make("p256");

    /// <summary>Runs a handshake between the test client and a server to its end, retry
    /// included: hello, the server's answer, maybe a second hello and answer, the client's
    /// Finished. Asserts each step went as a good handshake goes.</summary>
    /// <param name="server">The server.</param>
    /// <param name="client">The client.</param>
    internal static void Complete(TlsServerHarness server, TlsTestClient client)
    {
        TlsServerHarness.Received r = server.Receive(client.Hello());
        Assert.True(r.Answer > 0, $"the hello: alert {r.Event.Alert}");
        client.Take(server.TakeOutput());
        if (client.Retried && !client.ServerFinished)
        {
            r = server.Receive(client.Hello());
            Assert.True(r.Answer > 0, $"the second hello: alert {r.Event.Alert}");
            client.Take(server.TakeOutput());
        }

        Assert.True(client.ServerFinished, "the server's flight did not verify");
        foreach (TlsServerHarness.Received f in server.ReceiveAll(client.Finished()))
        {
            Assert.True(f.Answer > 0, $"the client's Finished: alert {f.Event.Alert}");
            if (f.Event.Kind == TlsEngine.EventConnected)
            {
                return;
            }
        }

        Assert.Fail("the server did not connect");
    }

    /// <summary>Every group, by name for the test's display.</summary>
    /// <returns>(the group, its share's octets) for each.</returns>
    public static TheoryData<ushort, int> AllGroups() => new()
    {
        { TlsEngine.X25519, 32 }, { TlsEngine.X448, 56 }, { TlsEngine.Secp256r1, 32 }, { TlsEngine.Secp384r1, 48 }, { TlsEngine.Secp521r1, 66 },
        { 0x0100, 29 }, { 0x0101, 35 }, { 0x0102, 41 }, { 0x0103, 47 }, { 0x0104, 50 },
        { TlsEngine.X25519MlKem768, 0 }, { TlsEngine.Secp256r1MlKem768, 0 }, { TlsEngine.Secp384r1MlKem1024, 0 },
    };

    /// <summary>
    /// Every group the engine has, the client sharing it alone: the handshake completes (the
    /// client's own key schedule opens the flight and verifies its CertificateVerify and
    /// Finished), data goes both ways, and the engine names the group. For the hybrids the
    /// shares and secrets are RFC 10024's orders: a server writing ML-KEM's part where X25519's
    /// goes would make a secret the client's decapsulation cannot match. The engine's draws are
    /// the random, the share's private parts in the share's order (ECDH scalar or exponent; for
    /// the hybrids ML-KEM's 32-octet m with the ECDH scalar on the side the share puts it), then
    /// the signature's hedge.
    /// </summary>
    /// <param name="group">The group.</param>
    /// <param name="scalar">The ECDH or finite-field draw's octets (0 for the hybrids: listed in the test).</param>
    [Theory]
    [MemberData(nameof(AllGroups))]
    [Requirement("RFC9846-4.3.8-19#1", "RFC9846-4.3.8-19#2", "RFC9846-4.3.8-11#1")]
    public void ShakesHandsInEveryGroup(ushort group, int scalar)
    {
        Platform.RequireLinuxX64();
        using var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
        using var client = new TlsTestClient { Groups = [group], ShareGroups = [group] };
        Complete(server, client);
        Assert.Equal(group, client.Group);
        Assert.Equal((2, 0x1301u, (uint)group, 0x0403u), server.Negotiated());
        int[] draws = group switch
        {
            TlsEngine.X25519MlKem768 => [32, 32, 32, 32],          // random, m, the X25519 scalar, the hedge
            TlsEngine.Secp256r1MlKem768 => [32, 32, 32, 32],       // random, the P-256 scalar, m, the hedge
            TlsEngine.Secp384r1MlKem1024 => [32, 48, 32, 32],
            _ => [32, scalar, 32],
        };
        Assert.Equal(draws, server.Random.Lengths);

        byte[] data = RandomNumberGenerator.GetBytes(5000);
        TlsServerHarness.Received r = server.Receive(client.SealData(data));
        Assert.Equal(TlsEngine.EventData, r.Event.Kind);
        Assert.Equal(data, r.Data);
        SendAll(server, client, data);
        Assert.Equal(data, client.Data.SelectMany(d => d).ToArray());
    }

    /// <summary>Sends data through the engine to the client whole: send takes what the output
    /// span holds, so the output goes to the client and the rest is sent, round after round.</summary>
    /// <param name="server">The server.</param>
    /// <param name="client">The client, which takes every record.</param>
    /// <param name="data">The data.</param>
    internal static void SendAll(TlsServerHarness server, TlsTestClient client, ReadOnlySpan<byte> data)
    {
        while (data.Length > 0)
        {
            long taken = server.Send(data);
            Assert.True(taken > 0, $"send took {taken} with the output drained");
            client.Take(server.TakeOutput());
            data = data[(int)taken..];
        }
    }

    /// <summary>
    /// A client that supports X25519MLKEM768 but shares x25519 only, against a server whose order
    /// rules with the hybrid first: the server asks for the hybrid (HelloRetryRequest), the
    /// second hello's hybrid share is taken; without the flag the x25519 share is taken at once.
    /// </summary>
    /// <param name="ordered">Whether the server's order rules.</param>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("RFC9846-4.2.4-2#1")]
    public void RetriesForTheHybridWhenItsOrderRules(bool ordered)
    {
        Platform.RequireLinuxX64();
        using var server = new TlsServerHarness(P256.Key, [P256.Certificate], flags: ordered ? TlsEngine.ServerGroupOrder : 0);
        using var client = new TlsTestClient { Groups = [TlsEngine.X25519MlKem768, TlsEngine.X25519], ShareGroups = [TlsEngine.X25519] };
        Complete(server, client);
        Assert.Equal(ordered, client.Retried);
        Assert.Equal(ordered ? TlsEngine.X25519MlKem768 : TlsEngine.X25519, client.Group);
    }

    /// <summary>Asserts a call failed with our alert: -1, FAILED, the alert, not the peer's; that
    /// the alert went out as one fatal record the client reads; and that the connection answers
    /// the same again.</summary>
    /// <param name="server">The server.</param>
    /// <param name="client">The client (it reads the alert record).</param>
    /// <param name="r">The failing call's answer.</param>
    /// <param name="alert">The alert expected.</param>
    /// <param name="what">The case, for the message.</param>
    internal static void Refused(TlsServerHarness server, TlsTestClient client, TlsServerHarness.Received r, uint alert, string what)
    {
        Assert.True(r.Answer == -1 && r.Event.Kind == TlsEngine.EventFailed && r.Event.Alert == alert && r.Event.Flags == 0,
            $"{what}: answer {r.Answer}, event {r.Event.Kind}, alert {r.Event.Alert} (expected {alert}), flags {r.Event.Flags}");
        client.Take(server.TakeOutput());
        Assert.True(client.Alerts.Count == 1 && client.Alerts[0] == (2, (byte)alert), $"{what}: the alerts sent: {string.Join(",", client.Alerts)}");
        TlsServerHarness.Received again = server.Receive(TlsTestClient.Plain(22, TlsTestClient.Message(1, [3, 3])));
        Assert.True(again.Answer == -1 && again.Event.Alert == alert, $"{what}: a later call answered {again.Answer}, alert {again.Event.Alert}");
        Assert.Empty(server.TakeOutput());
        Assert.Equal(-1, server.Negotiated().Progress);
    }

    /// <summary>A server and a client shaped by a test, its hello sent: the server's answer.</summary>
    /// <param name="shape">Shapes the client before its hello.</param>
    /// <param name="groups">The server's groups (null: the library's).</param>
    /// <param name="flags">The server's flags.</param>
    /// <param name="maxMessage">The server's max_message (0: the default).</param>
    /// <returns>Both sides and the answer.</returns>
    private static (TlsServerHarness Server, TlsTestClient Client, TlsServerHarness.Received Answer) Hello(Action<TlsTestClient> shape,
        ushort[]? groups = null, uint flags = 0, uint maxMessage = 0)
    {
        var server = new TlsServerHarness(P256.Key, [P256.Certificate], groups: groups, flags: flags, maxMessage: maxMessage);
        var client = new TlsTestClient();
        shape(client);
        return (server, client, server.Receive(client.Hello()));
    }

    /// <summary>
    /// The ClientHellos the server refuses, each by the alert RFC 9846 names: a legacy_version
    /// other than 0x0303, no TLS 1.3 among the versions, or no supported_versions
    /// (protocol_version: 4.2.2, and 4.2.1 until M3 speaks 1.2); no
    /// suite in common, no scheme the key makes, no group in common (handshake_failure, 4.2.1);
    /// signature_algorithms, supported_groups or key_share missing without a PSK
    /// (missing_extension, 9.2); a share for a group the client does not list (illegal_parameter,
    /// 4.3.8's MAY); and a share each group refuses: X25519's and X448's all-zero secrets, a
    /// NIST curve's point off the curve (P-256, P-384, P-521, and the hybrids' P-256 and P-384
    /// halves) or compressed, a finite field's Y of 1 and of p - 1, an ML-KEM key failing the
    /// modulus check (each hybrid's), the X25519 half of X25519MLKEM768 making a zero secret,
    /// and a share of the wrong length in every group (illegal_parameter: 4.3.8.1, 4.3.8.2,
    /// 7.4.2, RFC 10024 4.2). Each alert goes out in the clear (no keys yet) and the connection
    /// stays failed.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.2.1-3", "RFC9846-4.2.1-8", "RFC9846-4.3.8-10#4", "RFC9846-4.3.8.1-3", "RFC9846-4.3.8.2-5", "RFC9846-9.2-6.1.1", "RFC9846-9.2-6.2.1", "RFC9846-4.2.2-7.2.1#2")]
    public void RefusesTheHellosItMust()
    {
        Platform.RequireLinuxX64();
        byte[] pMinus1 = (FfdheTests.Prime(2048) - 1).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] badKem = new byte[1184 + 32];
        badKem[0] = 0xFF;
        badKem[1] = 0x0F;                                           // a coefficient of 4095 >= q
        RandomNumberGenerator.Fill(badKem.AsSpan(1184));
        byte[] p256 = new TlsShare(TlsEngine.Secp256r1).Public;
        byte[] offCurve = (byte[])p256.Clone();
        offCurve[^1] ^= 1;
        byte[] p384 = new TlsShare(TlsEngine.Secp384r1).Public;
        byte[] p384Off = (byte[])p384.Clone();
        p384Off[^1] ^= 1;
        byte[] p521 = new TlsShare(TlsEngine.Secp521r1).Public;
        byte[] p521Off = (byte[])p521.Clone();
        p521Off[^1] ^= 1;
        // the hybrids' halves: a real encapsulation key (768: from X25519MLKEM768's share, whose
        // first 1184 octets it is; 1024: SecP384r1MLKEM1024's last 1568), and one failing the
        // modulus check (a first coefficient of 4095, as above)
        byte[] ek768 = new TlsShare(TlsEngine.X25519MlKem768).Public[..1184];
        byte[] ek1024 = new TlsShare(TlsEngine.Secp384r1MlKem1024).Public[97..];
        byte[] badEk768 = [0xFF, 0x0F, .. ek768[2..]];
        byte[] badEk1024 = [0xFF, 0x0F, .. ek1024[2..]];
        // one group alone, its share replaced: the shape of most cases below
        static Action<TlsTestClient> Share(ushort group, byte[] share) => c =>
        {
            c.Groups = [group];
            c.ShareGroups = [group];
            c.ShareOverride[group] = share;
        };
        var cases = new (string What, Action<TlsTestClient> Shape, uint Alert)[]
        {
            ("X448's zero secret (u = 0)", Share(TlsEngine.X448, new byte[56]), 47),
            ("X448 short", Share(TlsEngine.X448, new byte[55]), 47),
            ("P-384 off the curve", Share(TlsEngine.Secp384r1, p384Off), 47),
            ("P-384 short", Share(TlsEngine.Secp384r1, p384[..^1]), 47),
            ("P-521 off the curve", Share(TlsEngine.Secp521r1, p521Off), 47),
            ("P-521 short", Share(TlsEngine.Secp521r1, p521[..^1]), 47),
            ("ffdhe2048 short", Share(0x0100, [.. new byte[254], 2]), 47),
            ("X25519MLKEM768 short", Share(TlsEngine.X25519MlKem768, [.. ek768, .. new byte[31]]), 47),
            ("X25519MLKEM768's X25519 half: a zero secret", Share(TlsEngine.X25519MlKem768, [.. ek768, .. new byte[32]]), 47),
            ("SecP256r1MLKEM768 short", Share(TlsEngine.Secp256r1MlKem768, [.. p256, .. ek768[..^1]]), 47),
            ("SecP256r1MLKEM768's P-256 half off the curve", Share(TlsEngine.Secp256r1MlKem768, [.. offCurve, .. ek768]), 47),
            ("SecP256r1MLKEM768's ML-KEM half: the modulus check", Share(TlsEngine.Secp256r1MlKem768, [.. p256, .. badEk768]), 47),
            ("SecP384r1MLKEM1024 short", Share(TlsEngine.Secp384r1MlKem1024, [.. p384, .. ek1024[..^1]]), 47),
            ("SecP384r1MLKEM1024's P-384 half off the curve", Share(TlsEngine.Secp384r1MlKem1024, [.. p384Off, .. ek1024]), 47),
            ("SecP384r1MLKEM1024's ML-KEM half: the modulus check", Share(TlsEngine.Secp384r1MlKem1024, [.. p384, .. badEk1024]), 47),
            ("no supported_versions", c => c.Omit.Add(43), 70),
            ("legacy_version 0x0301", c => c.LegacyVersion = 0x0301, 70),
            ("legacy_version 0x0304", c => c.LegacyVersion = 0x0304, 70),
            ("TLS 1.2 only", c => c.Versions = [0x0303], 70),
            ("no suite in common", c => c.Suites = [0x1304, 0x1305], 40),
            ("no scheme the key makes", c => c.SignatureAlgorithms = [0x0401, 0x0804, 0x0807], 40),
            ("no group in common", c => { c.Groups = [0x0200]; c.ShareGroups = []; }, 40),
            ("no signature_algorithms", c => c.Omit.Add(13), 109),
            ("no supported_groups", c => c.Omit.Add(10), 109),
            ("no key_share", c => c.Omit.Add(51), 109),
            ("a share for a group not listed", c => { c.Groups = [TlsEngine.X25519]; c.ShareGroups = [TlsEngine.X25519, TlsEngine.Secp256r1]; }, 47),
            ("X25519's zero secret", c => c.ShareOverride[TlsEngine.X25519] = new byte[32], 47),
            ("X25519 short", c => c.ShareOverride[TlsEngine.X25519] = new byte[31], 47),
            ("P-256 off the curve", c => { c.Groups = [TlsEngine.Secp256r1]; c.ShareGroups = [TlsEngine.Secp256r1]; c.ShareOverride[TlsEngine.Secp256r1] = offCurve; }, 47),
            ("P-256 compressed", c => { c.Groups = [TlsEngine.Secp256r1]; c.ShareGroups = [TlsEngine.Secp256r1]; c.ShareOverride[TlsEngine.Secp256r1] = [2, .. p256[1..33]]; }, 47),
            ("ffdhe2048's Y = 1", c => { c.Groups = [0x0100]; c.ShareGroups = [0x0100]; c.ShareOverride[0x0100] = [.. new byte[255], 1]; }, 47),
            ("ffdhe2048's Y = p - 1", c => { c.Groups = [0x0100]; c.ShareGroups = [0x0100]; c.ShareOverride[0x0100] = pMinus1; }, 47),
            ("ML-KEM's modulus check", c => { c.Groups = [TlsEngine.X25519MlKem768]; c.ShareGroups = [TlsEngine.X25519MlKem768]; c.ShareOverride[TlsEngine.X25519MlKem768] = badKem; }, 47),
        };
        foreach ((string what, Action<TlsTestClient> shape, uint alert) in cases)
        {
            (TlsServerHarness server, TlsTestClient client, TlsServerHarness.Received r) = Hello(shape);
            using (server)
            using (client)
            {
                Refused(server, client, r, alert, what);
            }
        }
    }

    /// <summary>
    /// The second ClientHello is held to 4.2.2: after a HelloRetryRequest for secp256r1 (the
    /// server's only group; the client shared x25519), a second hello with another session id
    /// (of another length, or of the same length with another octet), without the suite the
    /// retry chose, with two shares, with a share of another group, or offering early data is
    /// refused (illegal_parameter); the second hello as it should be is taken. The retry itself
    /// names the group, the suite and the session id it echoes.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.2.4-6#2", "RFC9846-4.2.2-1#2")]
    public void HoldsTheSecondHelloToTheRetry()
    {
        Platform.RequireLinuxX64();
        var cases = new (string What, Action<TlsTestClient>? Break)[]
        {
            ("as it should be", null),
            ("another session id", c => c.SessionId = [9, 9, 9]),
            ("another session id of the same length", c => c.SessionId = [1, 2, 3, 5]),
            ("the suite dropped", c => c.Suites = [0x1302]),
            ("two shares", c => c.RetryShareGroups = [TlsEngine.Secp256r1, TlsEngine.X25519]),
            ("another group's share", c => c.RetryShareGroups = [TlsEngine.X25519]),
            ("early data offered", c => c.Extra.Add((42, []))),
        };
        foreach ((string what, Action<TlsTestClient>? breakIt) in cases)
        {
            using var server = new TlsServerHarness(P256.Key, [P256.Certificate], groups: [TlsEngine.Secp256r1]);
            using var client = new TlsTestClient { Groups = [TlsEngine.X25519, TlsEngine.Secp256r1], ShareGroups = [TlsEngine.X25519], SessionId = [1, 2, 3, 4] };
            TlsServerHarness.Received r = server.Receive(client.Hello());
            Assert.Equal(TlsEngine.EventNone, r.Event.Kind);
            client.Take(server.TakeOutput());
            Assert.True(client.Retried, what);
            Assert.Equal(TlsEngine.Secp256r1, client.Group);
            Assert.Equal(1, client.ChangeCipherSpecs);                     // compatibility mode: after the retry
            breakIt?.Invoke(client);
            r = server.Receive(client.Hello());
            if (breakIt is null)
            {
                Assert.True(r.Answer > 0, $"{what}: alert {r.Event.Alert}");
                client.Take(server.TakeOutput());
                Assert.True(client.ServerFinished);
                Assert.Equal(1, client.ChangeCipherSpecs);                 // and only once
            }
            else
            {
                Refused(server, client, r, 47, what);
            }
        }
    }

    /// <summary>A server and a client past the server's flight (the server waits for the
    /// client's Finished; the client holds the handshake keys).</summary>
    /// <param name="shape">Shapes the client before its hello, or null.</param>
    /// <returns>Both sides.</returns>
    private static (TlsServerHarness Server, TlsTestClient Client) Flight(Action<TlsTestClient>? shape = null)
    {
        var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
        var client = new TlsTestClient();
        shape?.Invoke(client);
        TlsServerHarness.Received r = server.Receive(client.Hello());
        Assert.True(r.Answer > 0, $"the hello: alert {r.Event.Alert}");
        client.Take(server.TakeOutput());
        Assert.True(client.ServerFinished);
        return (server, client);
    }

    /// <summary>A server and a client connected.</summary>
    /// <returns>Both sides.</returns>
    private static (TlsServerHarness Server, TlsTestClient Client) Connected()
    {
        var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
        var client = new TlsTestClient();
        Complete(server, client);
        return (server, client);
    }

    /// <summary>A ClientHello's bare shape (no extensions: refused or out of place wherever it comes).</summary>
    /// <returns>The message.</returns>
    private static byte[] BareHello() => TlsTestClient.Message(1, [3, 3, .. new byte[32], 0, 0, 2, 0x13, 1, 1, 0]);

    /// <summary>
    /// Messages the state machine may not take where they come (RFC 9846 Appendix A.2): waiting
    /// for the client's Finished, a Finished that does not verify (decrypt_error, 4.5.3) or is
    /// not Hash.length octets (decode_error), a second ClientHello, application data, a
    /// KeyUpdate before the Finished (4.7.3), a Certificate or CertificateVerify not asked for,
    /// a plaintext handshake record once keys are in use, a protected change_cipher_spec, a
    /// record that does not open (bad_record_mac); once connected, a ClientHello (no
    /// renegotiation: 4.2.2), a Finished, a KeyUpdate of another value (illegal_parameter) or
    /// length (decode_error), a KeyUpdate with more in its record (5.1: unexpected_message), a
    /// plaintext alert or change_cipher_spec. Each is our alert, sealed under our current key.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.5.3-2#1", "RFC9846-4.7.3-1#1", "RFC9846-4.2.2-3", "RFC9846-4.7.3-3.2.1", "RFC9846-5.1-3.2.1#2")]
    public void RefusesWhatTheStateMachineMayNotTake()
    {
        Platform.RequireLinuxX64();
        var waiting = new (string What, Func<TlsTestClient, byte[]> Make, uint Alert)[]
        {
            ("a Finished that does not verify", c => c.Seal(22, TlsTestClient.Message(20, new byte[32])), 51),
            ("a Finished of 31 octets", c => c.Seal(22, TlsTestClient.Message(20, new byte[31])), 50),
            ("a second ClientHello", c => c.Seal(22, BareHello()), 10),
            ("application data", c => c.Seal(23, [1, 2, 3]), 10),
            ("a KeyUpdate before the Finished", c => c.Seal(22, TlsTestClient.Message(24, [0])), 10),
            ("a Certificate not asked for", c => c.Seal(22, TlsTestClient.Message(11, [0, 0, 0, 0])), 10),
            ("a CertificateVerify not asked for", c => c.Seal(22, TlsTestClient.Message(15, [8, 4, 0, 0])), 10),
            ("a plaintext ClientHello", _ => TlsTestClient.Plain(22, BareHello()), 10),
            ("a protected change_cipher_spec", c => c.Seal(20, [1]), 10),
            ("a record that does not open", c => { byte[] r = c.Seal(23, [1, 2, 3]); r[7] ^= 1; return r; }, 20),
        };
        foreach ((string what, Func<TlsTestClient, byte[]> make, uint alert) in waiting)
        {
            (TlsServerHarness server, TlsTestClient client) = Flight();
            using (server)
            using (client)
            {
                Refused(server, client, server.Receive(make(client)), alert, $"waiting for the Finished: {what}");
            }
        }

        var connected = new (string What, Func<TlsTestClient, byte[]> Make, uint Alert)[]
        {
            ("a ClientHello", c => c.Seal(22, BareHello()), 10),
            ("a Finished", c => c.Seal(22, TlsTestClient.Message(20, new byte[32])), 10),
            ("a KeyUpdate of 2", c => c.Seal(22, TlsTestClient.Message(24, [2])), 47),
            ("a KeyUpdate of two octets", c => c.Seal(22, TlsTestClient.Message(24, [0, 0])), 50),
            ("a KeyUpdate with more after it", c => c.Seal(22, [.. TlsTestClient.Message(24, [0]), .. TlsTestClient.Message(24, [0])]), 10),
            ("a plaintext alert", _ => TlsTestClient.Plain(21, [2, 40]), 10),
            ("a change_cipher_spec", _ => TlsTestClient.Plain(20, [1]), 10),
        };
        foreach ((string what, Func<TlsTestClient, byte[]> make, uint alert) in connected)
        {
            (TlsServerHarness server, TlsTestClient client) = Connected();
            using (server)
            using (client)
            {
                Refused(server, client, server.Receive(make(client)), alert, $"connected: {what}");
            }
        }
    }

    /// <summary>
    /// The record layer's rules before any key (RFC 9846 5): change_cipher_spec before the first
    /// ClientHello, application data in the clear, a type no document defines, an empty
    /// handshake record (unexpected_message, 5.1); a plaintext record over 2^14 octets
    /// (record_overflow); an alert record of other than two octets (decode_error: one alert to a
    /// record); two ClientHellos in one record (the first changes the read key: 5.1); and, once
    /// the first hello is in, change_cipher_spec of another value or length, or more than 32
    /// dropped in a row (unexpected_message; Appendix E.4 and the engine's flood bound). The
    /// alerts before keys go out in the clear.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.1-4", "RFC9846-5.1-5#3", "RFC9846-5.1-8.6.1#2", "RFC9846-5.1-10", "RFC9846-E.4-3")]
    public void RefusesTheRecordsItMust()
    {
        Platform.RequireLinuxX64();
        var start = new (string What, Func<TlsTestClient, byte[]> Make, uint Alert)[]
        {
            ("change_cipher_spec first", _ => TlsTestClient.Plain(20, [1]), 10),
            ("application data in the clear", _ => TlsTestClient.Plain(23, [1, 2, 3]), 10),
            ("a record of type 24", _ => TlsTestClient.Plain(24, [1]), 10),
            ("an empty handshake record", _ => TlsTestClient.Plain(22, []), 10),
            ("2^14 + 1 octets in the clear", _ => TlsTestClient.Plain(22, new byte[16385]), 22),
            ("an alert of three octets", _ => TlsTestClient.Plain(21, [2, 40, 0]), 50),
            ("two hellos in one record", c => { byte[] h = c.Hello(); return TlsTestClient.Plain(22, [.. h[5..], .. h[5..]]); }, 10),
        };
        foreach ((string what, Func<TlsTestClient, byte[]> make, uint alert) in start)
        {
            using var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
            using var client = new TlsTestClient();
            TlsServerHarness.Received r = server.ReceiveAll(make(client)).Last();
            Assert.True(r.Answer == -1 && r.Event.Alert == alert, $"{what}: answer {r.Answer}, alert {r.Event.Alert} (expected {alert})");
            byte[] sent = server.TakeOutput();
            if (what != "two hellos in one record")
            {
                Assert.Equal(TlsTestClient.Plain(21, [2, (byte)alert]), sent);
            }
        }

        foreach ((string what, byte[] ccs) in new[] { ("a 2", new byte[] { 2 }), ("two octets", new byte[] { 1, 1 }) })
        {
            (TlsServerHarness server, TlsTestClient client) = Flight();
            using (server)
            using (client)
            {
                Refused(server, client, server.Receive(TlsTestClient.Plain(20, ccs)), 10, $"change_cipher_spec {what}");
            }
        }

        (TlsServerHarness flood, TlsTestClient floodClient) = Flight();
        using (flood)
        using (floodClient)
        {
            for (int i = 0; i < 32; i++)
            {
                Assert.Equal(6, flood.Receive(TlsTestClient.Plain(20, [1])).Answer);
            }

            Refused(flood, floodClient, flood.Receive(TlsTestClient.Plain(20, [1])), 10, "the 33rd change_cipher_spec");
        }
    }

    /// <summary>
    /// The peer's alerts (RFC 9846 6): an error alert, in the clear before keys or after them
    /// (a peer that failed in the clear, A.1), fails the connection with the peer's alert and
    /// nothing sent; close_notify before the handshake completes is a failure too (alert 0,
    /// the peer's); after it, close_notify closes the peer's side (EVENT_CLOSED), what follows
    /// is ignored (6.1), and we may still send until our own close_notify; user_canceled is a
    /// warning (taken, nothing reported). After a failure every call answers it again.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-6.1-2.2.1#1", "RFC9846-6.1-2.4.1#2", "RFC9846-6.1-3")]
    public void TakesThePeersAlerts()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        {
            TlsServerHarness.Received r = server.Receive(TlsTestClient.Plain(21, [2, 40]));
            Assert.True(r.Answer == -1 && r.Event.Kind == TlsEngine.EventFailed && r.Event.Alert == 40 && r.Event.Flags == TlsEngine.EventPeer);
            Assert.Empty(server.TakeOutput());
            r = server.Receive(TlsTestClient.Plain(22, [1]));
            Assert.True(r.Answer == -1 && r.Event.Alert == 40 && r.Event.Flags == TlsEngine.EventPeer);
        }

        (TlsServerHarness s1, TlsTestClient c1) = Flight();
        using (s1)
        using (c1)
        {
            TlsServerHarness.Received r = s1.Receive(c1.Seal(21, [1, 0]));          // close_notify mid-handshake
            Assert.True(r.Answer == -1 && r.Event.Alert == 0 && r.Event.Flags == TlsEngine.EventPeer);
            Assert.Empty(s1.TakeOutput());
        }

        (TlsServerHarness s2, TlsTestClient c2) = Flight();
        using (s2)
        using (c2)
        {
            TlsServerHarness.Received r = s2.Receive(TlsTestClient.Plain(21, [2, 42]));
            Assert.True(r.Answer == -1 && r.Event.Alert == 42 && r.Event.Flags == TlsEngine.EventPeer);
        }

        (TlsServerHarness s3, TlsTestClient c3) = Connected();
        using (s3)
        using (c3)
        {
            Assert.Equal(TlsEngine.EventNone, s3.Receive(c3.Seal(21, [1, 90])).Event.Kind);    // user_canceled
            Assert.Equal(TlsEngine.EventClosed, s3.Receive(c3.Seal(21, [1, 0])).Event.Kind);
            byte[] after = c3.SealData([1, 2, 3]);
            TlsServerHarness.Received r = s3.Receive(after);
            Assert.True(r.Answer == after.Length && r.Event.Kind == TlsEngine.EventNone, "after close_notify: ignored");
            Assert.Equal(3, s3.Send([7, 8, 9]));                                    // our side is still open
            Assert.Equal(0, s3.Close());
            Assert.Equal(-1, s3.Close());
            Assert.Equal(-1, s3.Send([1]));
            c3.Take(s3.TakeOutput());
            Assert.Equal([7, 8, 9], c3.Data.Single());
            Assert.Equal(((byte)1, (byte)0), c3.Alerts.Single());                  // close_notify, warning
        }
    }

    /// <summary>
    /// Handshake messages across records (RFC 9846 5.1): a ClientHello cut into records of one
    /// octet each is gathered and taken; one cut with a change_cipher_spec between its parts is
    /// refused (no interleaving: unexpected_message); a record arriving an octet at a time waits
    /// (0) until whole; a ClientHello over max_message is refused (illegal_parameter), whole in
    /// one record or announced by its first fragment's header.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.1-2", "RFC9846-5.1-3.1.1#2")]
    public void GathersMessagesAcrossRecords()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient())
        {
            byte[] hello = client.Hello()[5..];
            byte[] records = [.. hello.SelectMany(b => TlsTestClient.Plain(22, [b]))];
            List<TlsServerHarness.Received> answers = server.ReceiveAll(records);
            Assert.Equal(hello.Length, answers.Count);
            Assert.All(answers, a => Assert.Equal(6, a.Answer));
            client.Take(server.TakeOutput());
            Assert.True(client.ServerFinished);
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient())
        {
            byte[] hello = client.Hello()[5..];
            Assert.Equal(15, server.Receive(TlsTestClient.Plain(22, hello[..10])).Answer);
            Refused(server, client, server.Receive(TlsTestClient.Plain(20, [1])), 10, "change_cipher_spec inside a message");
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient())
        {
            byte[] record = client.Hello();
            for (int i = 1; i < record.Length; i++)
            {
                Assert.Equal(0, server.Receive(record.AsSpan(0, i)).Answer);
            }

            Assert.Equal(record.Length, server.Receive(record).Answer);
        }

        foreach (bool whole in new[] { true, false })
        {
            using var server = new TlsServerHarness(P256.Key, [P256.Certificate], maxMessage: 512);
            using var client = new TlsTestClient();
            client.Extra.Add((21, new byte[600]));                                 // padding
            byte[] hello = client.Hello()[5..];
            TlsServerHarness.Received r = server.Receive(TlsTestClient.Plain(22, whole ? hello : hello[..8]));
            Refused(server, client, r, 47, whole ? "a hello over max_message" : "its first fragment");
        }
    }

    /// <summary>
    /// Early data offered and not taken (RFC 9846 4.3.10): records the handshake key cannot open
    /// are dropped until one opens (then garbage is bad_record_mac again); with a
    /// HelloRetryRequest, protected records before the second hello are dropped by their outer
    /// type; past 16 KiB of them the connection fails (unexpected_message). The handshake around
    /// them completes.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.3.10-8", "RFC9846-4.3.10-14")]
    public void SkipsTheEarlyDataItDoesNotTake()
    {
        Platform.RequireLinuxX64();
        static byte[] Garbage(int n) => [23, 3, 3, (byte)(n >> 8), (byte)n, .. RandomNumberGenerator.GetBytes(n)];
        (TlsServerHarness server, TlsTestClient client) = Flight(c => c.Extra.Add((42, [])));
        using (server)
        using (client)
        {
            for (int i = 0; i < 3; i++)
            {
                TlsServerHarness.Received r = server.Receive(Garbage(500));
                Assert.True(r.Answer == 505 && r.Event.Kind == TlsEngine.EventNone, $"early record {i}: {r.Answer}, alert {r.Event.Alert}");
            }

            foreach (TlsServerHarness.Received f in server.ReceiveAll(client.Finished()))
            {
                Assert.True(f.Answer > 0, $"the Finished after early data: alert {f.Event.Alert}");
            }

            Assert.Equal(2, server.Negotiated().Progress);
            TlsServerHarness.Received bad = server.Receive(Garbage(500));
            Assert.True(bad.Answer == -1 && bad.Event.Alert == 20, $"after: {bad.Event.Alert}");
        }

        (server, client) = Flight(c => c.Extra.Add((42, [])));
        using (server)
        using (client)
        {
            TlsServerHarness.Received r = default;
            for (int sent = 0; sent <= 16384; sent += 4005)
            {
                r = server.Receive(Garbage(4000));
            }

            Assert.True(r.Answer == -1 && r.Event.Alert == 10, $"past the bound: {r.Answer}, alert {r.Event.Alert}");
        }

        using (var retrying = new TlsServerHarness(P256.Key, [P256.Certificate], groups: [TlsEngine.Secp256r1]))
        using (var c = new TlsTestClient { Groups = [TlsEngine.X25519, TlsEngine.Secp256r1] })
        {
            c.Extra.Add((42, []));
            Assert.True(retrying.Receive(c.Hello()).Answer > 0);
            c.Take(retrying.TakeOutput());
            Assert.True(c.Retried);
            TlsServerHarness.Received r = retrying.Receive(Garbage(300));
            Assert.True(r.Answer == 305 && r.Event.Kind == TlsEngine.EventNone, $"before the second hello: {r.Event.Alert}");
            c.Extra.Clear();                                                        // no early_data after a retry
            Assert.True(retrying.Receive(c.Hello()).Answer > 0);
            c.Take(retrying.TakeOutput());
            Assert.True(c.ServerFinished);
        }
    }

    /// <summary>
    /// The calls' own refusals: send and KeyUpdate before the handshake allows them; a random
    /// source that fails (internal_error, in the clear, at the first draw); KeyUpdate asking the
    /// peer to update too; close twice; memory under the configuration's (server_init refuses).
    /// </summary>
    [Fact]
    public unsafe void RefusesTheCallsItMust()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        {
            Assert.Equal((0, 0u, 0u, 0u), server.Negotiated());
            Assert.Equal(-1, server.Send([1]));
            Assert.Equal(-1, server.KeyUpdate(false));
        }

        var broken = new RandomScript { Broken = true };
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], broken))
        using (var client = new TlsTestClient())
        {
            TlsServerHarness.Received r = server.Receive(client.Hello());
            Assert.True(r.Answer == -1 && r.Event.Alert == 80, $"no randomness: {r.Event.Alert}");
            Assert.Equal(TlsTestClient.Plain(21, [2, 80]), server.TakeOutput());
            Assert.Equal([32], broken.Lengths);
        }

        (TlsServerHarness s, TlsTestClient c) = Connected();
        using (s)
        using (c)
        {
            Assert.Equal(0, s.KeyUpdate(true));
            c.Take(s.TakeOutput());
            Assert.Equal([1], c.KeyUpdates);
            Assert.Equal(0, s.Close());
            Assert.Equal(-1, s.Close());
            Assert.Equal(-1, s.KeyUpdate(false));
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        {
            TlsServerConfig config = server.Config;
            TlsConnection connection;
            byte[] memory = new byte[(int)config.Memory];
            fixed (byte* m = memory)
            {
                Assert.Equal(-1, Native.Tls13ServerInit(&connection, &config, m, config.Memory - 1));
            }
        }
    }
}
