using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// The engine's server at its edges, against the tests' own client (<see cref="TlsTestClient"/>):
/// the random source failing at each draw in turn and scalars drawn out of range; the output span
/// full, partly taken, and at AES-GCM's record limit; a configuration edited after init (its
/// bounds checked again by server_init, an output_min that lies met by the engine's room checks
/// at every point of a handshake, nothing written past the spans); records and messages cut where
/// the rules tests do not cut them; the hello shapes the engine takes without a fuss; and the
/// calls' answers on a failed connection and an unstarted one.
/// </summary>
public sealed unsafe class TlsServerEdgeTests
{
    /// <summary>A P-256 credential shared by the tests (key generation is the slow part).</summary>
    private static readonly TlsInteropTests.Credential P256 = TlsInteropTests.Make("p256");

    /// <summary>The credentials made so far, by kind (each kind made once for the class).</summary>
    private static readonly Dictionary<string, TlsInteropTests.Credential> Credentials = [];

    /// <summary>floor(2^24.5): AES-GCM's records under one key (HTTPASM_TLS_GCM_RECORDS, RFC 9846 5.5).</summary>
    private const ulong GcmRecords = 23726566;

    /// <summary>A credential of a kind, made on first use: "p256", "p384", "p521" and
    /// "rsa2048" by .NET, "ed25519" and "ed448" by openssl (.NET makes no EdDSA keys).</summary>
    /// <param name="kind">The kind.</param>
    /// <returns>The credential.</returns>
    private static TlsInteropTests.Credential Credential(string kind)
    {
        lock (Credentials)
        {
            if (!Credentials.TryGetValue(kind, out TlsInteropTests.Credential? c))
            {
                c = kind is "ed25519" or "ed448" ? TlsOpenSslCliTests.Make(kind) : TlsInteropTests.Make(kind);
                Credentials[kind] = c;
            }

            return c;
        }
    }

    /// <summary>A server and a client connected (P-256 key, the client's defaults: x25519,
    /// AES-128-GCM).</summary>
    /// <returns>Both sides.</returns>
    private static (TlsServerHarness Server, TlsTestClient Client) Connected()
    {
        var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
        var client = new TlsTestClient();
        TlsServerRulesTests.Complete(server, client);
        return (server, client);
    }

    /// <summary>A server and a client past the server's flight: the server waits for the
    /// client's Finished.</summary>
    /// <returns>Both sides.</returns>
    private static (TlsServerHarness Server, TlsTestClient Client) Flight()
    {
        var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
        var client = new TlsTestClient();
        Assert.True(server.Receive(client.Hello()).Answer > 0);
        client.Take(server.TakeOutput());
        Assert.True(client.ServerFinished);
        return (server, client);
    }

    /// <summary>The records of an output: each one's type and its length field.</summary>
    /// <param name="output">Whole records.</param>
    /// <returns>(type, length) of each, in order.</returns>
    private static List<(byte Type, int Length)> Records(ReadOnlySpan<byte> output)
    {
        var records = new List<(byte, int)>();
        while (output.Length >= 5)
        {
            int n = (output[3] << 8) | output[4];
            records.Add((output[0], n));
            output = output[(5 + n)..];
        }

        Assert.True(output.IsEmpty, "a record cut short");
        return records;
    }

    /// <summary>A protected-looking record of random octets (outer type application_data): what
    /// a client sends as early data, which no key of the server's opens.</summary>
    /// <param name="n">Its fragment's octets.</param>
    /// <returns>The record.</returns>
    private static byte[] Garbage(int n) => [23, 3, 3, (byte)(n >> 8), (byte)n, .. RandomNumberGenerator.GetBytes(n)];

    /// <summary>The key exchange's draws in a group, in the engine's order (the share's private
    /// parts: tls/kex.asm's header).</summary>
    /// <param name="group">The group.</param>
    /// <returns>Each draw's octets.</returns>
    private static int[] KexDraws(ushort group) => group switch
    {
        TlsEngine.X25519 => [32],
        TlsEngine.X448 => [56],
        TlsEngine.Secp256r1 => [32],
        TlsEngine.Secp384r1 => [48],
        TlsEngine.Secp521r1 => [66],
        0x0100 => [29],
        0x0101 => [35],
        0x0102 => [41],
        0x0103 => [47],
        0x0104 => [50],
        TlsEngine.X25519MlKem768 => [32, 32],       // ML-KEM's m, then the X25519 scalar
        TlsEngine.Secp256r1MlKem768 => [32, 32],    // the P-256 scalar, then m
        _ => [48, 32],                              // SecP384r1MLKEM1024: the P-384 scalar, then m
    };

    /// <summary>The CertificateVerify's draws for a key kind under the client's default
    /// signature_algorithms: ECDSA's hedge (the scalar's octets), RSA-PSS's salt (SHA-256's 32:
    /// rsa_pss_rsae_sha256 is the client's first RSA scheme), none for EdDSA (deterministic).</summary>
    /// <param name="kind">The key kind.</param>
    /// <returns>Each draw's octets.</returns>
    private static int[] SignDraws(string kind) => kind switch
    {
        "p256" => [32],
        "p384" => [48],
        "p521" => [66],
        "rsa2048" => [32],
        _ => [],
    };

    /// <summary>Every group with the P-256 key, and every other key kind with x25519.</summary>
    /// <returns>(key kind, group) pairs.</returns>
    public static TheoryData<string, ushort> DrawCases() => new()
    {
        { "p256", TlsEngine.X25519 }, { "p256", TlsEngine.X448 }, { "p256", TlsEngine.Secp256r1 }, { "p256", TlsEngine.Secp384r1 },
        { "p256", TlsEngine.Secp521r1 }, { "p256", 0x0100 }, { "p256", 0x0101 }, { "p256", 0x0102 }, { "p256", 0x0103 }, { "p256", 0x0104 },
        { "p256", TlsEngine.X25519MlKem768 }, { "p256", TlsEngine.Secp256r1MlKem768 }, { "p256", TlsEngine.Secp384r1MlKem1024 },
        { "p384", TlsEngine.X25519 }, { "p521", TlsEngine.X25519 }, { "rsa2048", TlsEngine.X25519 }, { "ed25519", TlsEngine.X25519 },
        { "ed448", TlsEngine.X25519 },
    };

    /// <summary>
    /// The random source failing at each draw of a handshake in turn - the server random, each
    /// private part of the share (both halves of a hybrid's), the CertificateVerify's hedge or
    /// salt - fails it with internal_error (RFC 9846 6.2) at that draw, no later draw made: in the
    /// clear while no key is in use (every draw up to the share's), under the server's handshake
    /// key after the ServerHello went out (the signature's draw), which the client then reads.
    /// Past the last draw nothing more is drawn and the handshake completes: EdDSA's signers draw
    /// nothing (RFC 8032: deterministic).
    /// </summary>
    /// <param name="kind">The key kind.</param>
    /// <param name="group">The group the client shares alone.</param>
    [Theory]
    [MemberData(nameof(DrawCases))]
    public void FailsAtEachDraw(string kind, ushort group)
    {
        Platform.RequireLinuxX64();
        TlsInteropTests.Credential credential = Credential(kind);
        int[] draws = [32, .. KexDraws(group), .. SignDraws(kind)];
        int clear = 1 + KexDraws(group).Length;                     // the draws before any key
        for (int k = 1; k <= draws.Length; k++)
        {
            var script = new RandomScript { FailAt = k };
            using var server = new TlsServerHarness(credential.Key, [credential.Certificate], script);
            using var client = new TlsTestClient { Groups = [group], ShareGroups = [group] };
            TlsServerHarness.Received r = server.Receive(client.Hello());
            string what = $"{kind}, {group:X4}: draw {k} of {draws.Length} refused";
            Assert.True(r.Answer == -1 && r.Event.Alert == 80 && r.Event.Flags == 0, $"{what}: answer {r.Answer}, alert {r.Event.Alert}");
            Assert.Equal(draws[..k], script.Lengths);
            byte[] output = server.TakeOutput();
            if (k <= clear)
            {
                Assert.Equal(TlsTestClient.Plain(21, [2, 80]), output);
            }
            else
            {
                client.Take(output);
                Assert.Equal(group, client.Group);
                Assert.False(client.ServerFinished, what);
                Assert.Equal([((byte)2, (byte)80)], client.Alerts);
            }
        }

        var past = new RandomScript { FailAt = draws.Length + 1 };
        using var whole = new TlsServerHarness(credential.Key, [credential.Certificate], past);
        using var c2 = new TlsTestClient { Groups = [group], ShareGroups = [group] };
        TlsServerRulesTests.Complete(whole, c2);
        Assert.Equal(draws, past.Lengths);
    }

    /// <summary>
    /// An ECDH scalar drawn out of range (all ones: n or more, P-521's after its 521-bit mask) is
    /// drawn again, and the handshake completes with the next one: in each NIST curve's own group
    /// and in both hybrids that carry one. Eight out of range in a row (2^-256 at P-256 from a
    /// real source) and the engine stops drawing: internal_error in the clear, no ninth draw.
    /// </summary>
    /// <param name="group">The group.</param>
    /// <param name="size">The scalar's octets.</param>
    [Theory]
    [InlineData(TlsEngine.Secp256r1, 32)]
    [InlineData(TlsEngine.Secp384r1, 48)]
    [InlineData(TlsEngine.Secp521r1, 66)]
    [InlineData(TlsEngine.Secp256r1MlKem768, 32)]
    [InlineData(TlsEngine.Secp384r1MlKem1024, 48)]
    public void DrawsScalarsAgainWhileOutOfRange(ushort group, int size)
    {
        Platform.RequireLinuxX64();
        byte[] high = Enumerable.Repeat((byte)0xFF, size).ToArray();
        var once = new RandomScript().Then(RandomNumberGenerator.GetBytes(32), high);
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], once))
        using (var client = new TlsTestClient { Groups = [group], ShareGroups = [group] })
        {
            TlsServerRulesTests.Complete(server, client);
            Assert.Equal(new[] { 32, size, size }, once.Lengths.Take(3));
        }

        var always = new RandomScript { Fallback = false }.Then([RandomNumberGenerator.GetBytes(32), .. Enumerable.Repeat(high, 8)]);
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], always))
        using (var client = new TlsTestClient { Groups = [group], ShareGroups = [group] })
        {
            TlsServerHarness.Received r = server.Receive(client.Hello());
            Assert.True(r.Answer == -1 && r.Event.Alert == 80, $"eight scalars out of range: answer {r.Answer}, alert {r.Event.Alert}");
            Assert.Equal([32, .. Enumerable.Repeat(size, 8)], always.Lengths);
            Assert.Equal(0, always.Left);
            Assert.Equal(TlsTestClient.Plain(21, [2, 80]), server.TakeOutput());
        }
    }

    /// <summary>The library's own random source (httpasm_tls_random, the C header's choice for
    /// the configuration's random field, its context unused) runs a whole handshake.</summary>
    [Fact]
    public void DrawsFromTheLibrarysOwnSource()
    {
        Platform.RequireLinuxX64();
        using var server = new TlsServerHarness(P256.Key, [P256.Certificate], libraryRandom: true);
        using var client = new TlsTestClient();
        TlsServerRulesTests.Complete(server, client);
        Assert.Empty(server.Random.Lengths);
        Assert.Equal(2, server.Progress());
    }

    /// <summary>
    /// The output span full (a caller that sends and takes nothing): send takes nothing more (0,
    /// not -1: the caller takes and calls again), and a KeyUpdate or close_notify that cannot fit
    /// is refused (-1) with nothing changed. A KeyUpdate the peer asks for is owed then and goes
    /// before our next application data (RFC 9846 4.7.3), so send takes nothing while it cannot
    /// fit either; once the caller takes the output, the KeyUpdate goes first and the data after
    /// it under the new key, and close_notify fits again.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.7.3-4#1")]
    public void RefusesWhatTheFullOutputCannotHold()
    {
        Platform.RequireLinuxX64();
        (TlsServerHarness server, TlsTestClient client) = Connected();
        using (server)
        using (client)
        {
            byte[] data = RandomNumberGenerator.GetBytes(1 << 16);
            long total = 0;
            long taken;
            while ((taken = server.Send(data)) > 0)
            {
                total += taken;
            }

            Assert.True(total > 0);
            Assert.Equal(-1, server.KeyUpdate(false));
            Assert.Equal(-1, server.Close());
            TlsServerHarness.Received r = server.Receive(client.KeyUpdate(true));
            Assert.True(r.Answer > 0 && r.Event.Kind == TlsEngine.EventNone, $"the peer's KeyUpdate: {r.Answer}, alert {r.Event.Alert}");
            Assert.Equal(0, server.Send([1, 2, 3]));

            client.Take(server.TakeOutput());
            Assert.Equal(total, client.Data.Sum(d => (long)d.Length));
            Assert.Empty(client.KeyUpdates);
            Assert.Equal(3, server.Send([1, 2, 3]));
            client.Take(server.TakeOutput());
            Assert.Equal([0], client.KeyUpdates);                           // update_not_requested, before the data
            Assert.Equal([1, 2, 3], client.Data[^1]);
            Assert.Equal(0, server.Close());
        }
    }

    /// <summary>
    /// A caller that took only part of the output (its socket took that much): the rest stays
    /// queued, and what is sent next goes after it, the queued octets moved to the span's front
    /// first - so a record that would not fit behind them does (send takes it whole). The client
    /// reads both records whole, in order.
    /// </summary>
    [Fact]
    public void KeepsWhatTheCallerHasNotTaken()
    {
        Platform.RequireLinuxX64();
        (TlsServerHarness server, TlsTestClient client) = Connected();
        using (server)
        using (client)
        {
            TlsServerConfig config = server.Config;
            int capacity = (int)(config.Memory - config.MaxMessage);   // the output span (server_init's split)
            byte[] first = RandomNumberGenerator.GetBytes(capacity / 2 - 22);
            Assert.Equal(first.Length, server.Send(first));
            byte[] part = server.TakeOutput(capacity / 4);
            int left = server.Queued;
            Assert.Equal(capacity / 2 - capacity / 4, left);
            // the most a record may hold once the queued octets moved to the front (the reserve
            // of 64 kept): behind them where they were, it would not fit
            byte[] second = RandomNumberGenerator.GetBytes(capacity - left - 64 - 22);
            Assert.Equal(second.Length, server.Send(second));
            byte[] rest = server.TakeOutput();
            Assert.Equal(left + second.Length + 22, rest.Length);
            client.Take([.. part, .. rest]);
            Assert.Equal([first, second], client.Data);
        }
    }

    /// <summary>
    /// AES-GCM's limit (RFC 9846 5.5: 2^24.5 records under one key): two records short of it, our
    /// next record goes after a KeyUpdate of ours, under the new key, so the old key is never
    /// used up. The connection's sequence number is set near the limit instead of sealing 23
    /// million records, after checking it holds the records sent so far (the field is where the
    /// harness reads it). With the output full at that point, send takes nothing until the
    /// KeyUpdate fits. At the limit itself the key seals nothing more: close_notify and a
    /// KeyUpdate are refused (-1), and send takes nothing.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.5-1#1")]
    public void UpdatesItsKeyBeforeAesGcmRunsOut()
    {
        Platform.RequireLinuxX64();
        (TlsServerHarness server, TlsTestClient client) = Connected();
        using (server)
        using (client)
        {
            Assert.Equal(0x1301, client.Suite);
            for (int i = 0; i < 3; i++)
            {
                Assert.Equal(100, server.Send(new byte[100]));
            }

            client.Take(server.TakeOutput());
            Assert.Equal(3ul, server.WriteSequence);

            server.WriteSequence = GcmRecords - 3;
            client.SetReadSequence(GcmRecords - 3);
            byte[] a = RandomNumberGenerator.GetBytes(100), b = RandomNumberGenerator.GetBytes(100);
            Assert.Equal(100, server.Send(a));                              // record L - 3: the old key still
            Assert.Equal(GcmRecords - 2, server.WriteSequence);
            Assert.Equal(100, server.Send(b));                              // L - 2: a KeyUpdate first
            client.Take(server.TakeOutput());
            Assert.Equal([0], client.KeyUpdates);
            Assert.Equal([a, b], client.Data[^2..]);
            Assert.Equal(1ul, server.WriteSequence);                        // b, the new key's first

            // the output full when the limit comes: nothing taken until the KeyUpdate fits
            byte[] fill = new byte[1 << 16];
            while (server.Send(fill) > 0)
            {
            }

            server.WriteSequence = GcmRecords - 2;
            Assert.Equal(0, server.Send([1]));
            server.WriteSequence = GcmRecords;                              // the key used up
            Assert.Equal(-1, server.Close());
            Assert.Equal(-1, server.KeyUpdate(false));
            _ = server.TakeOutput();                                        // (records the client cannot follow now)
            Assert.Equal(-1, server.Close());                               // room now, the key still refuses
            Assert.Equal(0, server.Send([1]));
        }
    }

    /// <summary>
    /// A failed connection answers every call as failed: send, close and KeyUpdate -1, the
    /// progress -1 (asked with every out pointer NULL, which the C header allows). Before the
    /// failure the progress was 0.
    /// </summary>
    [Fact]
    public void AnswersEveryCallAfterAFailure()
    {
        Platform.RequireLinuxX64();
        using var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
        Assert.Equal(0, server.Progress());
        Assert.Equal(-1, server.Receive(TlsTestClient.Plain(21, [2, 40])).Answer);     // the peer's handshake_failure
        Assert.Equal(-1, server.Send([1]));
        Assert.Equal(-1, server.Close());
        Assert.Equal(-1, server.KeyUpdate(false));
        Assert.Equal(-1, server.Progress());
    }

    /// <summary>A connection never started (zeroed: no spans) is wiped without a fault and stays
    /// zeroed: wipe skips the spans it does not have.</summary>
    [Fact]
    public void WipesAConnectionNeverStarted()
    {
        Platform.RequireLinuxX64();
        TlsConnection c = default;
        Native.Tls13Wipe(&c);
        Assert.True(new ReadOnlySpan<byte>(&c, sizeof(TlsConnection)).IndexOfAnyExcept((byte)0) < 0);
    }

    /// <summary>
    /// A configuration edited after init is checked again where it bounds memory: server_init
    /// refuses (-1) a max_message raised past what memory holds beside output_min, an output_min
    /// that carries the sum past 2^64, and lists of 0 or more than 16 groups or 0 or more than 4
    /// suites (the server's frame copies them). An edit inside the bounds starts.
    /// </summary>
    [Fact]
    public void RefusesAConfigurationEditedPastItsBounds()
    {
        Platform.RequireLinuxX64();
        var cases = new (string What, ConfigSetter Edit)[]
        {
            ("max_message raised past the memory", c => c->MaxMessage += 16),
            ("output_min carried past 2^64", c => c->OutputMin = nuint.MaxValue),
            ("no groups", c => c->GroupCount = 0),
            ("17 groups", c => c->GroupCount = 17),
            ("no suites", c => c->SuiteCount = 0),
            ("5 suites", c => c->SuiteCount = 5),
        };
        foreach ((string what, ConfigSetter edit) in cases)
        {
            var e = Assert.Throws<InvalidOperationException>(() => new TlsServerHarness(P256.Key, [P256.Certificate], beforeStart: edit));
            Assert.True(e.Message.Contains("does not start", StringComparison.Ordinal), $"{what}: {e.Message}");
        }

        using var inside = new TlsServerHarness(P256.Key, [P256.Certificate], beforeStart: c => c->GroupCount = 1);
        using var client = new TlsTestClient { Groups = [TlsEngine.X25519MlKem768], ShareGroups = [TlsEngine.X25519MlKem768] };
        TlsServerRulesTests.Complete(inside, client);
    }

    /// <summary>The configuration's output_min (and max_message beside it, so server_init's
    /// bounds still hold) edited to leave the connection an output span of the given octets.</summary>
    /// <param name="octets">The output span's octets.</param>
    /// <returns>The edit.</returns>
    private static ConfigSetter Output(int octets) => c =>
    {
        c->MaxMessage = (uint)(c->Memory - (nuint)octets);
        c->OutputMin = (nuint)octets;
    };

    /// <summary>
    /// An output_min that lies (edited after init, too small for a flight) is met by the engine's
    /// own room checks, inside the spans, at every point a handshake writes: the ServerHello's
    /// room, the HelloRetryRequest's, the change_cipher_spec after it (compatibility mode), and
    /// each message of the flight - EncryptedExtensions, Certificate, CertificateVerify's header
    /// and signature, Finished. Each fails the handshake with internal_error, the alert in the
    /// reserve: in the clear before keys, under the handshake key after the ServerHello (the open
    /// flight record dropped), read by the client. The sizes: a ServerHello for x25519 without
    /// a session id is 95 octets; a HelloRetryRequest 61 plus the session id; each flight put
    /// wants its octets, a record's 22 and the reserve's 64 after what is queued.
    /// </summary>
    [Fact]
    public void KeepsInsideItsSpansWhenOutputMinLies()
    {
        Platform.RequireLinuxX64();
        static void Fails(TlsServerHarness server, TlsTestClient client, bool keyed, string what)
        {
            TlsServerHarness.Received r = server.Receive(client.Hello());
            Assert.True(r.Answer == -1 && r.Event.Alert == 80, $"{what}: answer {r.Answer}, alert {r.Event.Alert}");
            client.Take(server.TakeOutput());
            Assert.True(client.Alerts.Count == 1 && client.Alerts[0] == (2, 80), $"{what}: alerts {string.Join(",", client.Alerts)}");
            Assert.False(client.ServerFinished, what);
            Assert.Equal(keyed, client.Group != 0 && !client.Retried);
        }

        // the ServerHello: 150 - 64 = 86 octets of room, under its 133 (101 and x25519's 32)
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], beforeStart: Output(150)))
        using (var client = new TlsTestClient())
        {
            Fails(server, client, false, "the ServerHello");
        }

        // the HelloRetryRequest (61 octets): 120 - 64 = 56 of room
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], groups: [TlsEngine.Secp256r1], beforeStart: Output(120)))
        using (var client = new TlsTestClient { Groups = [TlsEngine.X25519, TlsEngine.Secp256r1] })
        {
            Fails(server, client, false, "the HelloRetryRequest");
            Assert.False(client.Retried);
        }

        // with a session id of 4 the retry is 65 octets and fits 130 - 64 = 66; its
        // change_cipher_spec (6) then does not (1 left)
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], groups: [TlsEngine.Secp256r1], beforeStart: Output(130)))
        using (var client = new TlsTestClient { Groups = [TlsEngine.X25519, TlsEngine.Secp256r1], SessionId = [1, 2, 3, 4] })
        {
            Fails(server, client, false, "the change_cipher_spec after the retry");
            Assert.True(client.Retried);
        }

        // the flight's messages, with an Ed25519 key (its signature always 64 octets): their sizes
        // from a handshake whose output is whole
        TlsInteropTests.Credential ed = Credential("ed25519");
        int ee;
        nuint certificate;
        using (var server = new TlsServerHarness(ed.Key, [ed.Certificate]))
        using (var client = new TlsTestClient())
        {
            TlsServerRulesTests.Complete(server, client);
            ee = 4 + client.EncryptedExtensions.Length;
            certificate = server.Config.CertificateLength;
        }

        int[] puts = [ee, (int)certificate, 8, 64, 4 + 32];
        string[] names = ["EncryptedExtensions", "Certificate", "CertificateVerify's header", "the signature", "Finished"];
        int before = 0;
        for (int i = 0; i < puts.Length; i++)
        {
            int octets = 95 + before + puts[i] + 22 + 64 - 1;               // one short of this put
            using var server = new TlsServerHarness(ed.Key, [ed.Certificate], beforeStart: Output(octets));
            using var client = new TlsTestClient();
            Fails(server, client, true, $"the flight's {names[i]}");
            before += puts[i];
        }
    }

    /// <summary>
    /// The peer's record_size_limit bounds every record of the flight (RFC 8449 4): at 64, the
    /// least a peer may ask, the flight goes in records of 63 content octets (and the type); at
    /// exactly the flight's size and one, the whole flight fills one record to the octet, the
    /// last message sealing it, and nothing is left open for the flight's end. Both handshakes
    /// complete (an Ed25519 key: the flight's size the same in both).
    /// </summary>
    [Fact]
    [Requirement("RFC8449-4-p4")]
    public void CutsTheFlightToThePeersRecordSizeLimit()
    {
        Platform.RequireLinuxX64();
        TlsInteropTests.Credential ed = Credential("ed25519");
        int Handshake(int limit)
        {
            using var server = new TlsServerHarness(ed.Key, [ed.Certificate]);
            using var client = new TlsTestClient();
            client.Extra.Add((28, TlsTestClient.U16((ushort)limit)));
            Assert.True(server.Receive(client.Hello()).Answer > 0);
            byte[] output = server.TakeOutput();
            List<int> sealedRecords = [.. Records(output).Where(r => r.Type == 23).Select(r => r.Length)];
            Assert.All(sealedRecords, n => Assert.True(n <= limit + 16, $"a record of {n} octets under a limit of {limit}"));
            Assert.All(sealedRecords[..^1], n => Assert.Equal(limit + 16, n));     // full but the last
            client.Take(output);
            Assert.True(client.ServerFinished);
            foreach (TlsServerHarness.Received f in server.ReceiveAll(client.Finished()))
            {
                Assert.True(f.Answer > 0, $"the client's Finished: alert {f.Event.Alert}");
            }

            Assert.Equal(2, server.Progress());
            return sealedRecords.Sum(n => n - 17);                           // the flight's octets
        }

        int flight = Handshake(64);
        Assert.Equal(flight, Handshake(flight + 1));
    }

    /// <summary>
    /// A handshake message's header cut across records (RFC 9846 5.1): one octet, then the other
    /// three with the rest - gathered, the hello taken; one octet, then three announcing 20,000
    /// octets - refused once the header is whole (over max_message: illegal_parameter); a
    /// ClientHello refused for itself (legacy_version 0x0301) after it was gathered -
    /// protocol_version.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.1-2")]
    public void GathersAHeaderCutAcrossRecords()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient())
        {
            byte[] hello = client.Hello()[5..];
            Assert.Equal(6, server.Receive(TlsTestClient.Plain(22, hello[..1])).Answer);
            Assert.True(server.Receive(TlsTestClient.Plain(22, hello[1..])).Answer > 0);
            client.Take(server.TakeOutput());
            Assert.True(client.ServerFinished);
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient())
        {
            Assert.Equal(6, server.Receive(TlsTestClient.Plain(22, [1])).Answer);
            TlsServerHarness.Received r = server.Receive(TlsTestClient.Plain(22, [0x00, 0x4E, 0x20]));
            TlsServerRulesTests.Refused(server, client, r, 47, "a header announcing 20,000 octets");
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient { LegacyVersion = 0x0301 })
        {
            byte[] hello = client.Hello()[5..];
            Assert.Equal(6, server.Receive(TlsTestClient.Plain(22, hello[..1])).Answer);
            TlsServerRulesTests.Refused(server, client, server.Receive(TlsTestClient.Plain(22, hello[1..])), 70, "a gathered hello of 0x0301");
        }
    }

    /// <summary>
    /// Protected records that open to something the record layer refuses, waiting for the
    /// client's Finished: a TLSInnerPlaintext of 2^14 + 2 octets (record_overflow: 5.4's 2^14 + 1
    /// at most), one of zeros only (no content type: unexpected_message, 5.4), an empty handshake
    /// record (unexpected_message, 5.1); and a handshake message gathered across protected
    /// records with a change_cipher_spec between its parts (unexpected_message, 5.1: no
    /// interleaving). Each is our alert under the handshake key.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.4-6", "RFC9846-5.4-5#2", "RFC9846-5.1-3.1.1#2")]
    public void RefusesWhatProtectedRecordsOpenTo()
    {
        Platform.RequireLinuxX64();
        var cases = new (string What, Func<TlsTestClient, byte[]> Make, uint Alert)[]
        {
            ("2^14 + 2 octets of TLSInnerPlaintext", c => c.Seal(23, new byte[16385]), 22),
            ("zeros only", c => c.Seal(0, [], padding: 5), 10),
            ("an empty handshake record", c => c.Seal(22, []), 10),
        };
        foreach ((string what, Func<TlsTestClient, byte[]> make, uint alert) in cases)
        {
            (TlsServerHarness server, TlsTestClient client) = Flight();
            using (server)
            using (client)
            {
                TlsServerRulesTests.Refused(server, client, server.Receive(make(client)), alert, what);
            }
        }

        (TlsServerHarness s, TlsTestClient c2) = Flight();
        using (s)
        using (c2)
        {
            byte[] finished = TlsTestClient.Message(20, new byte[32]);
            Assert.True(s.Receive(c2.Seal(22, finished[..10])).Answer > 0);
            TlsServerRulesTests.Refused(s, c2, s.Receive(TlsTestClient.Plain(20, [1])), 10, "change_cipher_spec inside the Finished");
        }
    }

    /// <summary>
    /// Once connected: application data while a handshake message is being gathered (part of a
    /// KeyUpdate in one record, data in the next) is unexpected_message (5.1: no interleaving);
    /// empty application data records bring nothing and count toward the engine's bound, 32 in a
    /// row taken and the 33rd refused; KeyUpdates likewise (a peer could otherwise keep the
    /// server rekeying for nothing), the 33rd in a row refused.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-5.1-3.1.1#2")]
    public void RefusesInterleavingAndFloodsOnceConnected()
    {
        Platform.RequireLinuxX64();
        (TlsServerHarness s1, TlsTestClient c1) = Connected();
        using (s1)
        using (c1)
        {
            byte[] update = TlsTestClient.Message(24, [0]);
            Assert.True(s1.Receive(c1.Seal(22, update[..2])).Answer > 0);
            TlsServerRulesTests.Refused(s1, c1, s1.Receive(c1.SealData([1])), 10, "data inside a KeyUpdate");
        }

        (TlsServerHarness s2, TlsTestClient c2) = Connected();
        using (s2)
        using (c2)
        {
            for (int i = 0; i < 32; i++)
            {
                byte[] empty = c2.SealData([]);
                TlsServerHarness.Received r = s2.Receive(empty);
                Assert.True(r.Answer == empty.Length && r.Event.Kind == TlsEngine.EventNone, $"empty record {i + 1}: {r.Answer}");
            }

            TlsServerRulesTests.Refused(s2, c2, s2.Receive(c2.SealData([])), 10, "the 33rd empty record");
        }

        (TlsServerHarness s3, TlsTestClient c3) = Connected();
        using (s3)
        using (c3)
        {
            for (int i = 0; i < 32; i++)
            {
                TlsServerHarness.Received r = s3.Receive(c3.KeyUpdate(false));
                Assert.True(r.Answer > 0 && r.Event.Kind == TlsEngine.EventNone, $"KeyUpdate {i + 1}: alert {r.Event.Alert}");
            }

            TlsServerRulesTests.Refused(s3, c3, s3.Receive(c3.KeyUpdate(false)), 10, "the 33rd KeyUpdate in a row");
        }
    }

    /// <summary>
    /// Early data offered with a HelloRetryRequest coming (RFC 9846 4.3.10): the protected records
    /// before the second hello are skipped by their outer type, up to 16 KiB of them; past that,
    /// unexpected_message.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.3.10-14")]
    public void BoundsTheEarlyDataSkippedBeforeTheSecondHello()
    {
        Platform.RequireLinuxX64();
        using var server = new TlsServerHarness(P256.Key, [P256.Certificate], groups: [TlsEngine.Secp256r1]);
        using var client = new TlsTestClient { Groups = [TlsEngine.X25519, TlsEngine.Secp256r1] };
        client.Extra.Add((42, []));
        Assert.True(server.Receive(client.Hello()).Answer > 0);
        client.Take(server.TakeOutput());
        Assert.True(client.Retried);
        TlsServerHarness.Received r = default;
        int skipped = 0;
        while (skipped <= 16384)
        {
            r = server.Receive(Garbage(4000));
            if (r.Answer < 0)
            {
                break;
            }

            skipped += 4005;
        }

        Assert.True(r.Answer == -1 && r.Event.Alert == 10, $"past the bound: {r.Answer}, alert {r.Event.Alert}");
        Assert.True(skipped > 16384 - 4005 && skipped <= 16384, $"{skipped} octets skipped first");
    }

    /// <summary>
    /// Hellos refused before their negotiation: a first message that is not a ClientHello (a
    /// Finished in the clear: unexpected_message), and a ClientHello whose body does not parse
    /// (cut after legacy_version: decode_error).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.2.2-1#1")]
    public void RefusesWhatIsNoClientHello()
    {
        Platform.RequireLinuxX64();
        var cases = new (string What, byte[] Record, uint Alert)[]
        {
            ("a Finished first", TlsTestClient.Plain(22, TlsTestClient.Message(20, new byte[32])), 10),
            ("a ClientHello cut short", TlsTestClient.Plain(22, TlsTestClient.Message(1, [3, 3])), 50),
        };
        foreach ((string what, byte[] record, uint alert) in cases)
        {
            using var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
            using var client = new TlsTestClient();
            TlsServerRulesTests.Refused(server, client, server.Receive(record), alert, what);
        }
    }

    /// <summary>
    /// Hello shapes the server takes: post_handshake_auth offered (noted for 4c5; nothing else
    /// yet), no server_name (the EncryptedExtensions then without one), two shares in either
    /// order (the better ranked of the server's order taken, no retry), the server's own
    /// suites' order (ChaCha20-Poly1305 first: taken though the client lists it last); with
    /// HTTPASM_TLS_SERVER_GROUP_ORDER, the server's first group shared (taken at once, no retry)
    /// and no group in common (handshake_failure).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.2.1-8")]
    public void TakesTheHelloShapesItShould()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient())
        {
            client.Extra.Add((49, []));                                     // post_handshake_auth
            TlsServerRulesTests.Complete(server, client);
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate]))
        using (var client = new TlsTestClient { ServerName = null })
        {
            TlsServerRulesTests.Complete(server, client);
            // the block's length, then supported_groups alone (type, length, the list's length,
            // 13 groups): no server_name acknowledged, none having been sent
            Assert.Equal(2 + 4 + 2 + 26, client.EncryptedExtensions.Length);
        }

        foreach (ushort[] order in new[] { new[] { TlsEngine.X25519, TlsEngine.Secp256r1 }, [TlsEngine.Secp256r1, TlsEngine.X25519] })
        {
            using var server = new TlsServerHarness(P256.Key, [P256.Certificate]);
            using var client = new TlsTestClient { Groups = order, ShareGroups = order };
            TlsServerRulesTests.Complete(server, client);
            Assert.False(client.Retried);
            Assert.Equal(TlsEngine.X25519, client.Group);                   // second in the library's order, before P-256
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], suites: [0x1303, 0x1301]))
        using (var client = new TlsTestClient())
        {
            TlsServerRulesTests.Complete(server, client);
            Assert.Equal(0x1303, client.Suite);
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], flags: TlsEngine.ServerGroupOrder))
        using (var client = new TlsTestClient { Groups = [TlsEngine.X25519MlKem768, TlsEngine.X25519], ShareGroups = [TlsEngine.X25519MlKem768] })
        {
            TlsServerRulesTests.Complete(server, client);
            Assert.False(client.Retried);
            Assert.Equal(TlsEngine.X25519MlKem768, client.Group);
        }

        using (var server = new TlsServerHarness(P256.Key, [P256.Certificate], flags: TlsEngine.ServerGroupOrder))
        using (var client = new TlsTestClient { Groups = [0x0200], ShareGroups = [] })
        {
            TlsServerRulesTests.Refused(server, client, server.Receive(client.Hello()), 40, "no group in common, the server's order ruling");
        }
    }
}
