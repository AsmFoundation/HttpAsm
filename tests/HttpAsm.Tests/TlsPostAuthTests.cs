using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace HttpAsm.Tests;

/// <summary>
/// Post-handshake authentication on the engine's server (RFC 9846 4.7.2; M2 step 4c5): the
/// CertificateRequest httpasm_tls13_request_certificate queues after the handshake, the client's
/// answer taken in its order and verified over ClientHello .. client Finished + the request (its
/// Finished under the client's current application secret), every refusal and every call's
/// answer; against the tests' own client and `openssl s_client -enable_pha`.
/// </summary>
public sealed class TlsPostAuthTests
{
    /// <summary>The server's credential (P-256).</summary>
    private static readonly TlsInteropTests.Credential Server = TlsInteropTests.Make("p256");

    /// <summary>The client credentials made so far, by kind.</summary>
    private static readonly Dictionary<string, TlsInteropTests.Credential> Clients = [];

    /// <summary>A client credential of a kind, made once.</summary>
    /// <param name="kind">"p256", "rsa2048" (.NET's) or "ed25519" (openssl's).</param>
    /// <returns>The credential.</returns>
    private static TlsInteropTests.Credential Client(string kind)
    {
        lock (Clients)
        {
            if (!Clients.TryGetValue(kind, out TlsInteropTests.Credential? c))
            {
                c = kind is "ed25519" or "ed448" or "rsa-pss" ? TlsOpenSslCliTests.Make(kind) : TlsInteropTests.Make(kind);
                Clients[kind] = c;
            }

            return c;
        }
    }

    /// <summary>A server with client authentication configured (the peer-chain span) and a client
    /// that offered post_handshake_auth, connected; the client holds a credential of a kind for
    /// its answers.</summary>
    /// <param name="kind">The client key's kind.</param>
    /// <param name="random">The server's random source (null: random).</param>
    /// <returns>Both sides.</returns>
    private static (TlsServerHarness Server, TlsTestClient Client) Connected(string kind = "p256", RandomScript? random = null)
    {
        var server = new TlsServerHarness(Server.Key, [Server.Certificate], random, flags: TlsEngine.ClientAuthRequest);
        TlsInteropTests.Credential c = Client(kind);
        var client = new TlsTestClient();
        client.Extra.Add((49, []));                                         // post_handshake_auth
        // (no certificate in the handshake: the post-handshake answer is the test's)
        TlsServerRulesTests.Complete(server, client);
        client.ClientChain = [c.Certificate];
        client.ClientKey = TlsTestClient.ClientSigner(kind, c.Key);
        return (server, client);
    }

    /// <summary>Requests, hands the request to the client, and feeds the client's answer back:
    /// the server's last answer.</summary>
    /// <param name="server">The server.</param>
    /// <param name="client">The client.</param>
    /// <returns>The last call's answer.</returns>
    private static TlsServerHarness.Received Exchange(TlsServerHarness server, TlsTestClient client)
    {
        Assert.Equal(0, server.RequestCertificate());
        client.Take(server.TakeOutput());
        Assert.NotNull(client.PostRequestContext);
        return server.ReceiveAll(client.PostAnswer()).Last();
    }

    /// <summary>
    /// A client of each kind of key answers the request: the request carries 16 random octets of
    /// context, the Certificate, CertificateVerify and Finished are taken, the call that takes the
    /// Finished reports AUTHENTICATED, and the chain is the one sent. A second request then has
    /// another context and is answered as well (each exchange's transcript starts from the
    /// handshake's again, 4.4); a third after the client's KeyUpdate (the Finished's key is the
    /// client's current application secret). Data flows between them.
    /// </summary>
    /// <param name="kind">The client key's kind.</param>
    [Theory]
    [InlineData("p256")]
    [InlineData("rsa2048")]
    [InlineData("ed25519")]
    [Requirement("RFC9846-4.7.2-1#1", "RFC9846-4.7.2-1#3", "RFC9846-4.4.2-4.2.1#1", "RFC9846-4.4.2-4.2.1#3")]
    public void AuthenticatesAfterTheHandshake(string kind)
    {
        Platform.RequireLinuxX64();
        (TlsServerHarness server, TlsTestClient client) = Connected(kind);
        using (server)
        using (client)
        {
            Assert.Equal(0, server.PeerCount());                             // the handshake's request, declined
            TlsServerHarness.Received r = Exchange(server, client);
            Assert.True(r.Answer > 0 && r.Event.Kind == TlsEngine.EventAuthenticated, $"{kind}: {r.Answer}, event {r.Event.Kind}, alert {r.Event.Alert}");
            Assert.Equal([Client(kind).Certificate], server.PeerChain());

            Assert.Equal(0, server.RequestCertificate());
            client.Take(server.TakeOutput());
            byte[] second = client.PostRequestContext!;
            Assert.Equal(16, second.Length);
            byte[] data = RandomNumberGenerator.GetBytes(100);
            Assert.Equal(data, server.Receive(client.SealData(data)).Data);    // data before the answer: taken
            Assert.True(server.Receive(client.KeyUpdate(false)).Answer > 0);    // a KeyUpdate before it too
            r = server.ReceiveAll(client.PostAnswer()).Last();
            Assert.Equal(TlsEngine.EventAuthenticated, r.Event.Kind);

            r = Exchange(server, client);
            Assert.Equal(TlsEngine.EventAuthenticated, r.Event.Kind);
            Assert.Equal(data, server.Receive(client.SealData(data)).Data);
        }
    }

    /// <summary>
    /// A client that declines (an empty Certificate, then its Finished: 4.7.2-1#4): AUTHENTICATED
    /// all the same, the chain empty (0 entries); whether to go on is the caller's.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.7.2-1#4")]
    public void ReportsAClientThatDeclines()
    {
        Platform.RequireLinuxX64();
        (TlsServerHarness server, TlsTestClient client) = Connected();
        using (server)
        using (client)
        {
            client.ClientChain = null;
            TlsServerHarness.Received r = Exchange(server, client);
            Assert.Equal(TlsEngine.EventAuthenticated, r.Event.Kind);
            Assert.Equal(0, server.PeerCount());
        }
    }

    /// <summary>
    /// The request is refused (-1, nothing sent) where 4.7.2 or the engine forbid it: before the
    /// handshake completed, for a client that did not offer post_handshake_auth (4.3.6-1#1), on a
    /// connection without the peer-chain span (no client authentication configured), while one is
    /// outstanding, after our close_notify, after a failure, when the random source fails at the
    /// context's draw, and when the output cannot hold it (a request then goes once drained).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.3.6-1#1")]
    public void RefusesTheRequestsItMust()
    {
        Platform.RequireLinuxX64();
        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest))
        using (var client = new TlsTestClient())
        {
            client.Extra.Add((49, []));
            Assert.Equal(-1, server.RequestCertificate());                  // before the hello
            Assert.True(server.Receive(client.Hello()).Answer > 0);
            client.Take(server.TakeOutput());
            Assert.Equal(-1, server.RequestCertificate());                  // before the client's Finished
        }

        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest))
        using (var client = new TlsTestClient())
        {
            TlsServerRulesTests.Complete(server, client);                   // no post_handshake_auth
            Assert.Equal(-1, server.RequestCertificate());
            Assert.Empty(server.TakeOutput());
        }

        using (var server = new TlsServerHarness(Server.Key, [Server.Certificate]))
        using (var client = new TlsTestClient())
        {
            client.Extra.Add((49, []));
            TlsServerRulesTests.Complete(server, client);                   // no peer-chain span
            Assert.Equal(-1, server.RequestCertificate());
        }

        (TlsServerHarness s1, TlsTestClient c1) = Connected();
        using (s1)
        using (c1)
        {
            Assert.Equal(0, s1.RequestCertificate());
            Assert.Equal(-1, s1.RequestCertificate());                      // one outstanding
            Assert.Equal(0, s1.Close());
            _ = s1.TakeOutput();
        }

        (TlsServerHarness s2, TlsTestClient c2) = Connected();
        using (s2)
        using (c2)
        {
            Assert.Equal(0, s2.Close());
            Assert.Equal(-1, s2.RequestCertificate());                      // after our close_notify
        }

        (TlsServerHarness s3, TlsTestClient c3) = Connected();
        using (s3)
        using (c3)
        {
            Assert.Equal(-1, s3.Receive(TlsTestClient.Plain(21, [2, 40])).Answer);
            Assert.Equal(-1, s3.RequestCertificate());                      // after a failure
        }

        // the handshake draws 3 times (the random, x25519's scalar, the hedge): the 4th is the context
        (TlsServerHarness s4, TlsTestClient c4) = Connected(random: new RandomScript { FailAt = 4 });
        using (s4)
        using (c4)
        {
            Assert.Equal(-1, s4.RequestCertificate());
            Assert.Empty(s4.TakeOutput());
            Assert.Equal(0, s4.RequestCertificate());                       // the source answers again
        }

        (TlsServerHarness s5, TlsTestClient c5) = Connected();
        using (s5)
        using (c5)
        {
            byte[] fill = new byte[1 << 16];
            while (s5.Send(fill) > 0)
            {
            }

            Assert.Equal(-1, s5.RequestCertificate());                      // no room
            c5.Take(s5.TakeOutput());
            TlsServerHarness.Received r = Exchange(s5, c5);
            Assert.Equal(TlsEngine.EventAuthenticated, r.Event.Kind);
        }
    }

    /// <summary>
    /// What the client's answer may not be, each by its alert: a Certificate of another context
    /// (illegal_parameter); a CertificateVerify that does not verify (decrypt_error); a Finished
    /// that does not verify (decrypt_error) or of 31 octets (decode_error); application data or a
    /// KeyUpdate between the answer's messages (unexpected_message: 4.7.2-1#5); and, with no
    /// request outstanding, a Certificate, a CertificateVerify or a Finished (unexpected_message);
    /// a CertificateVerify for a declined answer and a Finished for a Certificate with
    /// certificates (out of their turn: unexpected_message).
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.7.2-1#5", "RFC9846-4.5.2-19")]
    public void RefusesWhatAnAnswerMayNotBe()
    {
        Platform.RequireLinuxX64();
        var cases = new (string What, Action<TlsTestClient>? Shape, Func<TlsServerHarness, TlsTestClient, TlsServerHarness.Received> Run, uint Alert)[]
        {
            ("another context", c => c.AnswerContext = new byte[16], (s, c) => s.ReceiveAll(c.PostAnswer()).Last(), 47),
            ("a CertificateVerify that does not verify", c => c.CorruptSignature = true, (s, c) => s.ReceiveAll(c.PostAnswer()).Last(), 51),
            ("a CertificateVerify for a declined answer", c => { c.ClientChain = null; c.VerifyEmpty = true; }, (s, c) => s.ReceiveAll(c.PostAnswer()).Last(), 10),
            ("no CertificateVerify", c => c.OmitCertificateVerify = true, (s, c) => s.ReceiveAll(c.PostAnswer()).Last(), 10),
            ("a Finished that does not verify", null, (s, c) => WrongFinished(s, c), 51),
            ("data between the Certificate and the CertificateVerify", null, (s, c) => Between(s, c, () => c.SealData([1])), 10),
            ("a KeyUpdate between them", null, (s, c) => Between(s, c, () => c.KeyUpdate(false)), 10),
        };
        foreach ((string what, Action<TlsTestClient>? shape, Func<TlsServerHarness, TlsTestClient, TlsServerHarness.Received> run, uint alert) in cases)
        {
            (TlsServerHarness server, TlsTestClient client) = Connected();
            using (server)
            using (client)
            {
                shape?.Invoke(client);
                Assert.Equal(0, server.RequestCertificate());
                client.Take(server.TakeOutput());
                TlsServerRulesTests.Refused(server, client, run(server, client), alert, what);
            }
        }

        // with nothing outstanding
        var unasked = new (string What, byte[] Message, uint Alert)[]
        {
            ("a Certificate", TlsTestClient.Message(11, [0, 0, 0, 0]), 10),
            ("a CertificateVerify", TlsTestClient.Message(15, [4, 3, 0, 0]), 10),
            ("a Finished", TlsTestClient.Message(20, new byte[32]), 10),
        };
        foreach ((string what, byte[] message, uint alert) in unasked)
        {
            (TlsServerHarness server, TlsTestClient client) = Connected();
            using (server)
            using (client)
            {
                TlsServerRulesTests.Refused(server, client, server.Receive(client.Seal(22, message)), alert, $"unasked: {what}");
            }
        }

        // a Finished of 31 octets, after a declined answer's Certificate
        (TlsServerHarness s6, TlsTestClient c6) = Connected();
        using (s6)
        using (c6)
        {
            Assert.Equal(0, s6.RequestCertificate());
            c6.Take(s6.TakeOutput());
            byte[] certificate = TlsTestClient.Message(11, [16, .. c6.PostRequestContext!, 0, 0, 0]);
            Assert.True(s6.Receive(c6.Seal(22, certificate)).Answer > 0);
            TlsServerRulesTests.Refused(s6, c6, s6.Receive(c6.Seal(22, TlsTestClient.Message(20, new byte[31]))), 50, "a Finished of 31 octets");
        }

        // a Finished for a Certificate with certificates (its CertificateVerify due)
        (TlsServerHarness s7, TlsTestClient c7) = Connected();
        using (s7)
        using (c7)
        {
            Assert.Equal(0, s7.RequestCertificate());
            c7.Take(s7.TakeOutput());
            byte[] leaf = Client("p256").Certificate;
            byte[] certificate = TlsTestClient.Message(11, [16, .. c7.PostRequestContext!, .. TlsTestClient.U24(leaf.Length + 5), .. TlsTestClient.U24(leaf.Length), .. leaf, 0, 0]);
            Assert.True(s7.Receive(c7.Seal(22, certificate)).Answer > 0);
            TlsServerRulesTests.Refused(s7, c7, s7.Receive(c7.Seal(22, TlsTestClient.Message(20, new byte[32]))), 10, "a Finished for the CertificateVerify");
        }
    }

    /// <summary>The client's answer but its Finished (its Certificate and CertificateVerify, which
    /// the server takes), then a Finished of the right length whose MAC is random: a ciphertext
    /// altered would not open, so the wrong MAC is sealed properly under the client's key.</summary>
    /// <param name="server">The server.</param>
    /// <param name="client">The client.</param>
    /// <returns>The server's answer to the wrong Finished.</returns>
    private static TlsServerHarness.Received WrongFinished(TlsServerHarness server, TlsTestClient client)
    {
        client.OmitFinished = true;
        foreach (TlsServerHarness.Received r in server.ReceiveAll(client.PostAnswer()))
        {
            Assert.True(r.Answer > 0, $"the answer's first records: alert {r.Event.Alert}");
        }

        return server.Receive(client.Seal(22, TlsTestClient.Message(20, RandomNumberGenerator.GetBytes(32))));
    }

    /// <summary>The answer's Certificate fed, then something else, before its CertificateVerify.</summary>
    /// <param name="server">The server.</param>
    /// <param name="client">The client.</param>
    /// <param name="between">Seals the record that comes between (after the Certificate: the
    /// records' sequence numbers follow their order).</param>
    /// <returns>The server's answer to it.</returns>
    private static TlsServerHarness.Received Between(TlsServerHarness server, TlsTestClient client, Func<byte[]> between)
    {
        byte[] leaf = Client("p256").Certificate;
        byte[] certificate = TlsTestClient.Message(11, [16, .. client.PostRequestContext!, .. TlsTestClient.U24(leaf.Length + 5), .. TlsTestClient.U24(leaf.Length), .. leaf, 0, 0]);
        Assert.True(server.Receive(client.Seal(22, certificate)).Answer > 0);
        return server.Receive(between());
    }

    /// <summary>
    /// `openssl s_client -enable_pha` with its certificate and key: after the handshake the server
    /// requests, s_client answers on its own (OpenSSL's post-handshake authentication), the engine
    /// reports AUTHENTICATED and keeps the certificate s_client sent.
    /// </summary>
    /// <param name="kind">The client key's kind.</param>
    [Theory]
    [InlineData("p256")]
    [InlineData("ed25519")]
    public void AuthenticatesOpenSslAfterTheHandshake(string kind)
    {
        Platform.RequireLinuxX64();
        TlsInteropTests.Credential client = kind == "p256" ? TlsOpenSslCliTests.Make("p256") : Client(kind);
        string directory = Directory.CreateTempSubdirectory("httpasm-pha-").FullName;
        try
        {
            string cert = Path.Combine(directory, "client.der"), key = Path.Combine(directory, "client.pem");
            File.WriteAllBytes(cert, client.Certificate);
            File.WriteAllBytes(key, client.Key);
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var server = new TlsServerHarness(Server.Key, [Server.Certificate], flags: TlsEngine.ClientAuthRequest);
            string? failure = null;
            bool authenticated = false;
            var pump = new Thread(() =>
            {
                try
                {
                    using Socket s = listener.AcceptSocket();
                    authenticated = Pump(server, s);
                }
                catch (Exception e)
                {
                    failure = e.ToString();
                }
            }) { IsBackground = true };
            pump.Start();

            string error = SClient(port, cert, key, pump);
            Assert.True(failure is null, $"{failure}\n{error}");
            Assert.True(authenticated, error);
            Assert.Equal([client.Certificate], server.PeerChain());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Runs `openssl s_client -enable_pha` with a certificate against the port until the
    /// server's pump ended (s_client, its input kept open, ends on the server's close).</summary>
    /// <param name="port">The server's port.</param>
    /// <param name="cert">The client certificate's DER file.</param>
    /// <param name="key">Its key's PEM file.</param>
    /// <param name="pump">The server's pump thread (joined here).</param>
    /// <returns>s_client's standard error (-brief's summary, or what failed).</returns>
    private static string SClient(int port, string cert, string key, Thread pump)
    {
        var start = new ProcessStartInfo("openssl", $"s_client -connect 127.0.0.1:{port} -tls1_3 -brief -servername localhost -enable_pha -cert {cert} -certform DER -key {key}")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using Process p = Process.Start(start)!;
        Task<string> error = p.StandardError.ReadToEndAsync();
        _ = p.StandardOutput.ReadToEndAsync();
        Assert.True(pump.Join(TimeSpan.FromSeconds(60)), "the server pump did not finish");
        if (!p.WaitForExit(30000))
        {
            p.Kill();
        }

        return error.Result;
    }

    /// <summary>The server's side of the s_client run: the handshake, then a post-handshake request
    /// as soon as it completed, the client's answer until AUTHENTICATED, then close_notify and the
    /// socket's send side.</summary>
    /// <param name="server">The engine's connection.</param>
    /// <param name="s">The accepted socket.</param>
    /// <returns>Whether AUTHENTICATED came before the client went away.</returns>
    /// <exception cref="InvalidOperationException">The engine failed or refused the request.</exception>
    private static bool Pump(TlsServerHarness server, Socket s)
    {
        s.NoDelay = true;
        var buffer = new byte[1 << 18];
        int filled = 0;
        s.ReceiveTimeout = 20000;
        while (true)
        {
            int n = s.Receive(buffer, filled, buffer.Length - filled, SocketFlags.None);
            if (n == 0)
            {
                return false;
            }

            filled += n;
            int at = 0;
            while (at < filled)
            {
                TlsServerHarness.Received r = server.Receive(buffer.AsSpan(at, filled - at));
                if (r.Answer < 0)
                {
                    s.Send(server.TakeOutput());
                    throw new InvalidOperationException($"the engine failed: alert {r.Event.Alert}, flags {r.Event.Flags}");
                }

                if (r.Answer == 0)
                {
                    break;
                }

                at += (int)r.Answer;
                if (r.Event.Kind == TlsEngine.EventConnected && server.RequestCertificate() != 0)
                {
                    throw new InvalidOperationException("the request was refused");
                }

                byte[] output = server.TakeOutput();
                if (output.Length > 0)
                {
                    s.Send(output);
                }

                if (r.Event.Kind == TlsEngine.EventAuthenticated)
                {
                    Assert.Equal(0, server.Close());
                    s.Send(server.TakeOutput());
                    s.Shutdown(SocketShutdown.Send);
                    return true;
                }
            }

            Buffer.BlockCopy(buffer, at, buffer, 0, filled - at);
            filled -= at;
        }
    }
}
