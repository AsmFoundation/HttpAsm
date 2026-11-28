using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HttpAsm.Tests;

/// <summary>
/// The engine's server against .NET's SslStream as the client: on Linux SslStream is OpenSSL's
/// TLS 1.3 (3.0 in the WSL image and on CI's runners), an implementation written apart from this
/// one. Each handshake runs over loopback TCP, the engine pumped by a thread of the test (records
/// read off the socket, fed one at a time, its output written back), and carries application data
/// both ways (an echo) and both sides' close_notify.
/// </summary>
public sealed class TlsInteropTests
{
    /// <summary>A server key and its self-signed certificate, made by .NET.</summary>
    /// <param name="Key">The private key as PKCS#8 DER.</param>
    /// <param name="Certificate">The certificate's DER.</param>
    internal sealed record Credential(byte[] Key, byte[] Certificate);

    /// <summary>Makes a key of a kind and a certificate for "localhost" signed by it.</summary>
    /// <param name="kind">"rsa2048", "p256", "p384" or "p521".</param>
    /// <returns>The credential.</returns>
    /// <exception cref="ArgumentException">Another kind.</exception>
    internal static Credential Make(string kind)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CertificateRequest request;
        byte[] key;
        switch (kind)
        {
            case "rsa2048":
                {
                    using RSA rsa = RSA.Create(2048);
                    request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    key = rsa.ExportPkcs8PrivateKey();
                    using X509Certificate2 c = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
                    return new Credential(key, c.RawData);
                }

            case "p256":
            case "p384":
            case "p521":
                {
                    ECCurve curve = kind switch { "p256" => ECCurve.NamedCurves.nistP256, "p384" => ECCurve.NamedCurves.nistP384, _ => ECCurve.NamedCurves.nistP521 };
                    HashAlgorithmName hash = kind switch { "p256" => HashAlgorithmName.SHA256, "p384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
                    using ECDsa ec = ECDsa.Create(curve);
                    request = new CertificateRequest("CN=localhost", ec, hash);
                    key = ec.ExportPkcs8PrivateKey();
                    using X509Certificate2 c = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
                    return new Credential(key, c.RawData);
                }

            default:
                throw new ArgumentException($"unknown kind {kind}", nameof(kind));
        }
    }

    /// <summary>What one interop run saw.</summary>
    /// <param name="Suite">SslStream's negotiated suite.</param>
    /// <param name="Echoed">What came back for what was sent.</param>
    /// <param name="Negotiated">The engine's own account (progress, suite, group, scheme).</param>
    /// <param name="ServerSawClose">Whether the engine got the client's close_notify.</param>
    /// <param name="Draws">The engine's random draws' lengths.</param>
    internal sealed record Run(TlsCipherSuite Suite, byte[] Echoed, (int Progress, uint Suite, uint Group, uint Scheme) Negotiated,
        bool ServerSawClose, IReadOnlyList<int> Draws);

    /// <summary>
    /// One handshake between SslStream and the engine over loopback TCP, then an echo of data and
    /// both close_notifys.
    /// </summary>
    /// <param name="credential">The server's key and certificate.</param>
    /// <param name="suite">The one suite the client offers (CipherSuitesPolicy), or null for its default list.</param>
    /// <param name="groups">The server's groups (null: the library's).</param>
    /// <param name="flags">The server's configuration flags.</param>
    /// <param name="payload">What the client sends.</param>
    /// <returns>What happened.</returns>
    /// <exception cref="InvalidOperationException">The server pump failed (its message says how).</exception>
    internal static Run Handshake(Credential credential, TlsCipherSuite? suite, ushort[]? groups, uint flags, byte[] payload)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var server = new TlsServerHarness(credential.Key, [credential.Certificate], groups: groups, flags: flags);
        Assert.Equal(0, server.ConfigAnswer);
        bool sawClose = false;
        string? failure = null;
        var pump = new Thread(() =>
        {
            try
            {
                using Socket s = listener.AcceptSocket();
                s.NoDelay = true;
                var buffer = new byte[1 << 18];
                int filled = 0;
                while (true)
                {
                    int n = s.Receive(buffer, filled, buffer.Length - filled, SocketFlags.None);
                    if (n == 0)
                    {
                        return;                                             // the client is gone
                    }

                    filled += n;
                    int at = 0;
                    while (at < filled)
                    {
                        TlsServerHarness.Received r = server.Receive(buffer.AsSpan(at, filled - at));
                        if (r.Answer == 0)
                        {
                            break;                                          // a record not whole yet
                        }

                        byte[] output = server.TakeOutput();
                        if (r.Answer < 0)
                        {
                            s.Send(output);
                            failure = $"the engine failed: alert {r.Event.Alert}, flags {r.Event.Flags}";
                            return;
                        }

                        at += (int)r.Answer;
                        if (r.Event.Kind == TlsEngine.EventData)
                        {
                            // the echo: send takes what the output span holds, so a caller drains
                            // it and sends the rest, as many rounds as that takes
                            s.Send(output);
                            output = [];
                            ReadOnlySpan<byte> rest = r.Data;
                            while (rest.Length > 0)
                            {
                                long taken = server.Send(rest);
                                Assert.True(taken > 0, $"send took {taken} of {rest.Length} octets with the output drained");
                                s.Send(server.TakeOutput());
                                rest = rest[(int)taken..];
                            }
                        }
                        else if (r.Event.Kind == TlsEngine.EventClosed)
                        {
                            sawClose = true;
                            Assert.Equal(0, server.Close());
                            output = [.. output, .. server.TakeOutput()];
                        }

                        if (output.Length > 0)
                        {
                            s.Send(output);
                        }
                    }

                    Buffer.BlockCopy(buffer, at, buffer, 0, filled - at);
                    filled -= at;
                }
            }
            catch (Exception e)
            {
                failure = e.ToString();
            }
        }) { IsBackground = true };
        pump.Start();

        TlsCipherSuite negotiated;
        byte[] echoed = new byte[payload.Length];
        using (var client = new TcpClient())
        {
            client.NoDelay = true;
            client.Connect(IPAddress.Loopback, port);
            using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    certificate is not null && certificate.GetRawCertData().AsSpan().SequenceEqual(credential.Certificate),
            };
            // (CipherSuitesPolicy exists on Linux and macOS only; these tests run on Linux)
            if (suite is { } one && !OperatingSystem.IsWindows())
            {
                options.CipherSuitesPolicy = new CipherSuitesPolicy([one]);
            }

            tls.AuthenticateAsClient(options);
            negotiated = tls.NegotiatedCipherSuite;
            tls.Write(payload);
            tls.Flush();
            int got = 0;
            while (got < payload.Length)
            {
                int n = tls.Read(echoed, got, payload.Length - got);
                Assert.True(n > 0, $"the echo ended after {got} octets");
                got += n;
            }

            tls.ShutdownAsync().GetAwaiter().GetResult();               // close_notify
            var rest = new byte[16];
            Assert.Equal(0, tls.Read(rest, 0, rest.Length));            // the server's close_notify
        }

        Assert.True(pump.Join(TimeSpan.FromSeconds(30)), "the server pump did not finish");
        if (failure is not null)
        {
            throw new InvalidOperationException(failure);
        }

        return new Run(negotiated, echoed, server.Negotiated(), sawClose, server.Random.Lengths);
    }

    /// <summary>Every key kind with every suite a client may force: the interop matrix.</summary>
    /// <returns>(the key's kind, the suite's .NET name) for each pairing.</returns>
    public static TheoryData<string, string> KindsAndSuites()
    {
        var data = new TheoryData<string, string>();
        foreach (string kind in new[] { "rsa2048", "p256", "p384", "p521" })
        {
            foreach (string suite in new[] { "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256" })
            {
                data.Add(kind, suite);
            }
        }

        return data;
    }

    /// <summary>
    /// Every key kind .NET makes (RSA 2048, ECDSA on P-256, P-384, P-521) under every suite the
    /// client is made to offer alone: OpenSSL's client accepts the engine's handshake (its
    /// certificate, its CertificateVerify in the scheme the key makes, its Finished), the engine
    /// accepts the client's Finished, 20,000 octets go there and back, and each side's
    /// close_notify reaches the other. The engine says what it chose: the suite forced, x25519
    /// (OpenSSL's share), and rsa_pss_rsae_sha256 or the curve's ECDSA scheme.
    /// </summary>
    /// <param name="kind">The key's kind.</param>
    /// <param name="suiteName">The suite forced.</param>
    [Theory]
    [MemberData(nameof(KindsAndSuites))]
    [Requirement("RFC9846-4.2.1-8", "RFC9846-4.5.2-16#1", "RFC9846-6.1-4", "RFC9846-6.1-2.2.1#2")]
    public void ShakesHandsWithOpenSsl(string kind, string suiteName)
    {
        Platform.RequireLinuxX64();
        TlsCipherSuite suite = Enum.Parse<TlsCipherSuite>(suiteName);
        byte[] payload = RandomNumberGenerator.GetBytes(20000);
        Run run = Handshake(Make(kind), suite, null, 0, payload);
        Assert.Equal(suite, run.Suite);
        Assert.Equal(payload, run.Echoed);
        Assert.True(run.ServerSawClose);
        uint scheme = kind switch { "rsa2048" => 0x0804u, "p256" => 0x0403u, "p384" => 0x0503u, _ => 0x0603u };
        Assert.Equal((2, (uint)suite, (uint)TlsEngine.X25519, scheme), run.Negotiated);
        // the draws: the random, X25519's scalar, then the salt (RSA-PSS SHA-256) or the hedge
        int last = kind switch { "rsa2048" => 32, "p256" => 32, "p384" => 48, _ => 66 };
        Assert.Equal([32, 32, last], run.Draws);
    }

    /// <summary>
    /// A server that takes only a group OpenSSL sent no share for (secp256r1, secp384r1,
    /// secp521r1, x448: OpenSSL 3.0 shares x25519 alone) answers with a HelloRetryRequest naming
    /// it; OpenSSL's second ClientHello carries that share and the handshake completes over that
    /// group, data and closes as above. With the server's order ruling (HTTPASM_TLS_SERVER_GROUP_ORDER)
    /// and secp256r1 first, the same retry happens though x25519 is the server's too.
    /// </summary>
    /// <param name="group">The group the server takes.</param>
    /// <param name="ordered">Whether x25519 is also the server's, behind it, with its order ruling.</param>
    [Theory]
    [InlineData(TlsEngine.Secp256r1, false)]
    [InlineData(TlsEngine.Secp384r1, false)]
    [InlineData(TlsEngine.Secp521r1, false)]
    [InlineData(TlsEngine.X448, false)]
    [InlineData(TlsEngine.Secp256r1, true)]
    [Requirement("RFC9846-4.2.1-5", "RFC9846-4.2.4-2#1", "RFC9846-4.2.4-6#2")]
    public void RetriesForTheGroupItTakes(ushort group, bool ordered)
    {
        Platform.RequireLinuxX64();
        byte[] payload = RandomNumberGenerator.GetBytes(1000);
        ushort[] groups = ordered ? [group, TlsEngine.X25519] : [group];
        Run run = Handshake(Make("p256"), null, groups, ordered ? TlsEngine.ServerGroupOrder : 0, payload);
        Assert.Equal(payload, run.Echoed);
        Assert.Equal(2, run.Negotiated.Progress);
        Assert.Equal(group, run.Negotiated.Group);
        int scalar = group switch { TlsEngine.Secp384r1 => 48, TlsEngine.Secp521r1 => 66, TlsEngine.X448 => 56, _ => 32 };
        Assert.Equal([32, scalar, 32], run.Draws);
    }
}
