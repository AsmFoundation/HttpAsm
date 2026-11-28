using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace HttpAsm.Tests;

/// <summary>
/// The engine's server against OpenSSL's command-line client, openssl s_client (3.0 in the WSL
/// image and on CI's runners): what SslStream cannot ask for. Each group s_client has, offered
/// alone so its share is the one taken (the finite fields and x448 among them); each signature
/// scheme, forced with -sigalgs, with keys of every kind openssl genpkey makes (RSA,
/// RSASSA-PSS, the three curves, Ed25519, Ed448); and a KeyUpdate s_client asks for. Each run
/// sends a line, the engine echoes it and closes; s_client's -brief summary and the engine's
/// own account must agree on what was chosen.
/// </summary>
public sealed class TlsOpenSslCliTests
{
    /// <summary>Runs a program to its end.</summary>
    /// <param name="file">The program.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="directory">Its working directory.</param>
    /// <returns>The exit code and both outputs.</returns>
    /// <exception cref="TimeoutException">It ran over a minute.</exception>
    private static (int Exit, string Out, string Err) Run(string file, string arguments, string directory)
    {
        var start = new ProcessStartInfo(file, arguments)
        {
            WorkingDirectory = directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using Process p = Process.Start(start)!;
        Task<string> output = p.StandardOutput.ReadToEndAsync();
        Task<string> error = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(60000))
        {
            p.Kill();
            throw new TimeoutException($"{file} {arguments}");
        }

        return (p.ExitCode, output.Result, error.Result);
    }

    /// <summary>A key of a kind and a self-signed certificate for "localhost", made by openssl
    /// (genpkey, then req -x509).</summary>
    /// <param name="kind">"rsa", "rsa-pss" (no parameters), "rsa-pss-sha256" (bound to SHA-256, a
    /// 32-octet minimum salt), "rsa-pss-sha256-salt64" (a 64-octet minimum), "p256", "p384",
    /// "p521", "ed25519" or "ed448".</param>
    /// <returns>The key's PEM (PKCS#8) and the certificate's DER.</returns>
    /// <exception cref="ArgumentException">Another kind.</exception>
    /// <exception cref="InvalidOperationException">openssl refused (its output says why).</exception>
    internal static TlsInteropTests.Credential Make(string kind)
    {
        string directory = Directory.CreateTempSubdirectory("httpasm-tls-").FullName;
        try
        {
            string algorithm = kind switch
            {
                "rsa" => "-algorithm RSA -pkeyopt rsa_keygen_bits:2048",
                "rsa-pss" => "-algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048",
                "rsa-pss-sha256" => "-algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32",
                "rsa-pss-sha256-salt64" => "-algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:64",
                "p256" => "-algorithm EC -pkeyopt ec_paramgen_curve:P-256",
                "p384" => "-algorithm EC -pkeyopt ec_paramgen_curve:P-384",
                "p521" => "-algorithm EC -pkeyopt ec_paramgen_curve:P-521",
                "ed25519" => "-algorithm ED25519",
                "ed448" => "-algorithm ED448",
                _ => throw new ArgumentException($"unknown kind {kind}", nameof(kind)),
            };
            (int exit, string output, string error) = Run("openssl", $"genpkey {algorithm} -out key.pem", directory);
            if (exit != 0)
            {
                throw new InvalidOperationException($"genpkey: {output}{error}");
            }

            (exit, output, error) = Run("openssl", "req -x509 -new -key key.pem -subj /CN=localhost -days 2 -outform DER -out cert.der", directory);
            if (exit != 0)
            {
                throw new InvalidOperationException($"req: {output}{error}");
            }

            return new TlsInteropTests.Credential(File.ReadAllBytes(Path.Combine(directory, "key.pem")), File.ReadAllBytes(Path.Combine(directory, "cert.der")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>What one s_client run saw.</summary>
    /// <param name="Out">Its standard output: the echo (and -msg's lines when asked).</param>
    /// <param name="Err">Its standard error: -brief's summary.</param>
    /// <param name="Negotiated">The engine's own account.</param>
    /// <param name="Served">What the server pump saw.</param>
    internal sealed record SClientRun(string Out, string Err, (int Progress, uint Suite, uint Group, uint Scheme) Negotiated, TlsInteropTests.Served Served);

    /// <summary>
    /// One s_client run against the engine over loopback TCP: s_client connects (TLS 1.3 only,
    /// -brief, any extra arguments), its standard input gets the lines one by one (each after
    /// the server took a record, when waitBetween is set: s_client reads a command letter only
    /// alone on a read), the engine echoes the first application data and closes, and s_client,
    /// with its input still open, ends on the server's close.
    /// </summary>
    /// <param name="credential">The server's key and certificate.</param>
    /// <param name="arguments">s_client's extra arguments.</param>
    /// <param name="lines">What s_client's standard input gets.</param>
    /// <param name="waitBetween">Whether each line after the first waits until the server took a
    /// record since the one before (a KeyUpdate brings no event, only a record).</param>
    /// <param name="flags">The server's configuration flags (client authentication's).</param>
    /// <param name="inspect">Called with the server's connection once the run ended, before it
    /// is wiped (what it kept: the client's certificates), or null.</param>
    /// <returns>What happened.</returns>
    /// <exception cref="InvalidOperationException">The server pump failed.</exception>
    /// <exception cref="TimeoutException">s_client did not end.</exception>
    internal static SClientRun SClient(TlsInteropTests.Credential credential, string arguments, string[] lines, bool waitBetween = false,
        uint flags = 0, Action<TlsServerHarness>? inspect = null)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var server = new TlsServerHarness(credential.Key, [credential.Certificate], flags: flags);
        Assert.Equal(0, server.ConfigAnswer);
        var served = new TlsInteropTests.Served();
        using var records = new SemaphoreSlim(0);

        // counted: records taken after the handshake that bring no event (a KeyUpdate), on the
        // pump's own thread, so the count never races the handshake's records
        var pump = new Thread(() =>
        {
            using Socket s = listener.AcceptSocket();
            TlsInteropTests.Serve(server, s, 1, served, r =>
            {
                if (r.Event.Kind == TlsEngine.EventNone && server.Negotiated().Progress == 2)
                {
                    records.Release();
                }
            });
        }) { IsBackground = true };
        pump.Start();

        var start = new ProcessStartInfo("openssl", $"s_client -connect 127.0.0.1:{port} -tls1_3 -brief -servername localhost {arguments}")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using Process p = Process.Start(start)!;
        Task<string> output = p.StandardOutput.ReadToEndAsync();
        Task<string> error = p.StandardError.ReadToEndAsync();
        if (waitBetween)
        {
            // a command letter is s_client's to act on once its handshake is done
            Assert.True(SpinWait.SpinUntil(() => server.Negotiated().Progress == 2, TimeSpan.FromSeconds(20)), "no handshake");
        }

        for (int i = 0; i < lines.Length; i++)
        {
            if (i > 0 && waitBetween)
            {
                // the record the line before made (a command letter s_client acts on alone)
                Assert.True(records.Wait(TimeSpan.FromSeconds(20)), $"no record after line {i}");
            }

            p.StandardInput.Write(lines[i]);
            p.StandardInput.Flush();
        }

        if (!p.WaitForExit(60000))
        {
            p.Kill();
            throw new TimeoutException("s_client did not end");
        }

        Assert.True(pump.Join(TimeSpan.FromSeconds(30)), "the server pump did not finish");
        if (served.Failure is not null)
        {
            throw new InvalidOperationException($"{served.Failure}\n{error.Result}");
        }

        inspect?.Invoke(server);
        return new SClientRun(output.Result, error.Result, server.Negotiated(), served);
    }

    /// <summary>
    /// Every group s_client has, offered alone (-groups): the engine takes its share at once (no
    /// HelloRetryRequest: the library's default list has them all), the handshake completes, the
    /// line comes back, and s_client's summary names the group the engine says it used.
    /// </summary>
    /// <param name="name">s_client's name of the group.</param>
    /// <param name="group">Its NamedGroup.</param>
    /// <param name="summary">What s_client's "Server Temp Key" line begins with.</param>
    [Theory]
    [InlineData("X25519", TlsEngine.X25519, "X25519")]
    [InlineData("X448", TlsEngine.X448, "X448")]
    [InlineData("P-256", TlsEngine.Secp256r1, "ECDH, prime256v1")]
    [InlineData("P-384", TlsEngine.Secp384r1, "ECDH, secp384r1")]
    [InlineData("P-521", TlsEngine.Secp521r1, "ECDH, secp521r1")]
    [InlineData("ffdhe2048", (ushort)0x0100, "DH, 2048 bits")]
    [InlineData("ffdhe3072", (ushort)0x0101, "DH, 3072 bits")]
    [InlineData("ffdhe4096", (ushort)0x0102, "DH, 4096 bits")]
    [InlineData("ffdhe6144", (ushort)0x0103, "DH, 6144 bits")]
    [InlineData("ffdhe8192", (ushort)0x0104, "DH, 8192 bits")]
    [Requirement("RFC9846-4.3.8.1-3", "RFC9846-4.3.8.2-5")]
    public void TakesEveryGroupOpenSslOffers(string name, ushort group, string summary)
    {
        Platform.RequireLinuxX64();
        SClientRun run = SClient(Make("p256"), $"-groups {name}", ["hello from s_client\n"]);
        Assert.Contains("hello from s_client", run.Out);
        Assert.Contains("Protocol version: TLSv1.3", run.Err);
        Assert.Contains($"Server Temp Key: {summary}", run.Err);
        Assert.Equal(2, run.Negotiated.Progress);
        Assert.Equal(group, run.Negotiated.Group);
    }

    /// <summary>
    /// Every signature scheme a server key makes, s_client offering it alone (-sigalgs), with a
    /// key openssl made of the kind it needs: RSA (rsa_pss_rsae_sha256/384/512), RSASSA-PSS
    /// (rsa_pss_pss_*: the key's own PSS), ECDSA on P-256, P-384 and P-521, Ed25519, Ed448.
    /// OpenSSL verifies each CertificateVerify; the engine says it signed with the scheme forced.
    /// </summary>
    /// <param name="kind">The key's kind.</param>
    /// <param name="sigalg">s_client's name of the scheme.</param>
    /// <param name="scheme">Its SignatureScheme.</param>
    [Theory]
    [InlineData("rsa", "rsa_pss_rsae_sha256", (ushort)0x0804)]
    [InlineData("rsa", "rsa_pss_rsae_sha384", (ushort)0x0805)]
    [InlineData("rsa", "rsa_pss_rsae_sha512", (ushort)0x0806)]
    [InlineData("rsa-pss", "rsa_pss_pss_sha256", (ushort)0x0809)]
    [InlineData("rsa-pss", "rsa_pss_pss_sha384", (ushort)0x080A)]
    [InlineData("rsa-pss", "rsa_pss_pss_sha512", (ushort)0x080B)]
    [InlineData("p256", "ecdsa_secp256r1_sha256", (ushort)0x0403)]
    [InlineData("p384", "ecdsa_secp384r1_sha384", (ushort)0x0503)]
    [InlineData("p521", "ecdsa_secp521r1_sha512", (ushort)0x0603)]
    [InlineData("ed25519", "ed25519", (ushort)0x0807)]
    [InlineData("ed448", "ed448", (ushort)0x0808)]
    [Requirement("RFC9846-4.5.2-14", "RFC9846-4.5.2-16#1")]
    public void SignsWithEverySchemeOpenSslOffers(string kind, string sigalg, ushort scheme)
    {
        Platform.RequireLinuxX64();
        SClientRun run = SClient(Make(kind), $"-sigalgs {sigalg}", ["signed by the engine\n"]);
        Assert.Contains("signed by the engine", run.Out);
        Assert.Contains("Protocol version: TLSv1.3", run.Err);
        Assert.Equal(2, run.Negotiated.Progress);
        Assert.Equal(scheme, run.Negotiated.Scheme);
    }

    /// <summary>
    /// s_client's KeyUpdate with update_requested ("K" on its input, -msg showing the messages):
    /// the engine moves to the client's next key (the line after it opens), owes its own
    /// KeyUpdate and sends it, update_not_requested, before its echo (RFC 9846 4.7.3), which
    /// s_client then opens under the server's next key.
    /// </summary>
    [Fact]
    [Requirement("RFC9846-4.7.3-1#3", "RFC9846-4.7.3-4#1", "RFC9846-4.7.3-7#1")]
    public void AnswersOpenSslsKeyUpdate()
    {
        Platform.RequireLinuxX64();
        SClientRun run = SClient(Make("p256"), "-msg", ["K\n", "after the update\n"], waitBetween: true);
        Assert.Contains("after the update", run.Out);
        // -msg: our KeyUpdate received (<<<) after s_client's own (>>>)
        Assert.Contains(">>> TLS 1.3, Handshake [length 0005], KeyUpdate", run.Out);
        Assert.Contains("<<< TLS 1.3, Handshake [length 0005], KeyUpdate", run.Out);
        Assert.Equal(1, run.Served.Echoes);
    }
}
