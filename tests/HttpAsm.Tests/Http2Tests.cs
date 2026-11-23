using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// HTTP/2 end to end: the server speaks h2c with prior knowledge to a connection that opens
/// with the client preface (RFC 9113 3.3). HttpClient shows interoperation and multiplexing;
/// h2spec, the protocol conformance suite, runs its 146 cases when it is installed.
/// </summary>
public sealed partial class Http2Tests
{
    /// <summary>Lets HttpClient speak HTTP/2 without TLS (prior knowledge).</summary>
    static Http2Tests() => AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

    /// <summary>
    /// GET and POST over HTTP/2: the handler sees the same request view as with HTTP/1.1
    /// (version 20, :path as the target, :authority), and the answer comes back with its
    /// fields lower-cased, a date and a content-length.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    [Requirement("RFC9113-3.3-3")]
    public async Task ServesHttpClientOverH2c()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        Exchange? seen = null;
        using var server = new TestServer(x =>
        {
            seen = x;
            x.Respond(200, x.Method + " " + x.Target + " " + Encoding.UTF8.GetString(x.Body), ("Content-Type", "text/plain"), ("X-Version", x.Version.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        });
        using var client = NewClient();

        using var get = await client.GetAsync(new Uri(server.Address, "a/b?c=d"), ct);
        Assert.Equal(HttpVersion.Version20, get.Version);
        Assert.Equal("GET /a/b?c=d ", await get.Content.ReadAsStringAsync(ct));
        Assert.Equal("20", get.Headers.GetValues("x-version").Single());
        Assert.Equal("text/plain", get.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(get.Headers.Date);
        Assert.Equal($"127.0.0.1:{server.Port}", seen?.Authority);

        using var post = await client.PostAsync(server.Address, new StringContent("hello h2"), ct);
        Assert.Equal("POST / hello h2", await post.Content.ReadAsStringAsync(ct));
    }

    /// <summary>
    /// Many requests at once share one connection as streams; every answer comes back on its
    /// own stream, even though every other one is answered later from the thread pool.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    [Requirement("RFC9113-5.1.1-1#1")]
    public async Task MultiplexesStreamsAndDeferredAnswers()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x =>
        {
            if (x.Target.EndsWith('0') || x.Target.EndsWith('2') || x.Target.EndsWith('4'))
            {
                x.Respond(200, x.Target);
                return;
            }

            x.Defer();
            _ = Task.Run(async () =>
            {
                await Task.Delay(Random.Shared.Next(1, 30), ct);
                x.Respond(200, x.Target);
            }, ct);
        });
        using var client = NewClient();

        string[] answers = await Task.WhenAll(Enumerable.Range(0, 300)
            .Select(i => client.GetStringAsync(new Uri(server.Address, FormattableString.Invariant($"r{i}")), ct)));

        for (int i = 0; i < answers.Length; i++)
        {
            Assert.Equal(FormattableString.Invariant($"/r{i}"), answers[i]);
        }
    }

    /// <summary>
    /// Large bodies both ways cross the flow-control windows: an 8 MiB answer is sent as the
    /// client's WINDOW_UPDATEs allow, and a 900 KB upload as this side's do.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    [Requirement("RFC9113-6.9-11", "RFC9113-6.9.1-2#1")]
    public async Task FlowControlsLargeBodies()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        byte[] big = new byte[8 << 20];
        new Random(8).NextBytes(big);
        using var server = new TestServer(x => x.Respond(200, x.Method == "GET" ? big : x.Body), maxBody: 1 << 20);
        using var client = NewClient();

        byte[] down = await client.GetByteArrayAsync(server.Address, ct);
        Assert.True(big.AsSpan().SequenceEqual(down));

        byte[] upload = big[..900_000];
        using var response = await client.PostAsync(server.Address, new ByteArrayContent(upload), ct);
        byte[] echoed = await response.Content.ReadAsByteArrayAsync(ct);
        Assert.True(upload.AsSpan().SequenceEqual(echoed));
    }

    /// <summary>
    /// h2spec 2.6.0, every case (generic, RFC 9113 and HPACK): the server must pass all 146. It
    /// runs when HTTPASM_H2SPEC names the binary (tests/run-linux.sh sets it after fetching the
    /// pinned release); HTTPASM_REQUIRE_H2SPEC=1 makes a missing binary a failure.
    /// </summary>
    /// <returns>The test.</returns>
    /// <exception cref="InvalidOperationException">The h2spec process could not be started.</exception>
    [Fact]
    public async Task PassesH2spec()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        string? h2spec = Environment.GetEnvironmentVariable("HTTPASM_H2SPEC");
        if (string.IsNullOrEmpty(h2spec) || !File.Exists(h2spec))
        {
            const string reason = "h2spec is not installed (HTTPASM_H2SPEC); tests/run-linux.sh fetches it.";
            if (Environment.GetEnvironmentVariable("HTTPASM_REQUIRE_H2SPEC") == "1")
            {
                Assert.Fail(reason);
            }

            Assert.Skip(reason);
        }

        using var server = new TestServer(x => x.Respond(200, "Hello, World!\n", ("Content-Type", "text/plain")), maxBody: 1 << 20);
        var start = new ProcessStartInfo(h2spec, ["-h", "127.0.0.1", "-p", server.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), "-o", "2"])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(start) ?? throw new InvalidOperationException("h2spec did not start.");
        Task<string> output = process.StandardOutput.ReadToEndAsync(ct);
        Task<string> errors = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromMinutes(3), ct);
        string text = await output + await errors;

        Match summary = Summary().Match(text);
        Assert.True(summary.Success, "No h2spec summary in:\n" + text);
        Assert.True(summary.Groups[1].Value == "146" && summary.Groups[2].Value == "146", Failures(text));
    }

    /// <summary>h2spec's last line: "146 tests, 146 passed, 0 skipped, 0 failed".</summary>
    [GeneratedRegex(@"(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed")]
    private static partial Regex Summary();

    /// <summary>The failed cases of an h2spec run, for the assertion's message.</summary>
    /// <param name="text">h2spec's output.</param>
    /// <returns>The "Failures:" section, or the whole output.</returns>
    private static string Failures(string text)
    {
        int at = text.IndexOf("Failures:", StringComparison.Ordinal);
        return at < 0 ? text : text[at..];
    }

    /// <summary>An HttpClient that speaks HTTP/2 only, without TLS (prior knowledge).</summary>
    /// <returns>The client.</returns>
    private static HttpClient NewClient() =>
        new(new SocketsHttpHandler { EnableMultipleHttp2Connections = false })
        {
            Timeout = TimeSpan.FromSeconds(20),
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
}
