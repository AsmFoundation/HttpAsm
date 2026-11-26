using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// The Linux driver end to end: a real server (libhttpasm.so's workers, epoll, sockets) in this
/// process, a handler in C#, and clients on loopback. HttpClient shows that a mainstream client
/// interoperates; <see cref="RawConnection"/> sends what no polite client would (pipelined
/// bursts, smuggling attempts, a byte at a time, half-closes) and checks the answers octet by
/// octet.
/// </summary>
public sealed class ServerTests
{
    /// <summary>The .NET copy of httpasm_server_options has the library's size.</summary>
    [Fact]
    public void OptionsMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(64, Unsafe.SizeOf<ServerOptions>());
        Assert.Equal((uint)Unsafe.SizeOf<ServerOptions>(), Native.StructSize(7));
    }

    /// <summary>A server without a handler is refused at creation, with -EINVAL.</summary>
    [Fact]
    public unsafe void CreateRefusesAMissingHandler()
    {
        Platform.RequireLinuxX64();
        var options = new ServerOptions();
        int error = 0;
        Assert.Equal(0, Native.ServerCreate(&options, &error));
        Assert.Equal(-22, error);
    }

    /// <summary>
    /// HttpClient's GET is answered with the handler's status, fields and body, plus the Date the
    /// library adds (an origin server with a clock must) and a Content-Length.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    [Requirement("RFC9110-6.6.1-6#1", "RFC9110-6.6.1-5", "RFC9110-8.6-9")]
    public async Task AnswersHttpClient()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x => x.Respond(200, "hello " + x.Target, ("Content-Type", "text/plain")));
        using var client = NewClient();

        using var response = await client.GetAsync(new Uri(server.Address, "path?q=1"), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("hello /path?q=1", await response.Content.ReadAsStringAsync(ct));
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(15, response.Content.Headers.ContentLength);
        DateTimeOffset date = Assert.NotNull(response.Headers.Date);
        Assert.InRange(date, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    /// <summary>
    /// Bodies reach the handler whole and decoded, framed by Content-Length, by chunked, and
    /// after an Expect: 100-continue handshake. 300 KB is far past the 16 KiB a connection's
    /// input starts with: the buffer grows (and may move) under a parsed request, whose pointers
    /// must follow it.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    [Requirement("RFC9112-6.1-4#1", "RFC9112-7.1-4", "RFC9110-10.1.1-14")]
    public async Task ReceivesBodiesWhole()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x => x.Respond(200, x.Body,
            ("X-Framing", (x.Flags & Abi.RequestChunked) != 0 ? "chunked" : "length")));
        using var client = NewClient();
        byte[] data = RandomBytes(300_000);

        using var byLength = await client.PostAsync(server.Address, new ByteArrayContent(data), ct);
        Assert.Equal("length", byLength.Headers.GetValues("X-Framing").Single());
        Assert.Equal(data, await byLength.Content.ReadAsByteArrayAsync(ct));

        using var chunkedRequest = new HttpRequestMessage(HttpMethod.Post, server.Address) { Content = new StreamContent(new MemoryStream(data)) };
        chunkedRequest.Headers.TransferEncodingChunked = true;
        using var chunked = await client.SendAsync(chunkedRequest, ct);
        Assert.Equal("chunked", chunked.Headers.GetValues("X-Framing").Single());
        Assert.Equal(data, await chunked.Content.ReadAsByteArrayAsync(ct));

        using var expectRequest = new HttpRequestMessage(HttpMethod.Put, server.Address) { Content = new ByteArrayContent(data) };
        expectRequest.Headers.ExpectContinue = true;
        using var expect = await client.SendAsync(expectRequest, ct);
        Assert.Equal(data, await expect.Content.ReadAsByteArrayAsync(ct));
    }

    /// <summary>
    /// 100 Continue goes out as soon as the head of a request expecting it is read, before any
    /// of the body (the client may be waiting for it), and the final answer follows the body.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-10.1.1-14", "RFC9110-10.1.1-16", "RFC9110-10.1.1-13.3")]
    public void SendsContinueBeforeTheBody()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Body));
        using var c = new RawConnection(server.Port);

        c.Send("POST /upload HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        RawResponse interim = c.ReadResponse();
        Assert.Equal(100, interim.Status);
        Assert.Empty(interim.Fields);
        c.Send("hello");
        RawResponse final = c.ReadResponse();

        Assert.Equal(200, final.Status);
        Assert.Equal("hello", final.Text);
    }

    /// <summary>When the body came with the head, 100 Continue has no use and is left out.</summary>
    [Fact]
    [Requirement("RFC9110-10.1.1-13.2")]
    public void OmitsContinueWhenTheBodyIsAlreadyHere()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Body));
        using var c = new RawConnection(server.Port);

        c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello");
        RawResponse final = c.ReadResponse();

        Assert.Equal(200, final.Status);
        Assert.Equal("hello", final.Text);
    }

    /// <summary>
    /// An HTTP/1.0 request's 100-continue is ignored: no 1xx goes to an HTTP/1.0 client, which
    /// would read it as the final answer. The server simply waits for the body.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-10.1.1-13.1", "RFC9110-15.2-1")]
    public void IgnoresContinueFromHttp10()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Body));
        using var c = new RawConnection(server.Port);

        c.Send("POST / HTTP/1.0\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        Assert.True(c.QuietFor(300));
        c.Send("hello");
        RawResponse final = c.ReadResponse();

        Assert.Equal(200, final.Status);
        Assert.Equal("hello", final.Text);
        Assert.True(c.ServerClosed());      // HTTP/1.0 without keep-alive does not persist
    }

    /// <summary>
    /// Pipelined requests are answered in the order they came, even when the handler answers
    /// every other one later from the thread pool, after a random delay: later answers wait for
    /// earlier ones. The server supports persistent connections (all of them on one), so it
    /// never needs to close every answer as a server without that support must.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.3.2-1#2", "RFC9112-9.3.2-1#3", "RFC9112-9.3-1", "RFC9112-9.3-5")]
    public void AnswersPipelinedRequestsInOrder()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x =>
        {
            int n = int.Parse(x.Target.AsSpan(1), System.Globalization.CultureInfo.InvariantCulture);
            if (n % 2 == 0)
            {
                x.Respond(200, x.Target);
                return;
            }

            x.Defer();
            _ = Task.Run(async () =>
            {
                await Task.Delay(Random.Shared.Next(1, 20), ct);
                x.Respond(200, x.Target);
            }, ct);
        });
        using var c = new RawConnection(server.Port);
        var burst = new StringBuilder();
        for (int i = 0; i < 40; i++)
        {
            burst.Append(CultureInfoInvariant($"GET /{i} HTTP/1.1\r\nHost: t\r\n\r\n"));
        }

        c.Send(burst.ToString());

        for (int i = 0; i < 40; i++)
        {
            Assert.Equal(CultureInfoInvariant($"/{i}"), c.ReadResponse().Text);
        }

        Assert.True(c.QuietFor(100));       // and the connection stays open
    }

    /// <summary>
    /// After a request with Connection: close the server answers it with Connection: close,
    /// closes, and never runs a request pipelined behind it: a server that sends close starts
    /// the closing itself and processes nothing more on the connection.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.6-6#1", "RFC9112-9.6-6#2", "RFC9112-9.6-6#3", "RFC9112-9.6-1", "RFC9112-9.6-7#1", "RFC9112-9.6-7#2")]
    public void ClosesAfterAConnectionCloseRequest()
    {
        Platform.RequireLinuxX64();
        int handled = 0;
        using var server = new TestServer(x =>
        {
            Interlocked.Increment(ref handled);
            x.Respond(200, "one");
        });
        using var c = new RawConnection(server.Port);

        c.Send("GET /1 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\nGET /2 HTTP/1.1\r\nHost: t\r\n\r\n");
        RawResponse response = c.ReadResponse();

        Assert.Equal("one", response.Text);
        Assert.Equal("close", response.Field("Connection"));
        Assert.True(c.ServerClosed());
        Assert.Equal(1, handled);
    }

    /// <summary>
    /// HTTP/1.0 persists only with keep-alive (answered with Connection: keep-alive); without
    /// it the connection closes after the answer. Either way the answer is HTTP/1.1, the highest
    /// version the server conforms to within the request's major version (RawConnection accepts
    /// no other status-line): the server never downgrades its responses to HTTP/1.0.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.3-1", "RFC9110-6.2-7#1", "RFC9110-6.2-7#2", "RFC9112-2.3-6#1", "RFC9112-2.3-6#2")]
    public void PersistsHttp10OnlyWithKeepAlive()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "ok"));

        using (var c = new RawConnection(server.Port))
        {
            c.Send("GET / HTTP/1.0\r\n\r\n");
            RawResponse response = c.ReadResponse();
            Assert.Equal("close", response.Field("Connection"));
            Assert.True(c.ServerClosed());
        }

        using (var c = new RawConnection(server.Port))
        {
            c.Send("GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
            Assert.Equal("keep-alive", c.ReadResponse().Field("Connection"));
            c.Send("GET /b HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
            Assert.Equal("ok", c.ReadResponse().Text);
        }
    }

    /// <summary>
    /// Requests whose framing or head is invalid are answered with the status the rule names,
    /// with Connection: close, and the connection closes: nothing reaches the handler, neither
    /// the refused request nor a request smuggled behind it.
    /// </summary>
    /// <param name="request">The octets sent.</param>
    /// <param name="status">The status expected.</param>
    /// <remarks>
    /// The cases, in order: Content-Length with Transfer-Encoding in either order (the classic
    /// request-smuggling setup, with a request hidden behind the body); two different lengths;
    /// a length that is no plain number; chunked not the last coding (the length cannot be
    /// known); Transfer-Encoding in HTTP/1.0 (faulty framing); bare LF line ends, whitespace
    /// before the colon and obs-fold (where parsers disagree); Host missing, and Host twice; a
    /// chunk-size with junk after it; a coding not implemented (501), an expectation not met
    /// (417), and a version not supported (505).
    /// </remarks>
    [Theory]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: t\r\n\r\n", 400)]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: t\r\n\r\n", 400)]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", 400)]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: +5\r\n\r\nhello", 400)]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n", 400)]
    [InlineData("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400)]
    [InlineData("GET / HTTP/1.1\nHost: t\n\n", 400)]
    [InlineData("GET / HTTP/1.1\r\nHost : t\r\n\r\n", 400)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nX: a\r\n b\r\n\r\n", 400)]
    [InlineData("GET / HTTP/1.1\r\n\r\n", 400)]
    [InlineData("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400)]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5 x\r\nhello\r\n0\r\n\r\n", 400)]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 501)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nExpect: teapot\r\n\r\n", 417)]
    [InlineData("GET / HTTP/2.0\r\nHost: t\r\n\r\n", 505)]
    [Requirement("RFC9112-6.1-15#1", "RFC9112-6.1-15#2", "RFC9112-6.3-2.5#2", "RFC9112-6.3-2.4.3", "RFC9112-6.1-16",
        "RFC9112-2.2-3", "RFC9112-3.2-6", "RFC9112-6.1-11", "RFC9110-10.1.1-5", "RFC9112-3.2-4#1", "RFC9112-2.2-9")]
    public void RefusesBadRequestsAndCloses(string request, int status)
    {
        Platform.RequireLinuxX64();
        int handled = 0;
        using var server = new TestServer(x =>
        {
            Interlocked.Increment(ref handled);
            x.Respond(200);
        });
        using var c = new RawConnection(server.Port);

        c.Send(request);
        RawResponse response = c.ReadResponse();

        Assert.Equal(status, response.Status);
        Assert.Equal("close", response.Field("Connection"));
        Assert.True(c.ServerClosed());
        Assert.Equal(0, handled);
    }

    /// <summary>
    /// A first message that is no HTTP at all (no HTTP-version on its line: an HTTP/2 client's
    /// broken preface, another protocol) is not answered in HTTP/1.1: the connection closes,
    /// with not one octet sent. A broken line that does carry an HTTP-version is answered 400.
    /// </summary>
    /// <param name="request">The octets sent.</param>
    /// <param name="answered">Whether a 400 is expected before the close.</param>
    [Theory]
    [InlineData("INVALID CONNECTION PREFACE\r\n\r\n", false)]
    [InlineData("\r\nSSH-2.0-OpenSSH_9.6\r\n\r\n", false)]
    [InlineData("GET /a b HTTP/1.1\r\nHost: t\r\n\r\n", true)]
    [InlineData("\u0016\u0003\u0001\u0002\u0000\u0001\u0000\u0001ü\u0003\u0003\r\n\r\n", false)]   // binary: a TLS ClientHello's start
    [Requirement("RFC9112-2.2-9")]
    public void ClosesSilentlyOnWhatIsNotHttp(string request, bool answered)
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200));
        using var c = new RawConnection(server.Port);

        c.Send(request);

        if (answered)
        {
            Assert.Equal(400, c.ReadResponse().Status);
        }

        Assert.True(c.ServerClosed());
    }

    /// <summary>
    /// A body past max_body is refused with 413 and the connection closes (its unread body
    /// would otherwise be taken for the next request): a declared length at once, before any
    /// body octet is read, saying Connection: close so the client knows the rest will not be
    /// read; a chunked body as soon as the decoded octets pass the limit. A body of exactly the
    /// limit is accepted.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-15.5.14-1#2", "RFC9112-9.3-7#1", "RFC9110-15.5.14-1#1", "RFC9110-10.1.1-13.4")]
    public void RefusesBodiesPastTheLimit()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Body), maxBody: 1000);

        using (var c = new RawConnection(server.Port))
        {
            c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1001\r\n\r\n");
            RawResponse response = c.ReadResponse();
            Assert.Equal(413, response.Status);
            Assert.Equal("close", response.Field("Connection"));
            Assert.True(c.ServerClosed());
        }

        using (var c = new RawConnection(server.Port))
        {
            c.Send("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n3e9\r\n" + new string('a', 1001) + "\r\n0\r\n\r\n");
            Assert.Equal(413, c.ReadResponse().Status);
            Assert.True(c.ServerClosed());
        }

        using (var c = new RawConnection(server.Port))
        {
            c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1000\r\n\r\n" + new string('b', 1000));
            Assert.Equal(1000, c.ReadResponse().Body.Length);
        }
    }

    /// <summary>
    /// The heads' limits from the server's options apply: a target past max_target is 414, more
    /// fields than max_fields or a head past max_head is 431 (fields larger than the server will
    /// process get a 4xx, as the semantics require). Parsing is defensive this way: no element
    /// is trusted to fit, and none is buffered past its bound.
    /// </summary>
    /// <param name="request">The octets sent.</param>
    /// <param name="status">The status expected.</param>
    [Theory]
    [InlineData("GET /0123456789012345678901234567890123456789012345678901234567890123456789 HTTP/1.1\r\nHost: t\r\n\r\n", 414)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n", 431)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nX: 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n\r\n", 431)]
    [Requirement("RFC9110-5.4-2", "RFC9110-2.3-1")]
    public void AppliesTheConfiguredLimits(string request, int status)
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200), limits: new H1Limits { MaxHead = 200, MaxTarget = 64, MaxFields = 4 });
        using var c = new RawConnection(server.Port);

        c.Send(request);

        Assert.Equal(status, c.ReadResponse().Status);
        Assert.True(c.ServerClosed());
    }

    /// <summary>
    /// max_fields bounds a request's header and trailer fields together: trailers take the
    /// records the header left. With the header at the limit, a trailer section that holds a
    /// field is 431 and an empty one is fine; below it, trailers fit up to the limit and one
    /// more is 431. The first row once corrupted the server's heap: with no record left the
    /// trailer parser got the limit 1 and the array's end as its destination, and wrote the
    /// record 32 octets past the array's allocation ("free(): invalid next size", an abort;
    /// found walking the coverage gate's unrun markers, 2026-11-26). The default limit (128)
    /// is held the same way.
    /// </summary>
    /// <param name="headerFields">Header fields beside Host and Transfer-Encoding.</param>
    /// <param name="trailers">Trailer fields.</param>
    /// <param name="defaultLimit">The default max_fields (128) instead of 4.</param>
    /// <param name="status">The status expected.</param>
    [Theory]
    [InlineData(2, 1, false, 431)]
    [InlineData(2, 0, false, 200)]
    [InlineData(1, 1, false, 200)]
    [InlineData(1, 2, false, 431)]
    [InlineData(0, 2, false, 200)]
    [InlineData(126, 1, true, 431)]
    [InlineData(126, 0, true, 200)]
    [InlineData(125, 1, true, 200)]
    [Requirement("RFC9110-5.4-2", "RFC9112-7.1.2-2")]
    public void BoundsHeaderAndTrailerFieldsTogether(int headerFields, int trailers, bool defaultLimit, int status)
    {
        Platform.RequireLinuxX64();
        int seen = -1;
        using var server = new TestServer(x =>
        {
            seen = x.Trailers.Count;
            x.Respond(200);
        }, limits: defaultLimit ? default : new H1Limits { MaxFields = 4 });
        using var c = new RawConnection(server.Port);

        string header = string.Concat(Enumerable.Range(0, headerFields).Select(i => $"X-H{i}: {i}\r\n"));
        string trailer = string.Concat(Enumerable.Range(0, trailers).Select(i => $"X-T{i}: {i}\r\n"));
        c.Send($"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n{header}\r\n3\r\nabc\r\n0\r\n{trailer}\r\n");

        Assert.Equal(status, c.ReadResponse().Status);
        Assert.Equal(status == 200 ? trailers : -1, seen);
    }

    /// <summary>
    /// HEAD is answered with GET's fields (Content-Length of the body it would have had) and no
    /// body: the next response on the connection starts right after the head. GET and HEAD,
    /// the two methods every general-purpose server must support, both work on any handler.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-9.3.2-1", "RFC9110-9.3.2-2#1", "RFC9110-8.6-6#1", "RFC9110-8.6-6#2", "RFC9110-9.1-9#1")]
    public void AnswersHeadWithoutTheBody()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "twelve bytes"));
        using var c = new RawConnection(server.Port);

        c.Send("HEAD / HTTP/1.1\r\nHost: t\r\n\r\nGET / HTTP/1.1\r\nHost: t\r\n\r\n");
        RawResponse head = c.ReadResponse(head: true);
        RawResponse get = c.ReadResponse();

        Assert.Equal("12", head.Field("Content-Length"));
        Assert.Equal("twelve bytes", get.Text);
    }

    /// <summary>
    /// CONNECT reaches the handler, but a 2xx answer, which would turn the connection into a
    /// tunnel this server cannot carry yet, is refused (-HTTPASM_ERROR_STATUS, nothing sent);
    /// the handler answers otherwise (501), and the connection goes on. The writer itself never
    /// frames a 2xx to CONNECT (H1MessageTests.LeavesOutImpossibleBodies); this keeps the server
    /// from sending one at all.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-9.3.6-6")]
    public void RefusesToStartATunnel()
    {
        Platform.RequireLinuxX64();
        int refused = 0;
        using var server = new TestServer(x =>
        {
            if (x.Method == "CONNECT")
            {
                refused = x.Respond(200);
                x.Respond(501);
                return;
            }

            x.Respond(200, "after");
        });
        using var c = new RawConnection(server.Port);

        c.Send("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        Assert.Equal(501, c.ReadResponse().Status);
        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");

        Assert.Equal("after", c.ReadResponse().Text);
        Assert.Equal(-25, refused);                                 // -HTTPASM_ERROR_STATUS
    }

    /// <summary>
    /// A request inviting an upgrade (Upgrade, with the "upgrade" connection option) is
    /// answered in HTTP/1.1 as if the invitation were not there: ignoring it is the server's
    /// choice, and the only one for an HTTP/1.0 request, whose Upgrade must be ignored. No 101
    /// goes out, and the connection persists.
    /// </summary>
    /// <param name="version">The request's HTTP version.</param>
    [Theory]
    [InlineData("HTTP/1.1")]
    [InlineData("HTTP/1.0")]
    [Requirement("RFC9110-7.8-2#2", "RFC9110-7.8-14#2")]
    public void IgnoresUpgrades(string version)
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "plain"));
        using var c = new RawConnection(server.Port);
        string keepAlive = version == "HTTP/1.0" ? "keep-alive, " : "";

        c.Send($"GET / {version}\r\nHost: t\r\nUpgrade: websocket\r\nConnection: {keepAlive}Upgrade\r\n\r\n");
        RawResponse response = c.ReadResponse();
        c.Send($"GET / {version}\r\nHost: t\r\nConnection: keep-alive\r\n\r\n");

        Assert.Equal((200, "plain"), (response.Status, response.Text));
        Assert.Equal("plain", c.ReadResponse().Text);
    }

    /// <summary>
    /// Every final answer carries Date in IMF-fixdate, the one HTTP-date format a sender may
    /// generate (fixed length, GMT, single spaces), close to now; a 5xx as well (the server has
    /// a clock, and dating a 5xx is allowed).
    /// </summary>
    [Fact]
    [Requirement("RFC9110-5.6.7-2", "RFC9110-5.6.7-11", "RFC9110-5.6.7-7#2", "RFC9110-5.6.7-17", "RFC9110-6.6.1-2", "RFC9110-6.6.1-6#2")]
    public void DatesItsAnswersInImfFixdate()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(x.Target == "/fail" ? 503 : 200, "ok"));
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\nGET /fail HTTP/1.1\r\nHost: t\r\n\r\n");
        RawResponse[] answers = [c.ReadResponse(), c.ReadResponse()];

        Assert.Equal(503, answers[1].Status);
        foreach (RawResponse answer in answers)
        {
            string date = Assert.IsType<string>(answer.Field("Date"));
            Assert.Matches(@"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$", date);
            DateTimeOffset when = DateTimeOffset.ParseExact(date, "r", System.Globalization.CultureInfo.InvariantCulture);
            Assert.InRange(when, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        }
    }

    /// <summary>
    /// A request-target of 8000 octets, the length every sender and recipient should support at
    /// least, is read whole and reaches the handler (the default limit is 8 KiB).
    /// </summary>
    [Fact]
    [Requirement("RFC9110-4.1-5")]
    public void ReadsLongTargets()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Target.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        using var c = new RawConnection(server.Port);

        c.Send($"GET /{new string('t', 7999)} HTTP/1.1\r\nHost: t\r\n\r\n");

        Assert.Equal("8000", c.ReadResponse().Text);
    }

    /// <summary>
    /// The server's own refusals explain themselves in one line of text/plain: the reason phrase
    /// (a 4xx, a 5xx), and for 505 the versions this server does speak. An answer to HEAD carries
    /// no content, a refusal included, but the same fields as GET's (Content-Type too).
    /// </summary>
    /// <param name="request">The octets sent.</param>
    /// <param name="status">The refusal expected.</param>
    /// <param name="text">The explanation expected ("" for none).</param>
    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nBad Name: x\r\n\r\n", 400, "Bad Request")]
    [InlineData("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501, "Not Implemented")]
    [InlineData("GET / HTTP/2.0\r\nHost: t\r\n\r\n", 505, "HTTP Version Not Supported: this server speaks HTTP/1.1, and HTTP/2 with prior knowledge\n")]
    [InlineData("HEAD / HTTP/1.1\r\nHost: t\r\nBad Name: x\r\n\r\n", 400, "")]
    [Requirement("RFC9110-15.5-1#1", "RFC9110-15.6-1#1", "RFC9110-15.6.6-1", "RFC9110-8.3-5#1")]
    public void ExplainsItsRefusals(string request, int status, string text)
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200));
        using var c = new RawConnection(server.Port);

        c.Send(request);
        RawResponse response = c.ReadResponse(head: request.StartsWith("HEAD", StringComparison.Ordinal));

        Assert.Equal((status, text), (response.Status, response.Text));
        Assert.Equal("text/plain", response.Field("Content-Type"));
    }

    /// <summary>
    /// The workers wait and do their I/O through epoll by default, and through io_uring when
    /// the options ask for it (HTTPASM_SERVER_URING) and the kernel allows it; both serve, and a
    /// server stopped and started again comes back on the same backend. Runs that know io_uring
    /// is there (WSL, CI) set HTTPASM_REQUIRE_URING=1, so a silent fall back to epoll fails
    /// them, saying why it may have happened (the kernel and RLIMIT_MEMLOCK, which Linux 6.14
    /// to 7.2 charge rings to unless they carry upstream commit b59cabf9b4ac). In an io_uring run (HTTPASM_TEST_IO=uring) every server asks,
    /// the plain one too.
    /// </summary>
    /// <remarks>
    /// Where io_uring is not required, the asking server may also come up on
    /// <see cref="ServerIo.Epoll"/> (Docker's seccomp refuses every ring) or
    /// <see cref="ServerIo.Mixed"/> (the kernel refused some); RingBudgetTests covers the refusal
    /// itself.
    /// </remarks>
    [Fact]
    public void WaitsWithEpollUnlessAskedForIoUring()
    {
        Platform.RequireLinuxX64();
        bool required = TestServer.RequireUring;
        using var plain = new TestServer(x => x.Respond(200, "served"));
        using var asking = new TestServer(x => x.Respond(200, "served"), flags: ServerIo.AskUring);

        uint io = asking.Io;
        if (required)
        {
            Assert.True(io == ServerIo.Uring, $"HTTPASM_REQUIRE_URING=1, but httpasm_server_io says {io} ({Platform.IoUringBudget()})");
        }
        else
        {
            Assert.Contains(io, new[] { ServerIo.Uring, ServerIo.Epoll, ServerIo.Mixed });
        }

        // epoll unless asked; in an io_uring run the plain server asks too, and gets the same.
        Assert.Equal(TestServer.UringRun ? io : ServerIo.Epoll, plain.Io);
        foreach (TestServer s in new[] { plain, asking })
        {
            using var c = new RawConnection(s.Port);
            c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
            Assert.Equal("served", c.ReadResponse().Text);
        }

        asking.Stop();
        Assert.Equal(ServerIo.None, asking.Io);
        Assert.Equal(0, asking.Start());
        Assert.Equal(io, asking.Io);
        using var again = new RawConnection(asking.Port);
        again.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        Assert.Equal("served", again.ReadResponse().Text);
    }

    /// <summary>
    /// A deferred exchange answered from another thread while its handler is still running (so
    /// the answer is posted before the worker even learns of the deferral) is delivered, and
    /// the connection carries on.
    /// </summary>
    [Fact]
    public void DeliversAnAnswerPostedBeforeTheHandlerReturns()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x =>
        {
            x.Defer();
            var thread = new Thread(() => x.Respond(200, "early " + x.Target));
            thread.Start();
            thread.Join();
        });
        using var c = new RawConnection(server.Port);

        for (int i = 0; i < 3; i++)
        {
            c.Send(CultureInfoInvariant($"GET /{i} HTTP/1.1\r\nHost: t\r\n\r\n"));
            Assert.Equal(CultureInfoInvariant($"early /{i}"), c.ReadResponse().Text);
        }
    }

    /// <summary>
    /// A deferred exchange can be answered only once, and only after it was deferred: a second
    /// answer is refused with -EINVAL and sends nothing.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    public async Task AnswersADeferredExchangeOnce()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        var results = new TaskCompletionSource<(int, int, int)>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var server = new TestServer(x =>
        {
            int deferred = x.Defer();
            _ = Task.Run(() =>
            {
                int first = x.Respond(200, "once");
                int second = x.Respond(200, "twice");
                results.SetResult((deferred, first, second));
            }, ct);
        });
        using var client = NewClient();

        Assert.Equal("once", await client.GetStringAsync(server.Address, ct));
        Assert.Equal((0, 0, -22), await results.Task.WaitAsync(TimeSpan.FromSeconds(10), ct));
    }

    /// <summary>A handler that returns without answering gets 500 for it, and the connection closes.</summary>
    [Fact]
    public void AnswersAHandlerThatDidNotAnswerWith500()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(_ => { });
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        RawResponse response = c.ReadResponse();

        Assert.Equal(500, response.Status);
        Assert.Equal("close", response.Field("Connection"));
        Assert.True(c.ServerClosed());
    }

    /// <summary>
    /// An answer the writer refuses (a field name that is no token, a framing field the library
    /// owns) sends nothing and returns the rule's error: the handler can answer again, properly.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-2.2-5#1")]
    public void LetsARefusedAnswerBeGivenAgain()
    {
        Platform.RequireLinuxX64();
        int badName = 0;
        int framing = 0;
        using var server = new TestServer(x =>
        {
            badName = x.Respond(200, "", ("Bad Name", "v"));
            framing = x.Respond(200, "", ("Content-Length", "99"));
            x.Respond(200, "fine");
        });
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");

        Assert.Equal("fine", c.ReadResponse().Text);
        Assert.Equal(-(int)ParseError.FieldName, badName);
        Assert.Equal(-(int)ParseError.FramingField, framing);
    }

    /// <summary>
    /// A chunked body arrives decoded (extensions dropped), and its trailer fields reach the
    /// handler apart from the header fields, whether the request comes whole or a few octets at
    /// a time (every state of the decoder is resumed across reads).
    /// </summary>
    /// <param name="piece">How many octets each send carries (0: all at once).</param>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [Requirement("RFC9112-7.1-4", "RFC9112-7.1.1-4", "RFC9112-7.1.2-3#2", "RFC9112-7.1.2-3#3", "RFC9110-6.5.1-3", "RFC9110-6.5.2-3")]
    public void DecodesChunkedBodiesAndKeepsTrailersApart(int piece)
    {
        Platform.RequireLinuxX64();
        Exchange? seen = null;
        using var server = new TestServer(x =>
        {
            seen = x;
            x.Respond(200, x.Body);
        });
        using var c = new RawConnection(server.Port);
        string request = "POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n"
            + "5;name=value\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 42\r\n\r\n";

        SendInPieces(c, request, piece);
        RawResponse response = c.ReadResponse();

        Assert.Equal("hello world", response.Text);
        Assert.NotNull(seen);
        Assert.Equal("42", Assert.Single(seen.Trailers).Value);
        Assert.DoesNotContain(seen.Fields, f => f.Name == "X-Sum");
    }

    /// <summary>
    /// A request that arrives an octet at a time is read and answered like any other: the
    /// handler runs once, on the whole request, never on a header section still arriving.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-5.3-6")]
    public void ReadsARequestSentAnOctetAtATime()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Method + " " + x.Target + " " + Encoding.ASCII.GetString(x.Body)));
        using var c = new RawConnection(server.Port);

        SendInPieces(c, "\r\nPOST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc", 1);

        Assert.Equal("POST /x abc", c.ReadResponse().Text);
    }

    /// <summary>
    /// A client that half-closes after its request still gets the answer, then the close; also
    /// when the answer is deferred and comes after the half-close was seen.
    /// </summary>
    /// <param name="deferred">Whether the handler answers later, from the thread pool.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnswersAClientThatHalfClosed(bool deferred)
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x =>
        {
            if (!deferred)
            {
                x.Respond(200, "bye");
                return;
            }

            x.Defer();
            _ = Task.Run(async () =>
            {
                await Task.Delay(200, ct);
                x.Respond(200, "bye");
            }, ct);
        });
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        c.ShutdownSend();

        Assert.Equal("bye", c.ReadResponse().Text);
        Assert.True(c.ServerClosed());
    }

    /// <summary>
    /// Connections idle past the timeout are closed, and so are heads that never complete (a
    /// slow-loris client cannot hold a connection by trickling octets), without an answer (an
    /// error response to the incomplete request is the server's option; it closes silently). A
    /// connection that keeps sending requests gets a full timeout after each.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-2#1", "RFC9112-9.5-2#2", "RFC9112-9.5-3", "RFC9112-8-1")]
    public void ClosesIdleConnections()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "ok"), idleMs: 300);
        using var idle = new RawConnection(server.Port);
        using var slow = new RawConnection(server.Port);
        using var busy = new RawConnection(server.Port);
        var clock = Stopwatch.StartNew();

        slow.Send("GET / HTTP/1.1\r\nHo");
        for (int i = 0; i < 5; i++)
        {
            busy.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
            Assert.Equal("ok", busy.ReadResponse().Text);
            Thread.Sleep(150);
        }

        Assert.True(idle.ServerClosed());
        Assert.True(slow.ServerClosed());
        Assert.InRange(clock.ElapsedMilliseconds, 250, 5000);
        Assert.True(busy.QuietFor(50));     // 750 ms in, past the timeout, and still open
    }

    /// <summary>
    /// The idle timeout is for idleness, not for the length of a transfer. An 8 MiB answer read
    /// in 64 KiB pieces every 10 ms takes over four times the 300 ms timeout, and arrives whole:
    /// each window in which it moves at least min_data_rate (240 octets a second by default)
    /// earns another (RFC9112-9.5-4: the transport's flow control resolves a slow reader, not a
    /// close). The deadline used to be set when the answer was queued, and the connection was
    /// closed with the answer still on its way. The answer is far larger than the kernel's
    /// buffering on loopback (its 64 KiB segments let the send buffer grow to 1.6 MB), which
    /// would otherwise deliver what a close left behind.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-4")]
    public void SendsAnswersLongerThanTheIdleTimeout()
    {
        Platform.RequireLinuxX64();
        byte[] big = RandomBytes(8 << 20);
        using var server = new TestServer(x => x.Respond(200, big), idleMs: 300);
        using var c = new RawConnection(server.Port, receiveBuffer: 65536);
        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        var clock = Stopwatch.StartNew();

        byte[] got = c.ReadSlowly(int.MaxValue, 65536, 10);         // to the close, or the timeout

        int head = got.AsSpan().IndexOf("\r\n\r\n"u8) + 4;
        Assert.True(head > 4, "no answer");
        Assert.True(big.AsSpan().SequenceEqual(got.AsSpan(head)), $"{got.Length - head} of {big.Length} octets came");
        Assert.True(clock.ElapsedMilliseconds > 900, $"{clock.ElapsedMilliseconds} ms: the read was not slow");
    }

    /// <summary>
    /// A request body sent slowly is taken whole however long it takes, as long as it keeps
    /// moving: 2 MiB in 32 KiB pieces every 25 ms takes about five times the 300 ms timeout,
    /// and is answered. The head's deadline used to run on through the body, and closed the
    /// connection in the middle of the upload.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-4")]
    public void TakesBodiesLongerThanTheIdleTimeout()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Body.Length.ToString(CultureInfo.InvariantCulture)), idleMs: 300, maxBody: 4 << 20);
        using var c = new RawConnection(server.Port);
        byte[] piece = RandomBytes(32768);
        var clock = Stopwatch.StartNew();

        c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 2097152\r\n\r\n");
        for (int i = 0; i < 64; i++)
        {
            Thread.Sleep(25);
            c.Send(piece);
        }

        Assert.Equal("2097152", c.ReadResponse().Text);
        Assert.True(clock.ElapsedMilliseconds > 900, $"{clock.ElapsedMilliseconds} ms: the upload was not slow");
    }

    /// <summary>
    /// min_data_rate is the server's to choose. The upload the default rate keeps
    /// (<see cref="TakesBodiesLongerThanTheIdleTimeout"/>: about 1.3 MB/s) is cut after its
    /// first window when the server asks for 10 MB/s.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-3")]
    public void HoldsTransfersToTheRateItIsGiven()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "taken"), idleMs: 300, maxBody: 4 << 20, minDataRate: 10_000_000);
        using var c = new RawConnection(server.Port, timeoutMs: 5000);
        byte[] piece = RandomBytes(32768);
        var clock = Stopwatch.StartNew();

        c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 2097152\r\n\r\n");
        bool cut = false;
        for (int i = 0; i < 64 && !cut; i++)
        {
            Thread.Sleep(25);
            cut = !TrySend(c, Encoding.Latin1.GetString(piece));
        }

        Assert.True(cut || c.ServerClosed(1000), $"the upload was kept for {clock.ElapsedMilliseconds} ms");
        Assert.InRange(clock.ElapsedMilliseconds, 250, 2000);
    }

    /// <summary>
    /// Slow requests are cut at the idle timeout. A head trickled an octet at a time
    /// (slowloris) makes no progress: a head must be whole within the timeout. A body sent below
    /// min_data_rate (RUDY: 200 octets a second against 240) is not progress enough to earn
    /// another window. Each connection is closed within a few timeouts while its client is
    /// still sending.
    /// </summary>
    /// <param name="attack">"slowloris" or "rudy".</param>
    [Theory]
    [InlineData("slowloris")]
    [InlineData("rudy")]
    [Requirement("RFC9112-9.5-3")]
    public void CutsSlowRequests(string attack)
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "ok"), idleMs: 300, maxBody: 1 << 20);
        using var c = new RawConnection(server.Port, timeoutMs: 5000);
        var clock = Stopwatch.StartNew();
        bool closed = false;
        if (attack == "rudy")
        {
            c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n");
        }

        // Slowloris: "Gxxx..." never ends its request-line, an octet every 50 ms. RUDY: 10
        // octets of body every 50 ms. Either way the client keeps going for 4 s unless cut.
        for (int i = 0; i < 80 && !closed; i++)
        {
            closed = !TrySend(c, attack == "rudy" ? "0123456789" : i == 0 ? "G" : "x");
            Thread.Sleep(50);
        }

        Assert.True(closed || c.ServerClosed(1000), $"{attack}: still open after {clock.ElapsedMilliseconds} ms");
        Assert.InRange(clock.ElapsedMilliseconds, 250, 3000);
    }

    /// <summary>
    /// A client that reads an answer below min_data_rate (a slow read: 200 octets a second
    /// against 240, holding the answer's memory on the server) is not progress enough to earn
    /// another window. After a second and a half of slow reading, the rest of what the server
    /// handed to the kernel arrives, then the end, far short of the 16 MiB answer. The kernel
    /// takes the first megabyte or two at once, because loopback's 64 KiB segments let it grow
    /// the server's send buffer that far. So the answer is large enough that only cutting the
    /// transfer, not any buffer, can explain a short read.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-3")]
    public void CutsSlowReaders()
    {
        Platform.RequireLinuxX64();
        byte[] big = RandomBytes(16 << 20);
        using var server = new TestServer(x => x.Respond(200, big), idleMs: 300);
        using var c = new RawConnection(server.Port, timeoutMs: 5000, receiveBuffer: 4096);
        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");

        byte[] slow = c.ReadSlowly(300, 10, 50);                   // 10 octets every 50 ms, 1.5 s
        byte[] rest = c.ReadSlowly(int.MaxValue, 65536, 0);        // then at once, to the end

        Assert.Equal(300, slow.Length);
        Assert.True(slow.Length + rest.Length < big.Length / 2, $"{slow.Length + rest.Length} octets came: the slow read was not cut");
    }

    /// <summary>Sends text, and says whether the connection took it (false: the server closed it).</summary>
    /// <param name="c">The connection.</param>
    /// <param name="text">The octets.</param>
    /// <returns>True when sent.</returns>
    private static bool TrySend(RawConnection c, string text)
    {
        try
        {
            c.Send(text);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>
    /// Stopping closes the connections between requests at once, lets an exchange in flight
    /// finish (its deferred answer is still delivered), and returns once the workers exited;
    /// the server then starts again on the same port.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    public async Task StopsGracefullyAndStartsAgain()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var started = new ManualResetEventSlim();
        using var server = new TestServer(x =>
        {
            if (x.Target != "/slow")
            {
                x.Respond(200, "quick");
                return;
            }

            x.Defer();
            started.Set();
            _ = Task.Run(async () =>
            {
                await Task.Delay(300, ct);
                x.Respond(200, "late");
            }, ct);
        });
        using var idle = new RawConnection(server.Port);
        using var busy = new RawConnection(server.Port);
        idle.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        Assert.Equal("quick", idle.ReadResponse().Text);
        busy.Send("GET /slow HTTP/1.1\r\nHost: t\r\n\r\n");
        Assert.True(started.Wait(5000, ct));

        Task stop = Task.Run(server.Stop, ct);

        Assert.True(idle.ServerClosed());
        Assert.Equal("late", busy.ReadResponse().Text);
        await stop.WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(0, server.Start());
        using var again = new RawConnection(server.Port);
        again.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        Assert.Equal("quick", again.ReadResponse().Text);
        Assert.Equal(-22, server.Start());  // already running
    }

    /// <summary>A thousand requests from many connections at once, on four workers, are all answered right.</summary>
    /// <returns>The test.</returns>
    [Fact]
    public async Task ServesManyConnectionsAtOnce()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x => x.Respond(200, x.Target), workers: 4);
        using var client = NewClient(maxConnections: 256);

        string[] answers = await Task.WhenAll(Enumerable.Range(0, 1000)
            .Select(i => client.GetStringAsync(new Uri(server.Address, CultureInfoInvariant($"{i}")), ct)));

        for (int i = 0; i < answers.Length; i++)
        {
            Assert.Equal(CultureInfoInvariant($"/{i}"), answers[i]);
        }
    }

    /// <summary>
    /// A client that pipelines many large requests' worth of answers and reads slowly gets them
    /// all, whole and in order: the server stops reading while its output is past the
    /// high-water mark, and resumes when the socket drains. The overload is left to TCP's flow
    /// control; the persistent connection is never dropped for it.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-4")]
    public void KeepsOrderAndOctetsUnderBackPressure()
    {
        Platform.RequireLinuxX64();
        byte[] big = RandomBytes(1 << 20);
        using var server = new TestServer(x => x.Respond(200, big, ("X-Target", x.Target)));
        using var c = new RawConnection(server.Port, timeoutMs: 30000);
        var burst = new StringBuilder();
        for (int i = 0; i < 24; i++)
        {
            burst.Append(CultureInfoInvariant($"GET /{i} HTTP/1.1\r\nHost: t\r\n\r\n"));
        }

        c.Send(burst.ToString());
        Thread.Sleep(200);                  // the server fills the socket and stops

        for (int i = 0; i < 24; i++)
        {
            RawResponse response = c.ReadResponse();
            Assert.Equal(CultureInfoInvariant($"/{i}"), response.Field("X-Target"));
            Assert.True(big.AsSpan().SequenceEqual(response.Body));
        }
    }

    /// <summary>An 8 MiB answer arrives whole.</summary>
    /// <returns>The test.</returns>
    [Fact]
    public async Task SendsLargeAnswersWhole()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        byte[] big = RandomBytes(8 << 20);
        using var server = new TestServer(x => x.Respond(200, big));
        using var client = NewClient();

        byte[] received = await client.GetByteArrayAsync(server.Address, ct);

        Assert.True(big.AsSpan().SequenceEqual(received));
    }

    /// <summary>An HttpClient for a test: HTTP/1.1, a 10 s timeout so a hang fails instead.</summary>
    /// <param name="maxConnections">The most connections to the server at once.</param>
    /// <returns>The client.</returns>
    private static HttpClient NewClient(int maxConnections = 8) =>
        new(new SocketsHttpHandler { MaxConnectionsPerServer = maxConnections })
        {
            Timeout = TimeSpan.FromSeconds(10),
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

    /// <summary>
    /// workers 0 asks for one worker per CPU the process may run on (its affinity mask, read
    /// with sched_getaffinity): the server starts and serves. No other test leaves the count to
    /// the library.
    /// </summary>
    [Fact]
    public void RunsOneWorkerPerCpuByDefault()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "ok"), workers: 0);
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");

        Assert.Equal("ok", c.ReadResponse().Text);
    }

    /// <summary>
    /// The life-cycle calls take what C callers may hand them: httpasm_server_create without
    /// options is -EINVAL (into *error, or nowhere when error is NULL too), and destroying or
    /// closing NULL does nothing; a client whose connect fails returns NULL with error NULL.
    /// </summary>
    [Fact]
    public unsafe void TakesNullWhereTheApiAllowsIt()
    {
        Platform.RequireLinuxX64();
        int error = 0;
        Assert.Equal(0, Native.ServerCreate(null, &error));
        Assert.Equal(-22, error);                                   // -EINVAL
        Assert.Equal(0, Native.ServerCreate(null, null));
        Native.ServerDestroy(0);
        Native.ClientClose(0);

        // A port nothing listens on: the connect is refused, and there is nowhere to say so.
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        ushort closed = (ushort)((IPEndPoint)probe.LocalEndPoint!).Port;
        Assert.Equal(0, Native.ClientConnect(0x0100007F, closed, 1000, null));
    }

    /// <summary>
    /// An idle timeout past what one wait can take (epoll_wait's timeout is an int of
    /// milliseconds; uint.MaxValue is 49.7 days) is waited in pieces of at most 2^31 - 1 ms: the
    /// server starts, serves, and keeps the connection.
    /// </summary>
    [Fact]
    public void TakesIdleTimeoutsPastOneWaitsRange()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, "ok"), idleMs: uint.MaxValue);
        using var c = new RawConnection(server.Port);

        for (int i = 0; i < 3; i++)
        {
            c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
            Assert.Equal("ok", c.ReadResponse().Text);
        }

        Assert.True(c.QuietFor(100));
    }

    /// <summary>
    /// A client may send its request and half-close (shutdown SHUT_WR) before the answer: it
    /// finished sending, not reading. A deferred answer that comes after the half-close is
    /// still sent whole, then the connection closes (nothing more can come on it).
    /// </summary>
    [Fact]
    public void AnswersAfterTheClientHalfClosesWhileDeferred()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x =>
        {
            x.Defer();
            _ = Task.Run(async () =>
            {
                await Task.Delay(300);
                x.Respond(200, "after the half-close");
            });
        });
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        c.ShutdownSend();

        Assert.Equal("after the half-close", c.ReadResponse().Text);
        Assert.True(c.ServerClosed());
    }

    /// <summary>
    /// An answer's head larger than the first room the connection reserves for it (512 octets)
    /// is written whole: the room doubles until the head fits. 20 fields of 100 octets each.
    /// </summary>
    [Fact]
    public void WritesHeadsLargerThanTheirFirstRoom()
    {
        Platform.RequireLinuxX64();
        (string, string)[] fields = [.. Enumerable.Range(0, 20).Select(i => ($"X-Field-{i}", new string((char)('a' + i), 100)))];
        using var server = new TestServer(x => x.Respond(200, "big head", fields));
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        RawResponse response = c.ReadResponse();

        Assert.Equal("big head", response.Text);
        Assert.All(fields, f => Assert.Equal(f.Item2, response.Field(f.Item1)));
    }

    /// <summary>
    /// A body larger than the connection's first 16 KiB of input moves the input when it grows,
    /// and every part of the request the handler sees moves with it: the method and target
    /// always, the authority and the scheme when present (an absolute-form target names both),
    /// and nothing that is absent (an HTTP/1.0 request without Host has no authority). The
    /// body is 300,000 octets, sent in pieces so the input grows several times.
    /// </summary>
    /// <param name="request">The request's head.</param>
    /// <param name="target">The target the handler must see.</param>
    /// <param name="authority">The authority (null: none).</param>
    /// <param name="scheme">The scheme (null: none).</param>
    [Theory]
    [InlineData("POST /upload?x=1 HTTP/1.0\r\nContent-Length: 300000\r\n\r\n", "/upload?x=1", null, null)]
    [InlineData("POST http://example.com:8080/upload HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 300000\r\n\r\n",
        "http://example.com:8080/upload", "example.com:8080", "http")]
    [InlineData("POST /plain HTTP/1.1\r\nHost: h\r\nContent-Length: 300000\r\n\r\n", "/plain", "h", null)]
    public void KeepsTheRequestWholeWhenItsInputMoves(string request, string target, string? authority, string? scheme)
    {
        Platform.RequireLinuxX64();
        Exchange? seen = null;
        using var server = new TestServer(x =>
        {
            seen = x;
            x.Respond(200, x.Body.Length.ToString(CultureInfo.InvariantCulture));
        });
        using var c = new RawConnection(server.Port);

        byte[] body = RandomBytes(300_000);
        c.Send(request);
        for (int at = 0; at < body.Length; at += 50_000)
        {
            Thread.Sleep(5);                                        // separate reads: the input grows in steps
            c.Send(body.AsSpan(at, 50_000));
        }

        Assert.Equal("300000", c.ReadResponse().Text);
        Assert.NotNull(seen);
        Assert.Equal(("POST", target, authority, scheme), (seen!.Method, seen.Target, seen.Authority, seen.Scheme));
        Assert.True(body.AsSpan().SequenceEqual(seen.Body));
    }

    /// <summary>
    /// A server stopping finishes the requests in progress: one whose body is still arriving
    /// when the stop begins is not closed as idle (only connections between requests are), and
    /// its answer goes out once the body is whole.
    /// </summary>
    /// <returns>A task.</returns>
    [Fact]
    public async Task FinishesARequestWhoseBodyIsArrivingWhenTheStopBegins()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        using var server = new TestServer(x => x.Respond(200, x.Body));
        using var c = new RawConnection(server.Port);

        c.Send("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\nhello");
        Thread.Sleep(100);                                          // the head is read; the body waits
        Task stop = Task.Run(server.Stop, ct);
        Thread.Sleep(100);
        c.Send("world");

        Assert.Equal("helloworld", c.ReadResponse().Text);
        await stop.WaitAsync(TimeSpan.FromSeconds(10), ct);
    }

    /// <summary>Octets that are the same on every run (seeded by the length).</summary>
    /// <param name="length">How many.</param>
    /// <returns>The octets.</returns>
    private static byte[] RandomBytes(int length)
    {
        byte[] data = new byte[length];
        new Random(length).NextBytes(data);
        return data;
    }

    /// <summary>Sends text in pieces of the given size, each a separate send (the socket has no delay).</summary>
    /// <param name="c">The connection.</param>
    /// <param name="text">The octets.</param>
    /// <param name="piece">The piece size; 0 sends all at once.</param>
    private static void SendInPieces(RawConnection c, string text, int piece)
    {
        if (piece == 0)
        {
            c.Send(text);
            return;
        }

        for (int i = 0; i < text.Length; i += piece)
        {
            c.Send(text.Substring(i, Math.Min(piece, text.Length - i)));
            Thread.Sleep(1);                // a separate segment, so the server reads it apart
        }
    }

    /// <summary>Formats with the invariant culture (the analyzers require one).</summary>
    /// <param name="text">The interpolated text.</param>
    /// <returns>The string.</returns>
    private static string CultureInfoInvariant(FormattableString text) => FormattableString.Invariant(text);
}
