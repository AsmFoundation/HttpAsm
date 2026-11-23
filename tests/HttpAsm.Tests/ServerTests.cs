using System.Diagnostics;
using System.Net;
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
    /// earlier ones.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.3.2-1#2", "RFC9112-9.3.2-1#3", "RFC9112-9.3-1")]
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
    /// closes, and never runs a request pipelined behind it.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.6-6#1", "RFC9112-9.6-6#2", "RFC9112-9.6-6#3", "RFC9112-9.6-1")]
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
    /// it the connection closes after the answer.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.3-1")]
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
    /// A body past max_body is refused with 413 and the connection closes (its unread body
    /// would otherwise be taken for the next request): a declared length at once, before any
    /// body octet is read; a chunked body as soon as the decoded octets pass the limit. A body
    /// of exactly the limit is accepted.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-15.5.14-1#2", "RFC9112-9.3-7#1")]
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
    /// fields than max_fields or a head past max_head is 431.
    /// </summary>
    /// <param name="request">The octets sent.</param>
    /// <param name="status">The status expected.</param>
    [Theory]
    [InlineData("GET /0123456789012345678901234567890123456789012345678901234567890123456789 HTTP/1.1\r\nHost: t\r\n\r\n", 414)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n", 431)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nX: 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n\r\n", 431)]
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
    /// HEAD is answered with GET's fields (Content-Length of the body it would have had) and no
    /// body: the next response on the connection starts right after the head.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-9.3.2-1", "RFC9110-9.3.2-2#1", "RFC9110-8.6-6#1", "RFC9110-8.6-6#2")]
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
    [Requirement("RFC9112-7.1-4", "RFC9112-7.1.1-4", "RFC9112-7.1.2-3#2", "RFC9112-7.1.2-3#3", "RFC9110-6.5.1-3")]
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

    /// <summary>A request that arrives an octet at a time is read and answered like any other.</summary>
    [Fact]
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
    /// slow-loris client cannot hold a connection by trickling octets). A connection that keeps
    /// sending requests gets a full timeout after each.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.5-2#1", "RFC9112-9.5-2#2")]
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
    /// high-water mark, and resumes when the socket drains.
    /// </summary>
    [Fact]
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
