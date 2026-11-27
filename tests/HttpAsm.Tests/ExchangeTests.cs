using System.Collections.Concurrent;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// The exchange API's contract (httpasm.h): the request's parts with NULL out-arguments,
/// deferral, answers the writer refuses and the retry they allow, a deferred answer racing
/// another, deferred answers over each version and to each kind of request, and answers that
/// come after their client is gone.
/// </summary>
public sealed unsafe class ExchangeTests
{
    /// <summary>-EINVAL: the exchange is not answerable (answered already, or not deferred).</summary>
    private const int Einval = -22;

    /// <summary>
    /// httpasm_exchange_body and httpasm_exchange_trailers take NULL for the length or count:
    /// the pointer is still returned, the same as with the out-argument.
    /// </summary>
    [Fact]
    public void ReadsTheBodyAndTrailersWithoutTheirLengths()
    {
        Platform.RequireLinuxX64();
        bool same = false;
        using var server = new TestServer(x =>
        {
            nuint length;
            uint count;
            same = Native.ExchangeBody(x.Pointer, null) == Native.ExchangeBody(x.Pointer, &length) && length == 3
                && Native.ExchangeTrailers(x.Pointer, null) == Native.ExchangeTrailers(x.Pointer, &count) && count == 1;
            x.Respond(200);
        });
        using var c = new RawConnection(server.Port);

        c.Send("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n");

        Assert.Equal(200, c.ReadResponse().Status);
        Assert.True(same);
    }

    /// <summary>
    /// An exchange is deferred once, inside its handler: a second httpasm_exchange_defer is
    /// -EINVAL, as is answering it twice, or deferring it once answered. The one answer reaches
    /// the client.
    /// </summary>
    [Fact]
    public void DefersOnceAndAnswersOnce()
    {
        Platform.RequireLinuxX64();
        var results = new ConcurrentQueue<(string, int)>();
        using var server = new TestServer(x =>
        {
            results.Enqueue(("defer", x.Defer()));
            results.Enqueue(("defer again", x.Defer()));
            _ = Task.Run(() =>
            {
                results.Enqueue(("answer", x.Respond(200, "late")));
                results.Enqueue(("answer again", x.Respond(200, "twice")));
            });
        });
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");

        Assert.Equal("late", c.ReadResponse().Text);
        Assert.Equal([("defer", 0), ("defer again", Einval), ("answer", 0), ("answer again", Einval)], results.ToArray());
        Assert.True(c.QuietFor(200));                       // one answer only
    }

    /// <summary>
    /// Two threads answer one deferred exchange at once: one wins and the other gets -EINVAL,
    /// whether it lost before reading the state or in the compare-and-swap that claims the
    /// exchange, and the client gets exactly one response. Run 300 times, on the same
    /// connection, with both threads released together each time.
    /// </summary>
    [Fact]
    public void AnswersADeferredExchangeOnceWhenTwoThreadsRace()
    {
        Platform.RequireLinuxX64();
        var winners = new ConcurrentQueue<int>();
        using var server = new TestServer(x =>
        {
            x.Defer();
            using var barrier = new Barrier(2);
            int[] got = new int[2];
            var a = new Thread(() => { barrier.SignalAndWait(); got[0] = x.Respond(200, "a"); });
            var b = new Thread(() => { barrier.SignalAndWait(); got[1] = x.Respond(200, "b"); });
            a.Start();
            b.Start();
            a.Join();
            b.Join();
            winners.Enqueue(got.Count(r => r == 0) * 10 + got.Count(r => r == Einval));
        }, workers: 1);
        using var c = new RawConnection(server.Port);

        for (int i = 0; i < 300; i++)
        {
            c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
            Assert.Contains(c.ReadResponse().Text, new[] { "a", "b" });
        }

        Assert.True(c.QuietFor(200));
        Assert.All(winners, w => Assert.Equal(11, w));     // one 0 and one -EINVAL every time
    }

    /// <summary>
    /// A deferred HTTP/1.1 answer the writer refuses (a framing field from the caller) is
    /// -HTTPASM_ERROR_FRAMING_FIELD with nothing sent, and leaves the exchange answerable: the
    /// correct answer that follows is the one the client gets.
    /// </summary>
    [Fact]
    public void RetriesADeferredAnswerTheWriterRefused()
    {
        Platform.RequireLinuxX64();
        int refused = 0;
        using var server = new TestServer(x =>
        {
            x.Defer();
            _ = Task.Run(() =>
            {
                refused = x.Respond(200, "no", ("Connection", "upgrade"));
                x.Respond(200, "yes");
            });
        });
        using var c = new RawConnection(server.Port);

        c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");

        Assert.Equal("yes", c.ReadResponse().Text);
        Assert.Equal(-(int)ParseError.FramingField, refused);
    }

    /// <summary>
    /// Deferred answers suit their requests as immediate ones do: to HEAD, the fields without
    /// the body; to a request that closes (Connection: close, or HTTP/1.0 without keep-alive),
    /// Connection: close and then the close; and a head too large for the first 1 KiB of room
    /// (fields of 2 KiB in all) is written whole all the same.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="head">Whether it is HEAD.</param>
    /// <param name="closes">Whether the connection closes after the answer.</param>
    [Theory]
    [InlineData("HEAD / HTTP/1.1\r\nHost: t\r\n\r\n", true, false)]
    [InlineData("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", false, true)]
    [InlineData("GET / HTTP/1.0\r\n\r\n", false, true)]
    [InlineData("GET /many-fields HTTP/1.1\r\nHost: t\r\n\r\n", false, false)]
    [Requirement("RFC9110-9.3.2-1", "RFC9112-9.6-6#1", "RFC9112-9.6-6#2")]
    public void SuitsDeferredAnswersToTheirRequests(string request, bool head, bool closes)
    {
        Platform.RequireLinuxX64();
        (string, string)[] many = [.. Enumerable.Range(0, 20).Select(i => ($"X-Field-{i}", new string((char)('a' + i), 100)))];
        using var server = new TestServer(x =>
        {
            x.Defer();
            _ = Task.Run(() => x.Respond(200, "deferred body", x.Target == "/many-fields" ? many : []));
        });
        using var c = new RawConnection(server.Port);

        c.Send(request);
        RawResponse response = c.ReadResponse(head);

        Assert.Equal(200, response.Status);
        Assert.Equal(head ? "" : "deferred body", response.Text);
        Assert.Equal("13", response.Field("Content-Length"));
        Assert.Equal(closes, response.Field("Connection") == "close");
        Assert.Equal(closes, c.ServerClosed(closes ? 5000 : 300));
        if (request.Contains("/many-fields", StringComparison.Ordinal))
        {
            Assert.All(many, f => Assert.Equal(f.Item2, response.Field(f.Item1)));
        }
    }

    /// <summary>
    /// A deferred HTTP/2 answer carries the caller's fields (copied, with their strings, into
    /// the completion the worker encodes), and one the HTTP/2 rules refuse - a status outside
    /// 200-599 (1xx are the server's alone), a connection-specific field (RFC9113-8.2.2-1) - is
    /// refused synchronously with nothing sent, the exchange answerable again.
    /// </summary>
    [Fact]
    [Requirement("RFC9113-8.2.2-1#1")]
    public void ChecksAndCarriesDeferredHttp2Answers()
    {
        Platform.RequireLinuxX64();
        var results = new ConcurrentQueue<int>();
        using var server = new TestServer(x =>
        {
            x.Defer();
            _ = Task.Run(() =>
            {
                results.Enqueue(x.Respond(103));
                results.Enqueue(x.Respond(600));
                results.Enqueue(x.Respond(200, "no", ("connection", "close")));
                results.Enqueue(x.Respond(200, "no", ("upgrade", "h2c")));
                results.Enqueue(x.Respond(201, "created", ("x-one", "1"), ("x-two", "second value")));
            });
        });
        using var c = new H2Connection(server.Port);

        c.SendRequest(1);
        H2Response response = c.ReadResponse(1);

        Assert.Equal(201, response.Status);
        Assert.Equal("created", Encoding.UTF8.GetString(response.Body));
        Assert.Equal("1", response.Fields.Single(f => f.Name == "x-one").Value);
        Assert.Equal("second value", response.Fields.Single(f => f.Name == "x-two").Value);
        Assert.Equal([-(int)ParseError.Status, -(int)ParseError.Status, -(int)ParseError.FramingField, -(int)ParseError.FramingField, 0], results.ToArray());
    }

    /// <summary>
    /// A deferred answer that comes after its client reset the connection is taken (0: it was
    /// posted) and dropped by the worker with the connection, whose memory waited for it. Over
    /// HTTP/2 the connection waits for every deferred stream's answer. The server serves the
    /// next client as before.
    /// </summary>
    /// <param name="http2">Whether the client speaks HTTP/2 (two deferred streams).</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DropsAnswersWhoseClientIsGone(bool http2)
    {
        Platform.RequireLinuxX64();
        var waiting = new BlockingCollection<Exchange>();
        using var server = new TestServer(x =>
        {
            if (x.Target == "/later")
            {
                x.Defer();
                waiting.Add(x);
            }
            else
            {
                x.Respond(200, "next");
            }
        }, workers: 1);

        if (http2)
        {
            using var c = new H2Connection(server.Port);
            c.SendRequest(1, path: "/later");
            c.SendRequest(3, path: "/later");
            Exchange first = waiting.Take(TestContext.Current.CancellationToken), second = waiting.Take(TestContext.Current.CancellationToken);
            c.Abort();
            Pause.AtLeast(100);                                  // the worker sees the reset
            Assert.Equal(0, first.Respond(200, "nobody"));
            Pause.AtLeast(50);
            Assert.Equal(0, second.Respond(200, "nobody"));
        }
        else
        {
            using var c = new RawConnection(server.Port);
            c.Send("GET /later HTTP/1.1\r\nHost: t\r\n\r\n");
            Exchange only = waiting.Take(TestContext.Current.CancellationToken);
            c.Abort();
            Pause.AtLeast(100);
            Assert.Equal(0, only.Respond(200, "nobody"));
        }

        Pause.AtLeast(100);
        using var next = new RawConnection(server.Port);
        next.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        Assert.Equal("next", next.ReadResponse().Text);
    }
}
