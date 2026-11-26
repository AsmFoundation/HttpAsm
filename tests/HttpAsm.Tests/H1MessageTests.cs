using System.Runtime.CompilerServices;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// The HTTP/1.1 writers (responses, requests, chunks), the client's response parser and the
/// chunked codec, through the C ABI and with no sockets. Writers and parsers are also run
/// against each other: what one writes, the other must read back unchanged.
/// </summary>
public sealed class H1MessageTests
{
    /// <summary>The .NET copies of the new structures have the library's sizes.</summary>
    [Fact]
    public void StructuresMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal((uint)Unsafe.SizeOf<HttpResponse>(), Native.StructSize(4));
        Assert.Equal((uint)Unsafe.SizeOf<ResponseHead>(), Native.StructSize(5));
        Assert.Equal((uint)Unsafe.SizeOf<ChunkedState>(), Native.StructSize(6));
        Assert.Equal(48, Unsafe.SizeOf<HttpResponse>());
        Assert.Equal(64, Unsafe.SizeOf<ResponseHead>());
        Assert.Equal(32, Unsafe.SizeOf<ChunkedState>());
    }

    /// <summary>A 200 with a known length: status-line, Date, Content-Length, the fields, CRLF.</summary>
    [Fact]
    [Requirement("RFC9112-4-2", "RFC9110-6.6.1-6#1", "RFC9110-8.6-9", "RFC9112-2.2-7", "RFC9110-5.6.3-2#1", "RFC9110-5.6.3-2#2",
        "RFC9110-5.6.3-5#1", "RFC9112-6.3-3")]
    public void WritesAResponseWithALength()
    {
        Platform.RequireLinuxX64();
        var (result, text, flags) = H1Messages.WriteResponse(200, [("Content-Type", "text/plain"), ("X-Empty", "")], length: 5);
        Assert.Equal("HTTP/1.1 200 OK\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 5\r\nContent-Type: text/plain\r\nX-Empty: \r\n\r\n", text);
        Assert.Equal(text.Length, result);
        Assert.Equal(Abi.ResponseLength, flags);
    }

    /// <summary>The body's framing per request version and length; Connection as persistence needs.</summary>
    /// <param name="version">The request's version.</param>
    /// <param name="known">Whether the length is known.</param>
    /// <param name="close">Whether the connection closes.</param>
    /// <param name="framing">The framing line expected (or empty).</param>
    /// <param name="connection">The Connection line expected (or empty).</param>
    /// <param name="flags">The flags reported.</param>
    [Theory]
    [InlineData(11, true, false, "Content-Length: 3\r\n", "", 0x1u)]
    [InlineData(11, false, false, "Transfer-Encoding: chunked\r\n", "", 0x4u)]
    [InlineData(11, true, true, "Content-Length: 3\r\n", "Connection: close\r\n", 0x3u)]
    [InlineData(10, true, false, "Content-Length: 3\r\n", "Connection: keep-alive\r\n", 0x1u)]
    [InlineData(10, false, false, "", "Connection: close\r\n", 0x2u)]
    [InlineData(10, true, true, "Content-Length: 3\r\n", "Connection: close\r\n", 0x3u)]
    [Requirement("RFC9112-6.1-13#2", "RFC9112-9.6-6#2", "RFC9112-9.6-1", "RFC9112-6.3-7#1")]
    public void FramesTheBody(int version, bool known, bool close, string framing, string connection, uint flags)
    {
        Platform.RequireLinuxX64();
        var (_, text, reported) = H1Messages.WriteResponse(200, length: known ? 3 : null, version: version, close: close, date: null);
        Assert.Equal($"HTTP/1.1 200 OK\r\n{framing}{connection}\r\n", text);
        Assert.Equal(flags, reported);
    }

    /// <summary>No framing fields where a body cannot exist; HEAD keeps the length of its GET.</summary>
    /// <param name="status">The status.</param>
    /// <param name="method">The request's method.</param>
    /// <param name="expected">The head expected.</param>
    [Theory]
    [InlineData(204, "GET", "HTTP/1.1 204 No Content\r\n\r\n")]
    [InlineData(304, "GET", "HTTP/1.1 304 Not Modified\r\n\r\n")]
    [InlineData(100, "GET", "HTTP/1.1 100 Continue\r\n\r\n")]
    [InlineData(103, "GET", "HTTP/1.1 103 \r\n\r\n")]
    [InlineData(200, "CONNECT", "HTTP/1.1 200 OK\r\n\r\n")]
    [InlineData(407, "CONNECT", "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 7\r\n\r\n")]
    [InlineData(200, "HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n")]
    [Requirement("RFC9110-8.6-8#1", "RFC9110-8.6-8#2", "RFC9112-6.1-10#1", "RFC9112-6.1-10#2", "RFC9110-8.6-6#1", "RFC9112-4-9#2",
        "RFC9110-8.6-7#1", "RFC9110-8.6-7#2", "RFC9112-6.1-9", "RFC9110-9.3.6-12#1")]
    public void LeavesOutImpossibleBodies(int status, string method, string expected)
    {
        Platform.RequireLinuxX64();
        var (_, text, flags) = H1Messages.WriteResponse(status, length: 7, method: Abi.Methods[method], date: null);
        Assert.Equal(expected, text);
        bool bodyless = status is < 200 or 204 or 304 || method == "HEAD" || (method == "CONNECT" && status < 300);
        Assert.Equal(bodyless, (flags & Abi.ResponseNoBody) != 0);
    }

    /// <summary>An unregistered status keeps the SP before its empty reason; out-of-range ones are refused.</summary>
    [Fact]
    [Requirement("RFC9112-4-9#2", "RFC9112-4-5", "RFC9110-15.2-1", "RFC9112-4-1")]
    public void WritesStatusLines()
    {
        Platform.RequireLinuxX64();
        Assert.StartsWith("HTTP/1.1 299 \r\n", H1Messages.WriteResponse(299, length: 0, date: null).Text);
        Assert.StartsWith("HTTP/1.1 431 Request Header Fields Too Large\r\n", H1Messages.WriteResponse(431, length: 0, date: null).Text);
        Assert.StartsWith("HTTP/1.1 413 Content Too Large\r\n", H1Messages.WriteResponse(413, length: 0, date: null).Text);
        Assert.Equal(-(long)ParseError.Status, H1Messages.WriteResponse(99).Result);
        Assert.Equal(-(long)ParseError.Status, H1Messages.WriteResponse(600).Result);
        Assert.Equal(-(long)ParseError.Status, H1Messages.WriteResponse(100, version: 10).Result);   // no 1xx to HTTP/1.0
    }

    /// <summary>
    /// 205 (Reset Content) carries no content: it goes out with Content-Length: 0, and a body,
    /// or one of unknown length, is refused before anything is written.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-15.3.6-3")]
    public void SendsResetContentEmpty()
    {
        Platform.RequireLinuxX64();
        Assert.Equal("HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n", H1Messages.WriteResponse(205, length: 0, date: null).Text);
        Assert.Equal(-(long)ParseError.Status, H1Messages.WriteResponse(205, length: 5).Result);
        Assert.Equal(-(long)ParseError.Status, H1Messages.WriteResponse(205, length: null).Result);
    }

    /// <summary>The caller's fields must be valid and may not take over the framing.</summary>
    /// <param name="name">The field's name.</param>
    /// <param name="value">Its value.</param>
    /// <param name="error">The refusal.</param>
    [Theory]
    [InlineData("Content-Length", "5", ParseError.FramingField)]
    [InlineData("transfer-encoding", "chunked", ParseError.FramingField)]
    [InlineData("Connection", "close", ParseError.FramingField)]
    [InlineData("Keep-Alive", "timeout=5", ParseError.FramingField)]
    [InlineData("TE", "trailers", ParseError.FramingField)]
    [InlineData("Bad Name", "v", ParseError.FieldName)]
    [InlineData("", "v", ParseError.FieldName)]
    [InlineData("X", "a\r\nInjected: yes", ParseError.FieldValue)]
    [InlineData("X", " leading", ParseError.FieldValue)]
    [InlineData("X", "trailing\t", ParseError.FieldValue)]
    [InlineData("X", "nul\0", ParseError.FieldValue)]
    [InlineData("X", "bare\rcr", ParseError.FieldValue)]
    [InlineData("X", "folded\r\n line", ParseError.FieldValue)]
    [Requirement("RFC9110-2.2-5#1", "RFC9112-6.2-2", "RFC9112-2.2-4#1", "RFC9112-5.2-3", "RFC9112-6.1-4#4")]
    public void RefusesFieldsItCannotSend(string name, string value, ParseError error)
    {
        Platform.RequireLinuxX64();
        var (result, _, _) = H1Messages.WriteResponse(200, [(name, value)], length: 1);
        Assert.Equal(-(long)error, result);
    }

    /// <summary>The caller's own Date replaces the writer's; a full output returns 0.</summary>
    [Fact]
    public void HonorsACallersDateAndReportsAFullOutput()
    {
        Platform.RequireLinuxX64();
        string text = H1Messages.WriteResponse(200, [("Date", "Mon, 07 Nov 1994 08:49:37 GMT")], length: 0).Text;
        Assert.Equal(1, text.Split("Date:").Length - 1);
        Assert.Contains("Mon, 07 Nov", text);
        Assert.Equal(0, H1Messages.WriteResponse(200, length: 0, capacity: 10).Result);
    }

    /// <summary>What the response writer writes, the response parser reads back: status, fields, framing.</summary>
    [Fact]
    [Requirement("RFC9112-4-2", "RFC9112-5-2", "RFC9112-2.1-4")]
    public void ResponsesRoundTrip()
    {
        Platform.RequireLinuxX64();
        var random = new Random(9112);
        for (int i = 0; i < 200; i++)
        {
            int status = random.Next(200, 600);
            (string, string)[] fields = Enumerable.Range(0, random.Next(0, 8))
                .Select(j => ($"X-Field-{j}", new string('v', random.Next(0, 40)) + j)).ToArray();
            long? length = random.Next(3) == 0 ? null : random.Next(0, 100000);
            if (status == 205)
            {
                length = 0;                                         // 205 carries no content (SendsResetContentEmpty)
            }

            var (result, text, _) = H1Messages.WriteResponse(status, fields, length);
            Assert.True(result > 0);
            ParsedResponse parsed = H1Messages.ParseResponse(text + "body");
            Assert.Equal(text.Length, parsed.Result);
            Assert.Equal(status, parsed.Status);
            foreach ((string name, string value) in fields)
            {
                Assert.Equal(value, parsed.Field(name));
            }

            bool bodyless = status is 204 or 304;
            if (bodyless)
            {
                Assert.Equal(Abi.HeadNoBody, parsed.Flags & Abi.HeadNoBody);
            }
            else if (length.HasValue)
            {
                Assert.Equal((ulong)length.Value, parsed.ContentLength);
                Assert.Equal(Abi.HeadContentLength, parsed.Flags & Abi.HeadContentLength);
            }
            else
            {
                Assert.Equal(Abi.HeadChunked, parsed.Flags & Abi.HeadChunked);
            }
        }
    }

    /// <summary>The response parser's framing rules, by RFC 9112 6.3's order.</summary>
    /// <param name="head">The response head.</param>
    /// <param name="method">The request's method.</param>
    /// <param name="flags">The flags expected.</param>
    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD", 0x28u)]
    [InlineData("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "GET", 0x28u)]
    [InlineData("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", "GET", 0x28u)]
    [InlineData("HTTP/1.1 100 Continue\r\n\r\n", "GET", 0x28u)]
    [InlineData("HTTP/1.1 200 Connection Established\r\nContent-Length: 5\r\n\r\n", "CONNECT", 0x18u)]
    [InlineData("HTTP/1.1 407 Proxy Auth\r\nContent-Length: 5\r\n\r\n", "CONNECT", 0x21u)]
    // Found by tests/fuzz/h1_response (2026-11-26): every 2xx to CONNECT is a tunnel, 204 and
    // unregistered 2xx codes included; an invalid code below 100 is framed as a 5xx's, never
    // a tunnel; 1xx and 304 to CONNECT stay bodiless, and the connection stays HTTP.
    [InlineData("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "CONNECT", 0x18u)]
    [InlineData("HTTP/1.1 299 \r\nTransfer-Encoding: chunked\r\n\r\n", "CONNECT", 0x18u)]
    [InlineData("HTTP/1.1 099 Odd\r\nContent-Length: 5\r\n\r\n", "CONNECT", 0x21u)]
    [InlineData("HTTP/1.1 000 Odd\r\n\r\n", "CONNECT", 0x04u)]
    [InlineData("HTTP/1.1 304 Not Modified\r\n\r\n", "CONNECT", 0x28u)]
    [InlineData("HTTP/1.1 101 Switching Protocols\r\n\r\n", "CONNECT", 0x28u)]
    [InlineData("HTTP/1.1 300 Multiple Choices\r\nContent-Length: 5\r\n\r\n", "CONNECT", 0x21u)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", "GET", 0x22u)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", "GET", 0x04u)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked x\r\n\r\n", "GET", 0x04u)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunkedØ\r\n\r\n", "GET", 0x04u)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "GET", 0x21u)]
    [InlineData("HTTP/1.1 200 OK\r\n\r\n", "GET", 0x04u)]
    [InlineData("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\n", "GET", 0x01u)]
    [InlineData("HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", "GET", 0x01u)]
    [InlineData("HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\n", "GET", 0x21u)]
    [Requirement("RFC9112-6.3-2.2", "RFC9112-9.3-6", "RFC9110-9.3.6-12#2", "RFC9110-15-6")]
    public void ReadsTheResponsesFraming(string head, string method, uint flags)
    {
        Platform.RequireLinuxX64();
        ParsedResponse r = H1Messages.ParseResponse(head, Abi.Methods[method]);
        Assert.Equal(head.Length, r.Result);
        Assert.Equal(flags, r.Flags);
    }

    /// <summary>Faulty framing and malformed status-lines are refused, so the client closes and discards.</summary>
    /// <param name="head">The response head.</param>
    /// <param name="error">The refusal.</param>
    [Theory]
    [InlineData("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", ParseError.TeHttp10)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n", ParseError.ContentLength)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", ParseError.ContentLength)]
    [InlineData("HTTP/1.1 2000 OK\r\n\r\n", ParseError.Status)]
    [InlineData("HTTP/1.1 20 OK\r\n\r\n", ParseError.Status)]
    [InlineData("HTTP/1.1 200\r\n\r\n", ParseError.Status)]
    [InlineData("HTTP/2.0 200 OK\r\n\r\n", ParseError.Version)]
    [InlineData("HTTP/1.1 200 O\u0001K\r\n\r\n", ParseError.Status)]
    [InlineData("HTTP/1.1 200 OK\nX: y\r\n\r\n", ParseError.BareLf)]
    [Requirement("RFC9112-6.1-16", "RFC9112-6.3-2.5#4", "RFC9112-4-2", "RFC9112-4-3", "RFC9112-4-8")]
    public void RefusesFaultyResponses(string head, ParseError error)
    {
        Platform.RequireLinuxX64();
        ParsedResponse r = H1Messages.ParseResponse(head);
        Assert.True(r.Result < 0);
        Assert.Equal(error, r.Error);
    }

    /// <summary>A response's obs-fold becomes SP in place, and the field keeps its whole value.</summary>
    [Fact]
    [Requirement("RFC9112-5.2-6", "RFC9112-5.2-2")]
    public void JoinsAResponsesObsFold()
    {
        Platform.RequireLinuxX64();
        string head = "HTTP/1.1 200 OK\r\nX-Folded: first\r\n  second\r\n\tthird \r\nContent-Length: 0\r\n\r\n";
        ParsedResponse r = H1Messages.ParseResponse(head, 1, out string joined);
        Assert.Equal(head.Length, r.Result);
        Assert.Equal("first    second  \tthird", r.Field("x-folded"));
        Assert.DoesNotContain("first\r\n", joined);
        Assert.Equal(2, r.Fields.Count);

        // Whitespace straight after the status-line, or a folded framing field, is refused.
        Assert.Equal(ParseError.ObsFold, H1Messages.ParseResponse("HTTP/1.1 200 OK\r\n X: y\r\n\r\n").Error);
        Assert.Equal(ParseError.ObsFold, H1Messages.ParseResponse("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n 0\r\n\r\n").Error);
    }

    /// <summary>A request: Host first, one framing, the flags' fields, the caller's fields; it parses back.</summary>
    [Fact]
    [Requirement("RFC9110-7.2-4#1", "RFC9110-7.2-4#2", "RFC9112-3.2-5#1", "RFC9112-6.3-7#1", "RFC9110-10.1.1-11.2", "RFC9112-3.2-5#2",
        "RFC9112-3.2-5#3", "RFC9112-2.2-5#1", "RFC9110-6.2-5#1", "RFC9110-6.2-5#2", "RFC9110-10.1.1-11.1", "RFC9112-6.1-4#3",
        "RFC9112-3.2.2-6")]
    public void WritesRequests()
    {
        Platform.RequireLinuxX64();
        const uint contentLength = 0x2, chunked = 0x4, expect = 0x8, close = 0x80;
        var (result, text) = H1Messages.WriteRequest("POST", "/upload?x=1", "example.com:8080", [("Accept", "*/*")], contentLength | expect, 10);
        Assert.Equal("POST /upload?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 10\r\nExpect: 100-continue\r\nAccept: */*\r\n\r\n", text);
        Assert.Equal(text.Length, result);
        ParsedRequest parsed = H1Parsing.Parse(text);
        Assert.Equal(text.Length, parsed.Result);
        Assert.Equal(10ul, parsed.ContentLength);
        Assert.Equal(Abi.RequestExpectContinue, parsed.Flags & Abi.RequestExpectContinue);

        Assert.Contains("Transfer-Encoding: chunked\r\nConnection: close\r\n", H1Messages.WriteRequest("PUT", "/", "h", flags: chunked | close).Text);
        Assert.Equal(-(long)ParseError.FramingField, H1Messages.WriteRequest("PUT", "/", "h", flags: chunked | contentLength).Result);
        Assert.Equal(-(long)ParseError.FramingField, H1Messages.WriteRequest("GET", "/", "h", [("Host", "other")]).Result);
        Assert.Equal(-(long)ParseError.Method, H1Messages.WriteRequest("G T", "/", "h").Result);
        Assert.Equal(-(long)ParseError.Target, H1Messages.WriteRequest("GET", "/a b", "h").Result);
        Assert.Equal(-(long)ParseError.Target, H1Messages.WriteRequest("GET", "/%4", "h").Result);
        Assert.Equal(-(long)ParseError.Authority, H1Messages.WriteRequest("GET", "/", "user@h").Result);
        Assert.Equal("GET / HTTP/1.1\r\nHost: \r\n\r\n", H1Messages.WriteRequest("GET", "/", "").Text);

        // Host goes with an absolute-form target too (old HTTP/1.0 proxies forward only Host).
        Assert.Equal("GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n", H1Messages.WriteRequest("GET", "http://example.com/x", "example.com").Text);
        // Expect only ahead of content: without any (no framing, or a length of 0) it is left out.
        Assert.Equal("GET / HTTP/1.1\r\nHost: h\r\n\r\n", H1Messages.WriteRequest("GET", "/", "h", flags: expect).Text);
        Assert.DoesNotContain("Expect", H1Messages.WriteRequest("POST", "/", "h", flags: contentLength | expect, length: 0).Text);
        Assert.Contains("Expect: 100-continue", H1Messages.WriteRequest("POST", "/", "h", flags: chunked | expect).Text);
        // No transfer coding of the caller's: only the writer's chunked can frame a request.
        Assert.Equal(-(long)ParseError.FramingField, H1Messages.WriteRequest("PUT", "/", "h", [("Transfer-Encoding", "gzip")], chunked).Result);
    }

    /// <summary>A chunked body decodes in place, whatever the read sizes, extensions ignored.</summary>
    /// <param name="piece">Octets per read.</param>
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(7)]
    [InlineData(4096)]
    [Requirement("RFC9112-7.1-2", "RFC9112-7.1-4", "RFC9112-7.1.1-2", "RFC9112-7.1.1-4", "RFC9110-5.6.4-2", "RFC9110-5.6.4-4",
        "RFC9110-5.6.3-5#2", "RFC9112-7.1-1")]
    public void DecodesChunkedBodies(int piece)
    {
        Platform.RequireLinuxX64();
        // Extensions are skipped whatever their form: BWS around ";" and "=", a quoted-string
        // holding ";", one holding a quoted-pair (an escaped DQUOTE).
        string body = "5\r\nhello\r\n1A ; name = value;quoted=\"a;b\";pair=\"x\\\"y\"\r\nabcdefghijklmnopqrstuvwxyz\r\n001\r\n!\r\n0\r\nX-Trailer: t\r\n\r\nNEXT";
        byte[]? data = H1Messages.DecodeChunked(Encoding.Latin1.GetBytes(body), piece, out ChunkedState state, out byte[] rest);
        Assert.NotNull(data);
        Assert.Equal("helloabcdefghijklmnopqrstuvwxyz!", Encoding.Latin1.GetString(data!));
        Assert.Equal(Abi.ChunkedTrailers, state.State);
        Assert.Equal(32ul, state.Total);
        Assert.Equal("X-Trailer: t\r\n\r\nNEXT", Encoding.Latin1.GetString(rest));
    }

    /// <summary>Malformed framing is refused, and large numerals are refused rather than wrapped.</summary>
    /// <param name="body">The body.</param>
    [Theory]
    [InlineData("\r\nhello\r\n0\r\n\r\n")]
    [InlineData("g\r\n")]
    [InlineData("5\r\nhelloX\r\n0\r\n\r\n")]
    [InlineData("5\nhello\r\n0\r\n\r\n")]
    [InlineData("5;ext\nx\r\n")]
    [InlineData("5;a\u0001b\r\nhello\r\n")]
    [InlineData("8000000000000000\r\n")]
    [InlineData("10000000000000000\r\n")]
    [InlineData("-5\r\n")]
    [InlineData("5 x\r\n")]
    [Requirement("RFC9112-7.1-5", "RFC9112-7.1-2")]
    public void RefusesMalformedChunks(string body)
    {
        Platform.RequireLinuxX64();
        Assert.Null(H1Messages.DecodeChunked(Encoding.Latin1.GetBytes(body), 4096, out ChunkedState state, out _));
        Assert.Equal(Abi.ChunkedError, state.State);
    }

    /// <summary>The largest numeral below 2^63 is read; one more digit's worth is refused.</summary>
    [Fact]
    [Requirement("RFC9112-7.1-5")]
    public void ReadsLargeChunkSizes()
    {
        Platform.RequireLinuxX64();
        byte[] head = Encoding.ASCII.GetBytes("7fffffffffffffff\r\nabc");
        ChunkedState state = default;
        nuint produced;
        unsafe
        {
            fixed (byte* p = head)
            {
                long consumed = Native.H1ChunkedDecode(&state, p, (nuint)head.Length, &produced);
                Assert.Equal(head.Length, consumed);
            }
        }

        Assert.Equal(0x7fffffffffffffffUL - 3, state.Remaining);
        Assert.Equal(3ul, state.Total);
    }

    /// <summary>chunk-ext is bounded: past 4096 octets on one line, the body is refused.</summary>
    [Fact]
    [Requirement("RFC9112-7.1.1-4")]
    public void BoundsChunkExtensions()
    {
        Platform.RequireLinuxX64();
        string within = $"1;{new string('e', 4000)}\r\nx\r\n0\r\n\r\n";
        Assert.Equal("x", Encoding.Latin1.GetString(H1Messages.DecodeChunked(Encoding.Latin1.GetBytes(within), 4096, out _, out _)!));
        string beyond = $"1;{new string('e', 5000)}\r\nx\r\n0\r\n\r\n";
        Assert.Null(H1Messages.DecodeChunked(Encoding.Latin1.GetBytes(beyond), 4096, out _, out _));
    }

    /// <summary>Trailer sections: empty, with fields flagged TRAILER (kept apart from the header), or refused.</summary>
    [Fact]
    [Requirement("RFC9112-7.1.2-2", "RFC9112-7.1.2-3#2", "RFC9112-7.1.2-3#3", "RFC9110-6.5.1-3")]
    public void ParsesTrailerSections()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(2, H1Messages.ParseTrailers("\r\nNEXT", out uint none, out _));
        Assert.Equal(0u, none);
        Assert.Equal(0, H1Messages.ParseTrailers("X-A: 1\r\n", out _, out _));
        string section = "X-Checksum: abc\r\nX-Count: 3\r\n\r\n";
        Assert.Equal(section.Length, H1Messages.ParseTrailers(section + "NEXT", out uint count, out List<ParsedField> fields));
        Assert.Equal(2u, count);
        Assert.All(fields, f => Assert.Equal(Abi.FieldTrailer, f.Flags));
        Assert.Equal("abc", fields[0].Value);
        Assert.Equal(-400, H1Messages.ParseTrailers("X-A: 1\r\n folded\r\n\r\n", out _, out _));
        Assert.Equal(-400, H1Messages.ParseTrailers("X-A: 1\n\r\n", out _, out _));
    }

    /// <summary>Chunks the writer makes, the decoder reads back; trailers it refuses are not written.</summary>
    [Fact]
    [Requirement("RFC9112-7.1-2", "RFC9110-6.5.1-2")]
    public unsafe void ChunksRoundTrip()
    {
        Platform.RequireLinuxX64();
        var random = new Random(7);
        var body = new List<byte>();
        var expected = new List<byte>();
        byte[] output = new byte[70000];
        fixed (byte* o = output)
        {
            for (int i = 0; i < 20; i++)
            {
                byte[] data = new byte[random.Next(1, 65536)];
                random.NextBytes(data);
                expected.AddRange(data);
                fixed (byte* d = data)
                {
                    long written = Native.H1WriteChunk(o, (nuint)output.Length, d, (nuint)data.Length);
                    Assert.True(written > data.Length);
                    body.AddRange(output.AsSpan(0, (int)written).ToArray());
                }
            }

            Assert.Equal(-(long)ParseError.Chunk, Native.H1WriteChunk(o, (nuint)output.Length, o, 0));
            using var trailers = new NativeFields(("X-Digest", "sha-256=:abc:"));
            long last = Native.H1WriteLastChunk(o, (nuint)output.Length, trailers.Pointer, trailers.Count);
            Assert.Equal("0\r\nX-Digest: sha-256=:abc:\r\n\r\n", Encoding.Latin1.GetString(o, (int)last));
            body.AddRange(output.AsSpan(0, (int)last).ToArray());

            using var framing = new NativeFields(("Content-Length", "5"));
            Assert.Equal(-(long)ParseError.FramingField, Native.H1WriteLastChunk(o, (nuint)output.Length, framing.Pointer, framing.Count));
        }

        byte[]? decoded = H1Messages.DecodeChunked(body.ToArray(), 1000, out ChunkedState state, out byte[] rest);
        Assert.Equal(expected.ToArray(), decoded);
        Assert.Equal(Abi.ChunkedTrailers, state.State);
        Assert.Equal("X-Digest: sha-256=:abc:\r\n\r\n", Encoding.Latin1.GetString(rest));
    }
}
