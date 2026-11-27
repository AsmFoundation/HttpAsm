using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace HttpAsm.Tests;

/// <summary>What one httpasm_client_send reported, copied out of the client's buffers.</summary>
/// <param name="Result">0, -HTTPASM_ERROR_*, or -errno.</param>
/// <param name="Status">The status (0 when the call failed).</param>
/// <param name="Fields">The header fields.</param>
/// <param name="Body">The decoded body.</param>
/// <param name="Trailers">A chunked body's trailer fields.</param>
/// <param name="Flags">HTTPASM_RESPONSE_HEAD_*.</param>
internal sealed record ClientResult(int Result, int Status, IReadOnlyList<ParsedField> Fields, byte[] Body, IReadOnlyList<ParsedField> Trailers, uint Flags)
{
    /// <summary>The body as UTF-8 text.</summary>
    public string Text => Encoding.UTF8.GetString(Body);

    /// <summary>The first header field with this name (case-insensitive), or null.</summary>
    /// <param name="name">The name.</param>
    /// <returns>Its value, or null.</returns>
    public string? Field(string name) => Fields.FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;
}

/// <summary>An httpasm_client on 127.0.0.1, owned by a test.</summary>
internal sealed unsafe class AsmClient : IDisposable
{
    /// <summary>The native client.</summary>
    private nint client;

    /// <summary>Connects.</summary>
    /// <param name="port">The server's port.</param>
    /// <param name="timeoutMs">The connect and I/O timeout.</param>
    /// <exception cref="IOException">The connection failed (the message has the -errno).</exception>
    public AsmClient(int port, uint timeoutMs = 10000)
    {
        int error = 0;
        client = Native.ClientConnect(0x0100007F, (ushort)port, timeoutMs, &error);
        if (client == 0)
        {
            throw new IOException($"httpasm_client_connect: {error}");
        }
    }

    /// <summary>Sends a request and reads its response.</summary>
    /// <param name="method">The method.</param>
    /// <param name="target">The request-target.</param>
    /// <param name="body">The body (UTF-8).</param>
    /// <param name="flags">HTTPASM_REQUEST_CLOSE or _EXPECT_CONTINUE.</param>
    /// <param name="fields">The fields.</param>
    /// <returns>What the call reported.</returns>
    public ClientResult Send(string method, string target, string body = "", uint flags = 0, params (string, string)[] fields) =>
        Send(method, target, Encoding.UTF8.GetBytes(body), flags, fields);

    /// <summary>Sends a request with a binary body.</summary>
    /// <param name="method">The method.</param>
    /// <param name="target">The request-target.</param>
    /// <param name="body">The body.</param>
    /// <param name="flags">HTTPASM_REQUEST_CLOSE or _EXPECT_CONTINUE.</param>
    /// <param name="fields">The fields.</param>
    /// <returns>What the call reported.</returns>
    public ClientResult Send(string method, string target, byte[] body, uint flags = 0, params (string, string)[] fields)
    {
        using var native = new NativeFields(fields);
        byte[] m = Encoding.Latin1.GetBytes(method), t = Encoding.Latin1.GetBytes(target), a = "127.0.0.1"u8.ToArray();
        fixed (byte* mp = m)
        fixed (byte* tp = t)
        fixed (byte* ap = a)
        fixed (byte* bp = body)
        {
            var request = new HttpRequest
            {
                Method = mp, MethodLength = (uint)m.Length, Target = tp, TargetLength = (uint)t.Length,
                Authority = ap, AuthorityLength = (uint)a.Length, Fields = native.Pointer, FieldCount = native.Count, Flags = flags,
            };
            ClientResponse response;
            int result = Native.ClientSend(client, &request, bp, (nuint)body.Length, &response);
            if (result != 0)
            {
                return new ClientResult(result, 0, [], [], [], 0);
            }

            var head = new List<ParsedField>();
            for (int i = 0; i < response.Head.FieldCount; i++)
            {
                head.Add(Copy(response.Head.Fields[i]));
            }

            var trailers = new List<ParsedField>();
            for (int i = 0; i < response.TrailerCount; i++)
            {
                trailers.Add(Copy(response.Trailers[i]));
            }

            return new ClientResult(0, response.Head.Status, head, new ReadOnlySpan<byte>(response.Body, (int)response.BodyLength).ToArray(), trailers, response.Head.Flags);
        }
    }

    /// <summary>Closes the client.</summary>
    public void Dispose()
    {
        Native.ClientClose(client);
        client = 0;
    }

    /// <summary>Copies a field record.</summary>
    /// <param name="f">The record.</param>
    /// <returns>The copy.</returns>
    private static ParsedField Copy(HttpField f) =>
        new(Encoding.Latin1.GetString(f.Name, (int)f.NameLength), Encoding.Latin1.GetString(f.Value, (int)f.ValueLength), f.Id, f.Flags);
}

/// <summary>
/// A canned server: each connection gets the octets a test scripts, exactly, so the client can be
/// tried on what well-behaved servers never send (interim responses, trailers, obs-fold, a body
/// that ends at the close, a close in the middle of a body, silence).
/// </summary>
internal sealed class CannedServer : IDisposable
{
    /// <summary>
    /// Inside an answer, a pause: the octets before it are sent, then 100 ms pass before the
    /// rest, so the client reads them apart (U+0001 never occurs in a canned answer otherwise).
    /// </summary>
    public const string Pause = "\u0001";

    /// <summary>The listener on 127.0.0.1.</summary>
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);

    /// <summary>Serves one connection.</summary>
    private readonly Task serving;

    /// <summary>Accepts one connection, reads one request head, sends each answer in turn (one
    /// per request), and closes when told to.</summary>
    /// <param name="answers">The octets for each request, in order.</param>
    /// <param name="close">Close after the last answer (true) or keep the connection open.</param>
    /// <param name="after">Octets sent 200 ms after the last answer, when no request is
    /// outstanding (null or empty: none): what a client must never take for a response.</param>
    /// <remarks>
    /// An answer may hold <see cref="Pause"/>s: it is sent in pieces, 100 ms apart.
    /// The server runs on a thread of its own (LongRunning), not the thread pool: under load
    /// (the coverage run's instrumented build, tests in parallel) a pool task started after the
    /// test had ended and Dispose had stopped the listener, and its AcceptSocket then threw
    /// "Not listening" (CI, 2026-11-26). A listener stopped before any client was accepted ends
    /// the server quietly: the client never needed the accept (the kernel completes the
    /// handshake from the backlog), so there was nothing to serve.
    /// Its socket sends without Nagle's delay (NoDelay), and <see cref="Settled"/> says when its
    /// last act is done. A test that waited a fixed time for the later octets lost the race now
    /// and then (1 run in 6, WSL, 2026-11-26): the client took them for the next answer.
    /// </remarks>
    public CannedServer(IReadOnlyList<string> answers, bool close, string? after = null)
    {
        listener.Start();
        serving = Task.Factory.StartNew(() =>
        {
            Socket accepted;
            try
            {
                accepted = listener.AcceptSocket();
            }
            catch (Exception e) when (e is InvalidOperationException or SocketException or ObjectDisposedException)
            {
                Settled.Set();
                return;                                                 // stopped before a client came
            }

            using (Socket socket = accepted)
            {
                socket.NoDelay = true;                                  // each Send leaves at once
                byte[] buffer = new byte[65536];
                try
                {
                    foreach (string answer in answers)
                    {
                        ReadHead(socket, buffer);
                        string[] pieces = answer.Split(Pause);
                        for (int i = 0; i < pieces.Length; i++)
                        {
                            if (i > 0)
                            {
                                Thread.Sleep(100);                      // the client reads what came so far
                            }

                            socket.Send(Encoding.Latin1.GetBytes(pieces[i]));
                        }
                    }

                    if (!string.IsNullOrEmpty(after))
                    {
                        Thread.Sleep(200);
                        socket.Send(Encoding.Latin1.GetBytes(after));
                    }
                }
                catch (SocketException)
                {
                    // The client went away before the script's end (a test that failed, or one
                    // whose client closes on purpose): nothing more to serve. Throwing here would
                    // fault the task, and Dispose's wait would hide the test's own failure.
                    Settled.Set();
                    return;
                }

                if (!close)
                {
                    Settled.Set();                                      // all sent; the connection stays
                    Thread.Sleep(3000);
                }
            }

            Settled.Set();                                              // closed (a second Set is harmless)
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    /// <summary>The port.</summary>
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

    /// <summary>
    /// Set once the server's last act is done: the later octets sent (the connection kept), or
    /// the connection closed. A test waits on it instead of guessing how long that takes.
    /// </summary>
    public ManualResetEventSlim Settled { get; } = new();

    /// <summary>Stops listening, and waits for the server to finish (5 s at most).</summary>
    public void Dispose()
    {
        listener.Stop();
        if (serving.Wait(TimeSpan.FromSeconds(5)))
        {
            Settled.Dispose();                                          // only once nothing can Set it
        }
    }

    /// <summary>Reads until a request head's end (CRLF CRLF), and the body its Content-Length names.</summary>
    /// <param name="socket">The connection.</param>
    /// <param name="buffer">Scratch.</param>
    private static void ReadHead(Socket socket, byte[] buffer)
    {
        int length = 0;
        int end;
        while ((end = buffer.AsSpan(0, length).IndexOf("\r\n\r\n"u8)) < 0)
        {
            int n = socket.Receive(buffer, length, buffer.Length - length, SocketFlags.None);
            if (n == 0)
            {
                return;
            }

            length += n;
        }

        string head = Encoding.Latin1.GetString(buffer, 0, end);
        int at = head.IndexOf("Content-Length: ", StringComparison.OrdinalIgnoreCase);
        int body = at < 0 ? 0 : int.Parse(head.AsSpan(at + 16).ToString().Split('\r')[0], System.Globalization.CultureInfo.InvariantCulture);
        for (int have = length - end - 4; have < body;)
        {
            have += socket.Receive(buffer, 0, buffer.Length, SocketFlags.None);
        }
    }
}

/// <summary>
/// The C ABI's client: one blocking HTTP/1.1 connection, against HttpAsm's own server, against
/// a canned server's unusual answers, and against Kestrel (ASP.NET Core), an independent
/// implementation.
/// </summary>
public sealed class ClientTests
{
    /// <summary>The response structure has the library's size.</summary>
    [Fact]
    public void ResponseMatchesTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(96, Unsafe.SizeOf<ClientResponse>());
        Assert.Equal((uint)Unsafe.SizeOf<ClientResponse>(), Native.StructSize(9));
    }

    /// <summary>
    /// Requests on one connection to HttpAsm's server, answered in order: a GET, a POST whose body
    /// comes back, a HEAD (no body read, though Content-Length names one: the client keeps the
    /// request in mind while it reads the answer), a 300 KB answer (the client's input grows and
    /// moves under a parsed head); then Connection: close ends it and the next call says
    /// -ENOTCONN. On the way the client shows its manners: one persistent connection (it never
    /// needs to say close), each answer read whole before the next request, every body framed
    /// by a valid Content-Length (never chunked, never a Transfer-Encoding), a final CRLF counted
    /// in it, and no more requests after the server's close.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.3-6", "RFC9112-9.6-5#1", "RFC9112-9.6-5#2", "RFC9110-8.6-5#1", "RFC9110-8.6-5#2", "RFC9110-6-6",
        "RFC9112-9.3-4", "RFC9112-9.3-7#2", "RFC9112-9.6-8#1", "RFC9112-6.3-6", "RFC9112-6.1-13#1", "RFC9112-6.3-7#2", "RFC9112-2.2-5#2",
        "RFC9112-6-2")]
    public void TalksToHttpAsm()
    {
        Platform.RequireLinuxX64();
        byte[] big = new byte[300_000];
        new Random(3).NextBytes(big);
        using var server = new TestServer(x => x.Respond(200, x.Target == "/big" ? big : Encoding.UTF8.GetBytes(x.Method + " " + x.Target + " " + Encoding.UTF8.GetString(x.Body) + " " + (x.Field("Content-Length") ?? "-"))));
        using var client = new AsmClient(server.Port);

        Assert.Equal("GET /a  -", client.Send("GET", "/a").Text);
        Assert.Equal("POST /b hello 5", client.Send("POST", "/b", "hello").Text);
        Assert.Equal("POST /c  0", client.Send("POST", "/c").Text);           // a POST names its empty body
        Assert.Equal("PUT /p  0", client.Send("PUT", "/p").Text);             // so do PUT and PATCH (RFC9110-8.6-5#1)
        Assert.Equal("PATCH /q  0", client.Send("PATCH", "/q").Text);
        Assert.Equal("POST /g line\r\n 6", client.Send("POST", "/g", "line\r\n").Text);   // a final CRLF counts in the length
        ClientResult head = client.Send("HEAD", "/d");
        Assert.Equal(200, head.Status);
        Assert.Empty(head.Body);
        Assert.Equal("10", head.Field("Content-Length"));                       // what GET would have sent
        ClientResult large = client.Send("GET", "/big");
        Assert.True(big.AsSpan().SequenceEqual(large.Body));
        ClientResult closing = client.Send("GET", "/e", "", 0x0080);           // HTTPASM_REQUEST_CLOSE
        Assert.Equal("GET /e  -", closing.Text);
        Assert.Equal("close", closing.Field("Connection"));
        Assert.Equal(-107, client.Send("GET", "/f").Result);                   // -ENOTCONN
    }

    /// <summary>
    /// What a canned server sends: an interim 100 is skipped for the final answer; a chunked body
    /// is decoded with its trailers kept apart; an HTTP/1.0 answer without a length ends at the
    /// close (and ends the connection); an obs-folded field is joined with a space.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-15.2-3#1", "RFC9112-7.1-4", "RFC9112-7.1.2-3#2", "RFC9112-5.2-6", "RFC9110-15.2-3#2", "RFC9110-10.1.1-11.3#1",
        "RFC9110-10.1.1-11.3#2", "RFC9112-7.1.2-3#1", "RFC9110-15-4", "RFC9110-15-6", "RFC9112-4-9#1")]
    public void ReadsEveryFraming()
    {
        Platform.RequireLinuxX64();
        string[] answers =
        [
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 199 Unknown Interim\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 42\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX-Folded: a\r\n  b\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 299 \r\nContent-Length: 3\r\n\r\n299",
            "HTTP/1.1 600 Beyond\r\nContent-Length: 3\r\n\r\n600",
            "HTTP/1.1 099 Below\r\nContent-Length: 3\r\n\r\n099",
            "HTTP/1.1 200 Not\tOK at all, café\r\nContent-Length: 4\r\n\r\nsame",
            "HTTP/1.0 200 OK\r\n\r\nto the close",
        ];
        using var server = new CannedServer(answers, close: true);
        using var client = new AsmClient(server.Port);

        // Expect: 100-continue, yet the body goes at once (the client does not wait for the 100),
        // and every 1xx before the final answer, known or not, is passed over.
        Assert.Equal("ok", client.Send("POST", "/", "x", 0x0008).Text);        // HTTPASM_REQUEST_EXPECT_CONTINUE
        ClientResult chunked = client.Send("GET", "/");
        Assert.Equal("hello world", chunked.Text);
        Assert.Equal("42", Assert.Single(chunked.Trailers).Value);            // trailers kept, apart
        Assert.Null(chunked.Field("X-Sum"));
        Assert.Equal("a    b", client.Send("GET", "/").Field("X-Folded"));    // CR LF become SP SP (RFC 9112 5.2)
        // Codes the client does not know are taken by their class (299: a 2xx), and invalid ones
        // (600, 099) as final answers framed like a 5xx's; the reason phrase changes nothing.
        ClientResult unknown = client.Send("GET", "/");
        Assert.Equal((299, "299"), (unknown.Status, unknown.Text));
        ClientResult beyond = client.Send("GET", "/");
        Assert.Equal((600, "600"), (beyond.Status, beyond.Text));
        ClientResult below = client.Send("GET", "/");
        Assert.Equal((99, "099"), (below.Status, below.Text));
        Assert.Equal("same", client.Send("GET", "/").Text);
        Assert.Equal("to the close", client.Send("GET", "/").Text);
        Assert.Equal(-107, client.Send("GET", "/").Result);
    }

    /// <summary>
    /// A chunked answer's trailers take the client's field records the head left
    /// (HTTPASM_CLIENT_FIELDS, 256): after a head of one field, 255 trailer fields are read whole
    /// and 256 are refused with -HTTPASM_ERROR_TOO_MANY_FIELDS. A malformed trailer line is
    /// refused with its own rule. The client returned a parser's status there (-431, -400) until
    /// 2026-11-27, against its contract (-HTTPASM_ERROR_* for an invalid response):
    /// tests/fuzz/client's 10-minute campaign found its oracle allowing the trailers only the
    /// head's 128 records, and the oracle also took any result below -37 for I/O.
    /// </summary>
    /// <param name="trailers">How many trailer fields the answer carries.</param>
    /// <param name="extra">A last trailer line, or empty.</param>
    /// <param name="result">0, or the -HTTPASM_ERROR_* expected.</param>
    [Theory]
    [InlineData(255, "", 0)]
    [InlineData(256, "", -(int)ParseError.TooManyFields)]
    [InlineData(1, "Bad Name: x\r\n", -(int)ParseError.WhitespaceBeforeColon)]
    [InlineData(1, "X-Folded: a\r\n b\r\n", -(int)ParseError.ObsFold)]
    [InlineData(1, "X-Bare: a\n", -(int)ParseError.BareLf)]
    public void BoundsTrailersByTheClientsRecords(int trailers, string extra, int result)
    {
        Platform.RequireLinuxX64();
        string answer = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"
            + string.Concat(Enumerable.Range(0, trailers).Select(i => $"X-T{i}: {i}\r\n")) + extra + "\r\n";
        using var server = new CannedServer([answer], close: true);
        using var client = new AsmClient(server.Port);
        ClientResult r = client.Send("GET", "/");
        Assert.Equal(result, r.Result);
        if (result == 0)
        {
            Assert.Equal("ok", r.Text);
            Assert.Equal(trailers, r.Trailers.Count);
            Assert.Equal("254", r.Trailers[^1].Value);
        }
    }

    /// <summary>
    /// Failures close the connection: an invalid status-line, a server that closes in the middle
    /// of a body (incomplete: RFC9112-6.3-2.6, reported as a failure, never as a response that
    /// looks complete), a server that never answers (the timeout), and a 101 (Switching
    /// Protocols) to a request that asked for no upgrade. A 101 is no interim answer to skip:
    /// after it the connection speaks another protocol (RFC 9110 15.2.2), one a server must not
    /// switch to unasked (RFC9110-7.8-5#3), so the octets after it are not this client's to read
    /// as HTTP/1.1 (-HTTPASM_ERROR_STATUS, 25). The fuzzer's oracle once skipped it as an
    /// interim answer, and CI's fuzzing caught the difference (2026-11-26, the seed
    /// tests/fuzz/seeds/client/switching-protocols). A Content-Length of 5.7 GB followed by five
    /// octets and the close is that close in a body: the client grows its input as octets
    /// arrive, and never asks for the named size up front (it did: tests/fuzz/client's CI run
    /// of 2026-11-26 reported "malloc(5777777824)"; the seed huge-content-length keeps the
    /// fuzzer's memory limit on it). And a server that stalls inside each framing - a length,
    /// a chunk, the trailers, a body delimited by the close - fails it with the timeout.
    /// </summary>
    /// <param name="answer">The canned server's answer.</param>
    /// <param name="close">Whether it closes after it.</param>
    /// <param name="result">The result expected.</param>
    [Theory]
    [InlineData("HTTP/1.1 2000 OK\r\n\r\n", true, -400)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", true, -104)]
    [InlineData("", false, -110)]
    [InlineData("HTTP/1.1 101 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true, -25)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 5777777777\r\n\r\nhello", true, -104)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", false, -110)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", false, -110)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: 1\r\n", false, -110)]
    [InlineData("HTTP/1.0 200 OK\r\n\r\nto the close, which never comes", false, -110)]
    [Requirement("RFC9112-6.3-2.6", "RFC9112-6.3-2.5#4", "RFC9112-8-2", "RFC9110-7.8-5#3")]
    public void ClosesOnFailures(string answer, bool close, int result)
    {
        Platform.RequireLinuxX64();
        using var server = new CannedServer([answer], close);
        using var client = new AsmClient(server.Port, timeoutMs: 500);

        int got = client.Send("GET", "/").Result;

        Assert.True(got == result || (result == -400 && got < 0), $"expected {result}, got {got}");
        Assert.Equal(-107, client.Send("GET", "/").Result);
    }

    /// <summary>
    /// Octets no request asked for are never taken for a response: with one request outstanding
    /// at a time, nothing the server sends outside a response answers anything. Octets right
    /// after a response close the connection once that response is returned (they are
    /// discarded); octets that come while the client is idle fail the next send with -EPROTO,
    /// before it is sent; and an idle connection the server closed fails it with -ECONNRESET,
    /// also before it is sent (so it may be retried elsewhere). The connection is closed after
    /// each (-ENOTCONN).
    /// </summary>
    /// <param name="answer">The canned answer to the first request.</param>
    /// <param name="later">Sent 200 ms after it ("": nothing; null: the server closes instead).</param>
    /// <param name="second">The second send's result.</param>
    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad", "", -107)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad", -71)]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", null, -104)]
    [Requirement("RFC9112-9.2-3#1", "RFC9112-9.2-3#2", "RFC9112-6.3-8#1", "RFC9112-6.3-8#2")]
    public void NeverTakesUnsolicitedOctetsForAResponse(string answer, string? later, int second)
    {
        Platform.RequireLinuxX64();
        using var server = new CannedServer([answer], close: later is null, after: later);
        using var client = new AsmClient(server.Port, timeoutMs: 2000);

        ClientResult first = client.Send("GET", "/");
        Assert.Equal((0, 200, "ok"), (first.Result, first.Status, first.Text));
        Assert.True(server.Settled.Wait(5000, TestContext.Current.CancellationToken), "the canned server did not finish");
        Thread.Sleep(50);                                           // loopback delivery: what came has arrived

        Assert.Equal(second, client.Send("GET", "/").Result);
        Assert.Equal(-107, client.Send("GET", "/").Result);
    }

    /// <summary>
    /// Kestrel (ASP.NET Core) as the server: a fixed-length answer, a chunked one written in
    /// pieces (its length unknown to Kestrel), and an echoed POST body, on one connection.
    /// </summary>
    /// <returns>The test.</returns>
    [Fact]
    public async Task TalksToKestrel()
    {
        Platform.RequireLinuxX64();
        var ct = TestContext.Current.CancellationToken;
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        await using var app = builder.Build();
        app.MapGet("/fixed", () => "fixed answer");
        app.MapGet("/chunked", async (HttpContext context) =>
        {
            for (int i = 0; i < 5; i++)
            {
                await context.Response.WriteAsync(FormattableString.Invariant($"part{i};"), context.RequestAborted);
                await context.Response.Body.FlushAsync(context.RequestAborted);
            }
        });
        app.MapPost("/echo", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            await context.Response.WriteAsync("echo:" + await reader.ReadToEndAsync(context.RequestAborted), context.RequestAborted);
        });
        await app.StartAsync(ct);
        int port = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First()).Port;

        using var client = new AsmClient(port);
        Assert.Equal("fixed answer", client.Send("GET", "/fixed").Text);
        ClientResult chunked = client.Send("GET", "/chunked");
        Assert.Equal("part0;part1;part2;part3;part4;", chunked.Text);
        Assert.NotEqual(0u, chunked.Flags & 0x0002);                            // HTTPASM_RESPONSE_HEAD_CHUNKED
        Assert.Equal("echo:hello kestrel", client.Send("POST", "/echo", "hello kestrel").Text);

        await app.StopAsync(ct);
    }

    /// <summary>
    /// Answers that arrive in pieces are read across reads, whatever the framing: a body
    /// delimited by the close, a chunk's data split between two reads (the second read is all
    /// data, no framing), and a trailer section that comes after a pause. And a chunked body of
    /// 300 KB with a trailer, longer than the client's first input buffer (16 KiB): the input
    /// grows while the length is unknown, and the head's and the trailers' pointers follow it
    /// when it moves.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-7.1-4", "RFC9112-7.1.2-3#2")]
    public void ReadsAnswersThatArriveInPieces()
    {
        Platform.RequireLinuxX64();
        string big = string.Concat(Enumerable.Range(0, 300).Select(i => new string((char)('a' + i % 26), 1000)));
        string[] answers =
        [
            $"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n01234567{CannedServer.Pause}89abcdef\r\n0\r\n\r\n",
            $"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n{CannedServer.Pause}X-Late: 1\r\n\r\n",
            $"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{big.Length:x}\r\n{big}\r\n0\r\nX-Sum: 300\r\n\r\n",
            $"HTTP/1.0 200 OK\r\nX-Kept: yes\r\n\r\nfirst{CannedServer.Pause} second",
        ];
        using var server = new CannedServer(answers, close: true);
        using var client = new AsmClient(server.Port);

        Assert.Equal("0123456789abcdef", client.Send("GET", "/").Text);
        ClientResult late = client.Send("GET", "/");
        Assert.Equal(("hello", "1"), (late.Text, Assert.Single(late.Trailers).Value));
        ClientResult large = client.Send("GET", "/");
        Assert.Equal(big, large.Text);
        Assert.Equal("300", Assert.Single(large.Trailers).Value);
        Assert.Equal("chunked", large.Field("Transfer-Encoding"));             // the head, re-parsed after the move
        ClientResult closing = client.Send("GET", "/");
        Assert.Equal(("first second", "yes"), (closing.Text, closing.Field("X-Kept")));
        Assert.Equal(-107, client.Send("GET", "/").Result);
    }

    /// <summary>
    /// A 2xx to CONNECT makes the connection a tunnel (RFC 9110 9.3.6): the answer is returned
    /// with no body, its Content-Length ignored (RFC9110-9.3.6-12#2: what follows is the
    /// tunnel's), and the connection is no longer the client's to use for HTTP (-ENOTCONN),
    /// whether the tunnel's first octets came with the head or not yet. Without them the client
    /// used to keep the connection as an idle HTTP/1.1 one (the head also says NO_BODY, which it
    /// checked first), and the next request went into the tunnel.
    /// </summary>
    /// <param name="answer">The canned answer: the head, with or without tunnel octets after it.</param>
    [Theory]
    [InlineData("HTTP/1.1 200 Connection Established\r\nContent-Length: 5\r\n\r\ntunnel octets")]
    [InlineData("HTTP/1.1 200 Connection Established\r\n\r\n")]
    [Requirement("RFC9110-9.3.6-12#2", "RFC9112-6.3-2.2")]
    public void HandsOverATunnel(string answer)
    {
        Platform.RequireLinuxX64();
        using var server = new CannedServer([answer], close: false);
        using var client = new AsmClient(server.Port);

        ClientResult tunnel = client.Send("CONNECT", "example.com:443");

        Assert.Equal((0, 200, ""), (tunnel.Result, tunnel.Status, tunnel.Text));
        Assert.Equal(-107, client.Send("GET", "/").Result);
    }

    /// <summary>
    /// A client that asked to close (HTTPASM_REQUEST_CLOSE) closes after the answer even when
    /// the server's answer would keep the connection (RFC9112-9.6-5#2: it sends no further
    /// request on it).
    /// </summary>
    [Fact]
    [Requirement("RFC9112-9.6-5#2")]
    public void ClosesAfterAskingToEvenWhenTheServerWouldKeepIt()
    {
        Platform.RequireLinuxX64();
        using var server = new CannedServer(["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"], close: false);
        using var client = new AsmClient(server.Port);

        Assert.Equal("ok", client.Send("GET", "/", "", 0x0080).Text);          // HTTPASM_REQUEST_CLOSE
        Assert.Equal(-107, client.Send("GET", "/").Result);
    }

    /// <summary>
    /// A request the writer refuses (a method with a space) is -HTTPASM_ERROR_METHOD with
    /// nothing sent, and the connection stays usable; a head larger than the client's first
    /// output buffer (4 KiB; fields of 8 KB here) is written whole, the buffer grown.
    /// </summary>
    [Fact]
    public void RefusesWhatItCannotWriteAndGrowsForWhatItCan()
    {
        Platform.RequireLinuxX64();
        using var server = new TestServer(x => x.Respond(200, x.Fields.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        using var client = new AsmClient(server.Port);

        Assert.Equal(-(int)ParseError.Method, client.Send("G T", "/").Result);
        (string, string)[] fields = [.. Enumerable.Range(0, 8).Select(i => ($"X-Large-{i}", new string('v', 1000)))];
        Assert.Equal("9", client.Send("GET", "/", "", 0, fields).Text);         // Host and the eight
    }

    /// <summary>
    /// A request larger than the socket takes at once is sent across several sendmsg calls:
    /// an 8 MiB head (one field) to a server reading at most 64 KiB every 20 ms for its first 4
    /// MiB, with a 500 ms timeout, so the first calls time out having sent part of the head and
    /// the next one goes on from there; the server then reads the rest at full speed and answers. A server that reads nothing fails the
    /// send with -ETIMEDOUT once the timeout passes with nothing sent.
    /// </summary>
    /// <remarks>
    /// The listener's receive buffer is 64 KiB (accepted sockets inherit it): loopback
    /// otherwise autotunes both ends' buffers to megabytes, enough to take most of the head
    /// with the server reading nothing - no call would be cut short - and enough left in them
    /// at the end that draining them outlasted the client's receive timeout.
    /// </remarks>
    /// <returns>A task.</returns>
    [Fact]
    public async Task SendsWhatTheSocketTakesAndTimesOutOnWhatItWillNot()
    {
        Platform.RequireLinuxX64();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Server.ReceiveBufferSize = 64 << 10;
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        long headLength = 0;
        using var stalledDone = new ManualResetEventSlim();        // the silent connection's end
        Task serving = Task.Factory.StartNew(() =>
        {
            using Socket slow = listener.AcceptSocket();
            byte[] buffer = new byte[256 << 10];
            var tail = new List<byte>();
            while (true)
            {
                int n = slow.Receive(buffer);
                if (n == 0)
                {
                    return;
                }

                Interlocked.Add(ref headLength, n);                     // read by the test's thread
                tail.AddRange(buffer.AsSpan(0, n).ToArray());
                if (tail.Count > 4)
                {
                    tail.RemoveRange(0, tail.Count - 4);
                }

                if (tail.SequenceEqual("\r\n\r\n"u8.ToArray()))
                {
                    slow.Send("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nsent"u8);
                    using Socket silent = listener.AcceptSocket();     // the second client: never read
                    stalledDone.Wait(TimeSpan.FromSeconds(10));        // open until its send has failed
                    return;
                }

                // Slowly for the head's first 4 MiB (at most 64 KiB per 20 ms: the first send
                // calls time out with part of it sent), then at full speed, so what the buffers
                // hold at the end drains well within the client's receive timeout.
                if (Interlocked.Read(ref headLength) < 4 << 20)
                {
                    Thread.Sleep(20);
                }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        using (var client = new AsmClient(port, timeoutMs: 500))
        {
            ClientResult huge = client.Send("GET", "/", "", 0, ("X-Huge", new string('h', 8 << 20)));
            Assert.Equal((0, "sent"), (huge.Result, huge.Text));
            Assert.True(Interlocked.Read(ref headLength) > 8 << 20);
        }

        using (var stalled = new AsmClient(port, timeoutMs: 300))
        {
            Assert.Equal(-110, stalled.Send("POST", "/", new byte[64 << 20]).Result);   // -ETIMEDOUT
        }

        stalledDone.Set();
        listener.Stop();
        await serving.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }
}
