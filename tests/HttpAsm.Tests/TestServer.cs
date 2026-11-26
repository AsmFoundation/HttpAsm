using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// One request as a handler sees it through the C ABI, with managed copies of what the tests
/// read, and the two ways to answer it.
/// </summary>
internal sealed unsafe class Exchange
{
    /// <summary>The native exchange.</summary>
    private readonly nint pointer;

    /// <summary>Copies the request, its body and trailers while they are valid.</summary>
    /// <param name="pointer">The native exchange.</param>
    public Exchange(nint pointer)
    {
        this.pointer = pointer;
        HttpRequest* r = Native.ExchangeRequest(pointer);
        Method = Encoding.Latin1.GetString(r->Method, (int)r->MethodLength);
        Target = Encoding.Latin1.GetString(r->Target, (int)r->TargetLength);
        Authority = r->Authority == null ? null : Encoding.Latin1.GetString(r->Authority, (int)r->AuthorityLength);
        Scheme = r->Scheme == null ? null : Encoding.Latin1.GetString(r->Scheme, (int)r->SchemeLength);
        Version = r->Version;
        Flags = r->Flags;
        var fields = new List<ParsedField>();
        for (int i = 0; i < r->FieldCount; i++)
        {
            fields.Add(Copy(r->Fields[i]));
        }

        Fields = fields;
        nuint length;
        byte* body = Native.ExchangeBody(pointer, &length);
        Body = new ReadOnlySpan<byte>(body, (int)length).ToArray();
        uint count;
        HttpField* trailers = Native.ExchangeTrailers(pointer, &count);
        Trailers = Enumerable.Range(0, (int)count).Select(i => Copy(trailers[i])).ToList();
    }

    /// <summary>The method.</summary>
    public string Method { get; }

    /// <summary>The request-target.</summary>
    public string Target { get; }

    /// <summary>The authority, or null.</summary>
    public string? Authority { get; }

    /// <summary>An absolute-form target's scheme (HTTP/2: :scheme), or null.</summary>
    public string? Scheme { get; }

    /// <summary>10 or 11.</summary>
    public int Version { get; }

    /// <summary>HTTPASM_REQUEST_*.</summary>
    public uint Flags { get; }

    /// <summary>The header fields.</summary>
    public IReadOnlyList<ParsedField> Fields { get; }

    /// <summary>The decoded body.</summary>
    public byte[] Body { get; }

    /// <summary>The trailer fields.</summary>
    public IReadOnlyList<ParsedField> Trailers { get; }

    /// <summary>The value of the first field with this name (case-insensitive), or null.</summary>
    /// <param name="name">The name.</param>
    /// <returns>The value, or null.</returns>
    public string? Field(string name) => Fields.FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;

    /// <summary>Answers (inside the handler, or from any thread after <see cref="Defer"/>).</summary>
    /// <param name="status">The status.</param>
    /// <param name="body">The body, as UTF-8 text.</param>
    /// <param name="fields">The fields.</param>
    /// <returns>0, or the library's negative error.</returns>
    public int Respond(int status, string body = "", params (string, string)[] fields) => Respond(status, Encoding.UTF8.GetBytes(body), fields);

    /// <summary>Answers with a binary body.</summary>
    /// <param name="status">The status.</param>
    /// <param name="body">The body.</param>
    /// <param name="fields">The fields.</param>
    /// <returns>0, or the library's negative error.</returns>
    public int Respond(int status, byte[] body, params (string, string)[] fields)
    {
        using var native = new NativeFields(fields);
        fixed (byte* b = body)
        {
            return Native.ExchangeRespond(pointer, (ushort)status, native.Pointer, native.Count, b, (nuint)body.Length);
        }
    }

    /// <summary>Defers the answer: the handler returns, and <see cref="Respond(int, string, (string, string)[])"/> comes later.</summary>
    /// <returns>0, or -EINVAL outside the handler.</returns>
    public int Defer() => Native.ExchangeDefer(pointer);

    /// <summary>
    /// The native exchange, for a test that calls the C ABI itself (a NULL argument, say).
    /// </summary>
    /// <remarks>Valid only while the exchange is: inside the handler, or until a deferred
    /// exchange is answered. A test must not use it after that.</remarks>
    public nint Pointer => pointer;

    /// <summary>Copies one field record.</summary>
    /// <param name="f">The record.</param>
    /// <returns>The copy.</returns>
    private static ParsedField Copy(HttpField f) =>
        new(Encoding.Latin1.GetString(f.Name, (int)f.NameLength), Encoding.Latin1.GetString(f.Value, (int)f.ValueLength), f.Id, f.Flags);
}

/// <summary>
/// An HttpAsm server in this test process, on 127.0.0.1 and a port the kernel chooses, whose
/// handler is a managed delegate. The native workers call <see cref="OnRequest"/> directly.
/// </summary>
internal sealed unsafe class TestServer : IDisposable
{
    /// <summary>127.0.0.1 in network byte order.</summary>
    private const uint Loopback = 0x0100007F;

    /// <summary>Keeps this object reachable from the native context pointer.</summary>
    private GCHandle self;

    /// <summary>The native server.</summary>
    private nint server;

    /// <summary>The managed handler.</summary>
    private readonly Action<Exchange> handler;

    /// <summary>
    /// Whether this test run asks every server for io_uring: HTTPASM_TEST_IO=uring. A run is
    /// made once with each backend (tests/run-linux.sh, CI): epoll, the default, then io_uring,
    /// so every test proves both.
    /// </summary>
    public static bool UringRun => Environment.GetEnvironmentVariable("HTTPASM_TEST_IO") == "uring";

    /// <summary>
    /// Whether this machine is known to allow io_uring (HTTPASM_REQUIRE_URING=1: WSL, a Linux
    /// host, CI; not Docker, whose seccomp refuses it), so a server that asks for it and comes
    /// up on epoll is a failure, not a fallback.
    /// </summary>
    public static bool RequireUring => Environment.GetEnvironmentVariable("HTTPASM_REQUIRE_URING") == "1";

    /// <summary>Creates and starts a server.</summary>
    /// <param name="handler">Called for each request, on a worker thread.</param>
    /// <param name="workers">Worker threads.</param>
    /// <param name="idleMs">The idle timeout (0: the default).</param>
    /// <param name="maxBody">The body limit (0: the default).</param>
    /// <param name="limits">The heads' limits.</param>
    /// <param name="flags">HTTPASM_SERVER_* (<see cref="ServerIo.AskUring"/> is added in an
    /// io_uring run: <see cref="UringRun"/>).</param>
    /// <param name="minDataRate">Octets a second a transfer keeps to outlive the idle timeout
    /// (0: the library's default, 240).</param>
    /// <exception cref="InvalidOperationException">The server could not be created or started, or an io_uring run
    /// (<see cref="UringRun"/>) that requires io_uring (<see cref="RequireUring"/>) did not get it for every worker.</exception>
    public TestServer(Action<Exchange> handler, uint workers = 2, uint idleMs = 0, ulong maxBody = 0, H1Limits limits = default, ushort flags = 0,
        uint minDataRate = 0)
    {
        this.handler = handler;
        self = GCHandle.Alloc(this);
        var options = new ServerOptions
        {
            Handler = (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&OnRequest,
            Context = GCHandle.ToIntPtr(self),
            Workers = workers,
            IdleTimeoutMs = idleMs,
            MaxBody = maxBody,
            BindAddress = Loopback,
            Limits = limits,
            Flags = (ushort)(flags | (UringRun ? ServerIo.AskUring : 0)),
            MinDataRate = minDataRate,
        };
        int error = 0;
        server = Native.ServerCreate(&options, &error);
        if (server == 0)
        {
            self.Free();
            throw new InvalidOperationException($"httpasm_server_create: {error}");
        }

        int started = Native.ServerStart(server);
        if (started != 0)
        {
            Native.ServerDestroy(server);
            self.Free();
            throw new InvalidOperationException($"httpasm_server_start: {started}");
        }

        // An io_uring run must run on io_uring wherever it is known to be allowed: a server that
        // fell back silently would make the run prove epoll twice and io_uring never.
        uint io = Native.ServerIoUsed(server);
        if (UringRun && RequireUring && io != ServerIo.Uring)
        {
            Native.ServerDestroy(server);
            self.Free();
            throw new InvalidOperationException(
                $"HTTPASM_TEST_IO=uring and HTTPASM_REQUIRE_URING=1, but httpasm_server_io says {io} ({Platform.IoUringBudget()})");
        }

        Port = Native.ServerPort(server);
    }

    /// <summary>The port the server listens on.</summary>
    public int Port { get; }

    /// <summary>What its workers use now: <see cref="ServerIo.Uring"/>, <see cref="ServerIo.Epoll"/>,
    /// <see cref="ServerIo.Mixed"/> (the kernel refused some workers' rings), or
    /// <see cref="ServerIo.None"/> while stopped.</summary>
    public uint Io => Native.ServerIoUsed(server);

    /// <summary>The base address for HttpClient.</summary>
    public Uri Address => new($"http://127.0.0.1:{Port}/");

    /// <summary>How many requests the handler threw on (answered 500 by the harness).</summary>
    public int HandlerFailures;

    /// <summary>Stops the server (the workers finish what is in flight) and frees it.</summary>
    public void Dispose()
    {
        if (server != 0)
        {
            Native.ServerDestroy(server);
            server = 0;
            self.Free();
        }
    }

    /// <summary>Stops the server without freeing it (in-flight exchanges finish first).</summary>
    public void Stop() => Native.ServerStop(server);

    /// <summary>Starts the server again after <see cref="Stop"/>, on the same port.</summary>
    /// <returns>0, or -errno: -EINVAL when it runs already.</returns>
    public int Start() => Native.ServerStart(server);

    /// <summary>The native handler: finds this server and runs the managed one.</summary>
    /// <param name="context">The GCHandle.</param>
    /// <param name="exchange">The native exchange.</param>
    /// <remarks>An exception must never unwind into the worker's assembly: it is caught, and the
    /// request answered 500 here.</remarks>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnRequest(nint context, nint exchange)
    {
        var server = (TestServer)GCHandle.FromIntPtr(context).Target!;
        try
        {
            server.handler(new Exchange(exchange));
        }
        catch (Exception)
        {
            Interlocked.Increment(ref server.HandlerFailures);
            Native.ExchangeRespond(exchange, 500, null, 0, null, 0);
        }
    }
}
