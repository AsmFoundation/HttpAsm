using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>
/// libhttpasm.so's C ABI (src/HttpAsm/include/httpasm.h), and the few C library calls the tests
/// need to build guarded buffers.
/// </summary>
/// <remarks>
/// The bare name "httpasm" makes .NET probe libhttpasm.so, which AsmFoundation.Sdk puts under
/// runtimes/linux-x64/native/ and lists in the test app's deps.json. Every entry point here is
/// a leaf that neither blocks nor calls back, so the GC transition could be suppressed. It is
/// not suppressed: these tests measure nothing, and the default is the safe one.
/// </remarks>
internal static unsafe partial class Native
{
    /// <summary>The library's name, as [LibraryImport] probes it.</summary>
    private const string Library = "httpasm";

    /// <summary>glibc by its soname: plain "libc" would make .NET probe libc.so, a linker script.</summary>
    private const string Libc = "libc.so.6";

    /// <summary>mmap's PROT_NONE: the page cannot be touched.</summary>
    internal const int ProtNone = 0;

    /// <summary>mmap's PROT_READ | PROT_WRITE.</summary>
    internal const int ProtReadWrite = 0x1 | 0x2;

    /// <summary>mmap's MAP_PRIVATE | MAP_ANONYMOUS on Linux x64.</summary>
    internal const int MapPrivateAnonymous = 0x02 | 0x20;

    /// <summary>uint32_t httpasm_abi_version(void).</summary>
    /// <returns>The loaded library's ABI version; 0 before the first release.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_abi_version")]
    internal static partial uint AbiVersion();

    /// <summary>size_t httpasm_token_length(const uint8_t *p, size_t n).</summary>
    /// <param name="p">The octets.</param>
    /// <param name="n">How many there are.</param>
    /// <returns>The number of leading octets that are tchar; n when all are.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_token_length")]
    internal static partial nuint TokenLength(byte* p, nuint n);

    /// <summary>size_t httpasm_field_value_scan(const uint8_t *p, size_t n).</summary>
    /// <param name="p">The octets.</param>
    /// <param name="n">How many there are.</param>
    /// <returns>The index of the first octet a field value may not hold; n when none.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_value_scan")]
    internal static partial nuint FieldValueScan(byte* p, nuint n);

    /// <summary>uint32_t httpasm_struct_size(uint32_t which).</summary>
    /// <param name="which">1 httpasm_field, 2 httpasm_request, 3 httpasm_h1_limits.</param>
    /// <returns>The library's size of that structure, 0 for another value.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_struct_size")]
    internal static partial uint StructSize(uint which);

    /// <summary>uint32_t httpasm_field_id(const uint8_t *name, size_t n).</summary>
    /// <param name="name">The name.</param>
    /// <param name="n">Its length.</param>
    /// <returns>The known-field id, 0 when not known or not a token.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_id")]
    internal static partial uint FieldId(byte* name, nuint n);

    /// <summary>const uint8_t *httpasm_field_name(uint32_t id, size_t *length).</summary>
    /// <param name="id">A known-field id.</param>
    /// <param name="length">Receives the name's length; may be null.</param>
    /// <returns>The lower-case name, or null.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_name")]
    internal static partial byte* FieldName(uint id, nuint* length);

    /// <summary>int64_t httpasm_h1_parse_request(buf, len, scan_from, limits, request, fields).</summary>
    /// <param name="buffer">The received octets.</param>
    /// <param name="length">How many.</param>
    /// <param name="scanFrom">The resume point of the search for the head's end.</param>
    /// <param name="limits">The limits, or null for the defaults.</param>
    /// <param name="request">Receives the head.</param>
    /// <param name="fields">Receives the field lines.</param>
    /// <returns>The head's length, 0 when incomplete, or -status.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_parse_request")]
    internal static partial long H1ParseRequest(byte* buffer, nuint length, nuint* scanFrom, H1Limits* limits, HttpRequest* request, HttpField* fields);

    /// <summary>int64_t httpasm_h1_parse_response(buf, len, scan_from, limits, request_method, head, fields).</summary>
    /// <param name="buffer">The received octets (writable: obs-fold is joined in place).</param>
    /// <param name="length">How many.</param>
    /// <param name="scanFrom">The resume point.</param>
    /// <param name="limits">The limits, or null.</param>
    /// <param name="requestMethod">The request's HTTPASM_METHOD_*.</param>
    /// <param name="head">Receives the head.</param>
    /// <param name="fields">Receives the fields.</param>
    /// <returns>The head's length, 0 when incomplete, or -status.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_parse_response")]
    internal static partial long H1ParseResponse(byte* buffer, nuint length, nuint* scanFrom, H1Limits* limits, uint requestMethod, ResponseHead* head, HttpField* fields);

    /// <summary>int64_t httpasm_h1_chunked_decode(state, in, len, produced).</summary>
    /// <param name="state">The decoder's state.</param>
    /// <param name="input">The body octets, decoded in place.</param>
    /// <param name="length">How many.</param>
    /// <param name="produced">Receives the data octets now at the input's start.</param>
    /// <returns>The octets consumed, or -400.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_chunked_decode")]
    internal static partial long H1ChunkedDecode(ChunkedState* state, byte* input, nuint length, nuint* produced);

    /// <summary>int64_t httpasm_h1_parse_trailers(buf, len, scan_from, limits, fields, count).</summary>
    /// <param name="buffer">The octets after the last chunk's line.</param>
    /// <param name="length">How many.</param>
    /// <param name="scanFrom">The resume point.</param>
    /// <param name="limits">The limits, or null.</param>
    /// <param name="fields">Receives the trailer fields.</param>
    /// <param name="count">Receives how many.</param>
    /// <returns>The section's length, 0 when incomplete, or -status.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_parse_trailers")]
    internal static partial long H1ParseTrailers(byte* buffer, nuint length, nuint* scanFrom, H1Limits* limits, HttpField* fields, uint* count);

    /// <summary>int64_t httpasm_h1_write_response(out, cap, response).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="response">The response; its flags come back updated.</param>
    /// <returns>The head's length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_response")]
    internal static partial long H1WriteResponse(byte* output, nuint capacity, HttpResponse* response);

    /// <summary>int64_t httpasm_h1_write_request(out, cap, request).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="request">The request's description.</param>
    /// <returns>The head's length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_request")]
    internal static partial long H1WriteRequest(byte* output, nuint capacity, HttpRequest* request);

    /// <summary>int64_t httpasm_h1_write_chunk(out, cap, data, len).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="data">The chunk's data.</param>
    /// <param name="length">At least 1.</param>
    /// <returns>The chunk's length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_chunk")]
    internal static partial long H1WriteChunk(byte* output, nuint capacity, byte* data, nuint length);

    /// <summary>int64_t httpasm_h1_write_last_chunk(out, cap, trailers, count).</summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="capacity">Its size.</param>
    /// <param name="trailers">The trailer fields, or null.</param>
    /// <param name="count">How many.</param>
    /// <returns>The length, 0 if too small, or -error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_h1_write_last_chunk")]
    internal static partial long H1WriteLastChunk(byte* output, nuint capacity, HttpField* trailers, uint count);

    /// <summary>size_t httpasm_hpack_size(uint32_t limit).</summary>
    /// <param name="limit">The table's limit.</param>
    /// <returns>The octets its memory needs; 0 past HTTPASM_HPACK_MAX_LIMIT.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_size")]
    internal static partial nuint HpackSize(uint limit);

    /// <summary>int httpasm_hpack_init(void *memory, size_t size, uint32_t limit, uint32_t flags).</summary>
    /// <param name="memory">The table's memory.</param>
    /// <param name="size">Its octets.</param>
    /// <param name="limit">The limit.</param>
    /// <param name="flags">HTTPASM_HPACK_*.</param>
    /// <returns>0, or -HTTPASM_ERROR_HPACK_LIMIT.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_init")]
    internal static partial int HpackInit(byte* memory, nuint size, uint limit, uint flags);

    /// <summary>int64_t httpasm_hpack_decode(table, block, length, output).</summary>
    /// <param name="table">The decoder's table.</param>
    /// <param name="block">The header block.</param>
    /// <param name="length">Its octets.</param>
    /// <param name="output">Where the fields go.</param>
    /// <returns>0, 1 when the output ran out, or -HTTPASM_ERROR_HPACK_*.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_decode")]
    internal static partial long HpackDecode(byte* table, byte* block, nuint length, HpackOutput* output);

    /// <summary>size_t httpasm_hpack_encode_bound(fields, count).</summary>
    /// <param name="fields">The fields.</param>
    /// <param name="count">How many.</param>
    /// <returns>The most octets the encoding can take.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_encode_bound")]
    internal static partial nuint HpackEncodeBound(HttpField* fields, uint count);

    /// <summary>int64_t httpasm_hpack_encode(table, fields, count, out, cap).</summary>
    /// <param name="table">The encoder's table.</param>
    /// <param name="fields">The fields.</param>
    /// <param name="count">How many.</param>
    /// <param name="output">Where the block goes.</param>
    /// <param name="cap">Its room.</param>
    /// <returns>The block's length, or 0 when cap is below the bound.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_encode")]
    internal static partial long HpackEncode(byte* table, HttpField* fields, uint count, byte* output, nuint cap);

    /// <summary>void httpasm_hpack_encoder_limit(table, limit).</summary>
    /// <param name="table">The encoder's table.</param>
    /// <param name="limit">The peer's SETTINGS_HEADER_TABLE_SIZE.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_encoder_limit")]
    internal static partial void HpackEncoderLimit(byte* table, uint limit);

    /// <summary>uint32_t httpasm_hpack_table_size(table, uint32_t *max_size).</summary>
    /// <param name="table">The table.</param>
    /// <param name="maxSize">Receives the maximum, or null.</param>
    /// <returns>The dynamic table's size.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_table_size")]
    internal static partial uint HpackTableSize(byte* table, uint* maxSize);

    /// <summary>int httpasm_hpack_entry(table, index, field).</summary>
    /// <param name="table">The table.</param>
    /// <param name="index">An HPACK index.</param>
    /// <param name="field">Receives the entry.</param>
    /// <returns>0, or -HTTPASM_ERROR_HPACK_INDEX.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_hpack_entry")]
    internal static partial int HpackEntry(byte* table, uint index, HttpField* field);

    /// <summary>httpasm_client *httpasm_client_connect(address, port, timeout_ms, int *error).</summary>
    /// <param name="address">IPv4, network byte order.</param>
    /// <param name="port">The port.</param>
    /// <param name="timeoutMs">The connect and I/O timeout (0: none).</param>
    /// <param name="error">Receives -errno on failure.</param>
    /// <returns>The client, or null.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_client_connect")]
    internal static partial nint ClientConnect(uint address, ushort port, uint timeoutMs, int* error);

    /// <summary>int httpasm_client_send(client, request, body, length, response).</summary>
    /// <param name="client">The client.</param>
    /// <param name="request">The request.</param>
    /// <param name="body">The body.</param>
    /// <param name="length">Its length.</param>
    /// <param name="response">Receives the response.</param>
    /// <returns>0, -HTTPASM_ERROR_*, or -errno.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_client_send")]
    internal static partial int ClientSend(nint client, HttpRequest* request, byte* body, nuint length, ClientResponse* response);

    /// <summary>void httpasm_client_close(client).</summary>
    /// <param name="client">The client.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_client_close")]
    internal static partial void ClientClose(nint client);

    /// <summary>httpasm_server *httpasm_server_create(options, int *error).</summary>
    /// <param name="options">The options.</param>
    /// <param name="error">Receives -errno on failure.</param>
    /// <returns>The server, or null.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_create")]
    internal static partial nint ServerCreate(ServerOptions* options, int* error);

    /// <summary>int httpasm_server_start(server).</summary>
    /// <param name="server">The server.</param>
    /// <returns>0 or -errno.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_start")]
    internal static partial int ServerStart(nint server);

    /// <summary>uint16_t httpasm_server_port(server).</summary>
    /// <param name="server">The server.</param>
    /// <returns>The port it listens on.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_port")]
    internal static partial ushort ServerPort(nint server);

    /// <summary>uint32_t httpasm_server_io(server).</summary>
    /// <param name="server">The server.</param>
    /// <returns>What its workers use: <see cref="ServerIo.Uring"/>, <see cref="ServerIo.Epoll"/>,
    /// or <see cref="ServerIo.None"/> when it is not running.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_server_io")]
    internal static partial uint ServerIoUsed(nint server);

    /// <summary>void httpasm_server_stop(server).</summary>
    /// <param name="server">The server.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_server_stop")]
    internal static partial void ServerStop(nint server);

    /// <summary>void httpasm_server_destroy(server).</summary>
    /// <param name="server">The server.</param>
    [LibraryImport(Library, EntryPoint = "httpasm_server_destroy")]
    internal static partial void ServerDestroy(nint server);

    /// <summary>const httpasm_request *httpasm_exchange_request(exchange).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <returns>The request.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_request")]
    internal static partial HttpRequest* ExchangeRequest(nint exchange);

    /// <summary>const uint8_t *httpasm_exchange_body(exchange, size_t *length).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <param name="length">Receives the body's length.</param>
    /// <returns>The body.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_body")]
    internal static partial byte* ExchangeBody(nint exchange, nuint* length);

    /// <summary>const httpasm_field *httpasm_exchange_trailers(exchange, uint32_t *count).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <param name="count">Receives how many.</param>
    /// <returns>The trailer fields.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_trailers")]
    internal static partial HttpField* ExchangeTrailers(nint exchange, uint* count);

    /// <summary>int httpasm_exchange_defer(exchange).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <returns>0 or -EINVAL.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_defer")]
    internal static partial int ExchangeDefer(nint exchange);

    /// <summary>int httpasm_exchange_respond(exchange, status, fields, count, body, length).</summary>
    /// <param name="exchange">The exchange.</param>
    /// <param name="status">The status.</param>
    /// <param name="fields">The fields.</param>
    /// <param name="count">How many.</param>
    /// <param name="body">The body.</param>
    /// <param name="length">Its length.</param>
    /// <returns>0 or a negative error.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_exchange_respond")]
    internal static partial int ExchangeRespond(nint exchange, ushort status, HttpField* fields, uint count, byte* body, nuint length);

    /// <summary>void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset).</summary>
    /// <param name="addr">A placement hint; zero lets the kernel choose.</param>
    /// <param name="length">The mapping's size in bytes.</param>
    /// <param name="prot">PROT_* bits.</param>
    /// <param name="flags">MAP_* bits.</param>
    /// <param name="fd">-1 for an anonymous mapping.</param>
    /// <param name="offset">0 for an anonymous mapping.</param>
    /// <returns>The mapping's address, or -1 (MAP_FAILED) with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "mmap", SetLastError = true)]
    internal static partial nint Mmap(nint addr, nuint length, int prot, int flags, int fd, nint offset);

    /// <summary>int mprotect(void *addr, size_t len, int prot).</summary>
    /// <param name="addr">A page-aligned address.</param>
    /// <param name="length">The range's size in bytes.</param>
    /// <param name="prot">PROT_* bits.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "mprotect", SetLastError = true)]
    internal static partial int Mprotect(nint addr, nuint length, int prot);

    /// <summary>int munmap(void *addr, size_t length).</summary>
    /// <param name="addr">The mapping's address.</param>
    /// <param name="length">Its size in bytes.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "munmap", SetLastError = true)]
    internal static partial int Munmap(nint addr, nuint length);

    /// <summary>uint64_t httpasm_cpu_found(void).</summary>
    /// <returns>The HTTPASM_CPU_* bits the CPU and the OS offer.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_cpu_found")]
    internal static partial ulong CpuFound();

    /// <summary>uint64_t httpasm_cpu_features(void).</summary>
    /// <returns>The HTTPASM_CPU_* bits the library uses.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_cpu_features")]
    internal static partial ulong CpuFeatures();

    /// <summary>uint64_t httpasm_cpu_limit(uint64_t cap).</summary>
    /// <param name="cap">The new cap (it replaces HTTPASM_CPU's).</param>
    /// <returns>The bits the library uses from now on.</returns>
    /// <remarks>
    /// Process-wide. Every tier computes the same results, so other tests are unaffected, but a
    /// test that reads the features back must not run beside another that changes them: such
    /// tests live in <see cref="SerialCollection"/> and restore the cap they found.
    /// </remarks>
    [LibraryImport(Library, EntryPoint = "httpasm_cpu_limit")]
    internal static partial ulong CpuLimit(ulong cap);

    /// <summary>int setenv(const char *name, const char *value, int overwrite).</summary>
    /// <param name="name">The variable.</param>
    /// <param name="value">Its value.</param>
    /// <param name="overwrite">Nonzero to replace an existing value.</param>
    /// <returns>0, or -1 with errno set.</returns>
    /// <remarks>
    /// The C library's own environment, which a native library's getenv reads: .NET's
    /// Environment.SetEnvironmentVariable changes only the managed copy on Linux. Not safe while
    /// another thread calls getenv: callers run in <see cref="SerialCollection"/>.
    /// </remarks>
    [LibraryImport(Libc, EntryPoint = "setenv", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SetEnv(string name, string value, int overwrite);

    /// <summary>int unsetenv(const char *name).</summary>
    /// <param name="name">The variable.</param>
    /// <returns>0, or -1 with errno set.</returns>
    /// <remarks>Same caveat as <see cref="SetEnv"/>.</remarks>
    [LibraryImport(Libc, EntryPoint = "unsetenv", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int UnsetEnv(string name);

    /// <summary>The io_uring_setup system call's number on x86-64.</summary>
    internal const long SysIoUringSetup = 425;

    /// <summary>long syscall(long number, ...), called with io_uring_setup's two arguments.</summary>
    /// <param name="number"><see cref="SysIoUringSetup"/>.</param>
    /// <param name="entries">The SQ ring's size to ask for.</param>
    /// <param name="parameters">struct io_uring_params (120 octets, zeroed): the kernel fills it.</param>
    /// <returns>The ring's descriptor, or -1 with errno set (ENOMEM past RLIMIT_MEMLOCK on a
    /// kernel that charges rings to it; EPERM or ENOSYS where io_uring is refused).</returns>
    /// <remarks>
    /// glibc's syscall is variadic, but on x86-64 it is assembly that only moves its integer
    /// arguments into place and ignores the vector-register count a variadic call passes in al,
    /// so this fixed-argument import calls it correctly. The caller closes a descriptor it gets.
    /// </remarks>
    [LibraryImport(Libc, EntryPoint = "syscall", SetLastError = true)]
    internal static partial long SyscallIoUringSetup(long number, long entries, byte* parameters);

    /// <summary>int close(int fd).</summary>
    /// <param name="fd">The descriptor.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "close", SetLastError = true)]
    internal static partial int Close(int fd);

    /// <summary>getrlimit's and setrlimit's RLIMIT_MEMLOCK on Linux x64.</summary>
    internal const int RlimitMemlock = 8;

    /// <summary>int getrlimit(int resource, struct rlimit *rlim).</summary>
    /// <param name="resource">RLIMIT_* (<see cref="RlimitMemlock"/>).</param>
    /// <param name="limit">Receives the soft and the hard limit.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "getrlimit", SetLastError = true)]
    internal static partial int GetRlimit(int resource, out Rlimit limit);

    /// <summary>int setrlimit(int resource, const struct rlimit *rlim).</summary>
    /// <param name="resource">RLIMIT_* (<see cref="RlimitMemlock"/>).</param>
    /// <param name="limit">The new soft and hard limit.</param>
    /// <returns>0, or -1 with errno set (EPERM: raising a hard limit without the privilege).</returns>
    /// <remarks>
    /// Process-wide: every thread of the test process sees the new limit at once, so a test that
    /// lowers one must not run beside others that depend on it (see
    /// <see cref="SerialCollection"/>), and must put the old one back.
    /// </remarks>
    [LibraryImport(Libc, EntryPoint = "setrlimit", SetLastError = true)]
    internal static partial int SetRlimit(int resource, in Rlimit limit);
}

/// <summary>struct rlimit on Linux x64: the soft limit, then the hard one (RLIM_INFINITY = ~0).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct Rlimit
{
    /// <summary>rlim_cur: what the kernel enforces now; any process may lower or raise it up to <see cref="Max"/>.</summary>
    public ulong Current;

    /// <summary>rlim_max: the ceiling for <see cref="Current"/>; only privilege raises it.</summary>
    public ulong Max;
}
