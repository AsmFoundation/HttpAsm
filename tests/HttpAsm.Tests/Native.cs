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
}
