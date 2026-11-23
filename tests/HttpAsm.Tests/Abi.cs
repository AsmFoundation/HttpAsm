using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>httpasm_field (httpasm.h): one field line, 32 octets.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct HttpField
{
    /// <summary>The name, in the caller's buffer.</summary>
    public byte* Name;

    /// <summary>The value, in the caller's buffer.</summary>
    public byte* Value;

    /// <summary>The name's length.</summary>
    public uint NameLength;

    /// <summary>The value's length.</summary>
    public uint ValueLength;

    /// <summary>HTTPASM_FIELD_* id, 0 when not a known field.</summary>
    public ushort Id;

    /// <summary>HTTPASM_FIELD_FLAG_*.</summary>
    public ushort Flags;

    /// <summary>Unused.</summary>
    public uint Reserved;
}

/// <summary>httpasm_request (httpasm.h): one request's head, 96 octets.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct HttpRequest
{
    /// <summary>The method token.</summary>
    public byte* Method;

    /// <summary>The request-target.</summary>
    public byte* Target;

    /// <summary>The authority, or null.</summary>
    public byte* Authority;

    /// <summary>The scheme, or null.</summary>
    public byte* Scheme;

    /// <summary>The caller's field array.</summary>
    public HttpField* Fields;

    /// <summary>The body's length, with <see cref="Abi.RequestContentLength"/>.</summary>
    public ulong ContentLength;

    /// <summary>The method's length.</summary>
    public uint MethodLength;

    /// <summary>The target's length.</summary>
    public uint TargetLength;

    /// <summary>The authority's length.</summary>
    public uint AuthorityLength;

    /// <summary>The scheme's length.</summary>
    public uint SchemeLength;

    /// <summary>Field records written.</summary>
    public uint FieldCount;

    /// <summary>HTTPASM_REQUEST_*.</summary>
    public uint Flags;

    /// <summary>The head's octets (HTTP/1.x).</summary>
    public uint HeadLength;

    /// <summary>HTTPASM_METHOD_*.</summary>
    public ushort MethodId;

    /// <summary>10, 11 or 20.</summary>
    public byte Version;

    /// <summary>HTTPASM_TARGET_*.</summary>
    public byte TargetForm;

    /// <summary>HTTPASM_ERROR_* after a refusal.</summary>
    public ushort Error;

    /// <summary>Unused.</summary>
    public ushort Reserved0;

    /// <summary>Unused.</summary>
    public uint Reserved1;

    /// <summary>Unused.</summary>
    public ulong Reserved2;
}

/// <summary>httpasm_h1_limits (httpasm.h): 16 octets; zero fields take the defaults.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct H1Limits
{
    /// <summary>The head's octets.</summary>
    public uint MaxHead;

    /// <summary>The request-target's octets.</summary>
    public uint MaxTarget;

    /// <summary>Field lines.</summary>
    public uint MaxFields;

    /// <summary>Unused.</summary>
    public uint Reserved;
}

/// <summary>httpasm_response (httpasm.h): what a server answers, 48 octets; Flags is in and out.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct HttpResponse
{
    /// <summary>The handler's fields.</summary>
    public HttpField* Fields;

    /// <summary>A 29-octet IMF-fixdate, or null.</summary>
    public byte* Date;

    /// <summary>The body's length, with <see cref="Abi.ResponseLength"/>.</summary>
    public ulong ContentLength;

    /// <summary>How many fields.</summary>
    public uint FieldCount;

    /// <summary>HTTPASM_RESPONSE_*.</summary>
    public uint Flags;

    /// <summary>100-599.</summary>
    public ushort Status;

    /// <summary>The request's version: 10 or 11.</summary>
    public byte RequestVersion;

    /// <summary>The request's HTTPASM_METHOD_*.</summary>
    public byte RequestMethod;

    /// <summary>Unused.</summary>
    public uint Reserved;

    /// <summary>Unused.</summary>
    public ulong Reserved2;
}

/// <summary>httpasm_response_head (httpasm.h): a response's head as a client reads it, 64 octets.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ResponseHead
{
    /// <summary>The reason-phrase.</summary>
    public byte* Reason;

    /// <summary>The caller's field array.</summary>
    public HttpField* Fields;

    /// <summary>The body's length, with the CONTENT_LENGTH flag.</summary>
    public ulong ContentLength;

    /// <summary>The reason's length.</summary>
    public uint ReasonLength;

    /// <summary>Field records written.</summary>
    public uint FieldCount;

    /// <summary>HTTPASM_RESPONSE_HEAD_*.</summary>
    public uint Flags;

    /// <summary>The head's octets.</summary>
    public uint HeadLength;

    /// <summary>The status code as received.</summary>
    public ushort Status;

    /// <summary>10 or 11.</summary>
    public byte Version;

    /// <summary>Unused.</summary>
    public byte Reserved0;

    /// <summary>HTTPASM_ERROR_* after a refusal.</summary>
    public ushort Error;

    /// <summary>Unused.</summary>
    public ushort Reserved1;

    /// <summary>Unused.</summary>
    public ulong Reserved2;

    /// <summary>Unused.</summary>
    public ulong Reserved3;
}

/// <summary>httpasm_h1_chunked (httpasm.h): the chunked decoder's state, 32 octets.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct ChunkedState
{
    /// <summary>Data octets left in the current chunk.</summary>
    public ulong Remaining;

    /// <summary>Data octets decoded so far.</summary>
    public ulong Total;

    /// <summary>HTTPASM_CHUNKED_*.</summary>
    public uint State;

    /// <summary>chunk-ext octets on the current line.</summary>
    public uint ExtensionLength;

    /// <summary>HEXDIGs of the current chunk-size.</summary>
    public uint SizeDigits;

    /// <summary>Unused.</summary>
    public uint Reserved;
}

/// <summary>httpasm_client_response (httpasm.h): 96 octets.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ClientResponse
{
    /// <summary>The head: status, reason, fields, flags.</summary>
    public ResponseHead Head;

    /// <summary>The decoded body.</summary>
    public byte* Body;

    /// <summary>Its length.</summary>
    public nuint BodyLength;

    /// <summary>A chunked body's trailer fields, or null.</summary>
    public HttpField* Trailers;

    /// <summary>How many.</summary>
    public uint TrailerCount;

    /// <summary>Reserved.</summary>
    public uint Reserved;
}

/// <summary>httpasm_hpack_output (httpasm.h): 48 octets.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct HpackOutput
{
    /// <summary>The records.</summary>
    public HttpField* Fields;

    /// <summary>Where decoded names and values go.</summary>
    public byte* Space;

    /// <summary>Its octets.</summary>
    public nuint SpaceSize;

    /// <summary>Out: octets of space written.</summary>
    public nuint SpaceUsed;

    /// <summary>Out: the header list's size (RFC 9113 6.5.2).</summary>
    public ulong ListSize;

    /// <summary>The records' room.</summary>
    public uint MaxFields;

    /// <summary>Out: records written.</summary>
    public uint Count;
}

/// <summary>httpasm_server_options (httpasm.h): 64 octets; zero fields take their defaults.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct ServerOptions
{
    /// <summary>void (*)(void *context, httpasm_exchange *exchange).</summary>
    public nint Handler;

    /// <summary>Passed to the handler.</summary>
    public nint Context;

    /// <summary>Request bodies past this get 413.</summary>
    public ulong MaxBody;

    /// <summary>Worker threads.</summary>
    public uint Workers;

    /// <summary>The idle and request-head timeout.</summary>
    public uint IdleTimeoutMs;

    /// <summary>IPv4, network byte order.</summary>
    public uint BindAddress;

    /// <summary>0 for any free port.</summary>
    public ushort Port;

    /// <summary>Reserved.</summary>
    public ushort Flags;

    /// <summary>The heads' limits.</summary>
    public H1Limits Limits;

    /// <summary>Reserved.</summary>
    public ulong Reserved;
}

/// <summary>The constants of httpasm.h that the tests use.</summary>
internal static class Abi
{
    /// <summary>HTTPASM_RESPONSE_LENGTH.</summary>
    public const uint ResponseLength = 0x0001;

    /// <summary>HTTPASM_RESPONSE_CLOSE.</summary>
    public const uint ResponseClose = 0x0002;

    /// <summary>HTTPASM_RESPONSE_CHUNKED.</summary>
    public const uint ResponseChunked = 0x0004;

    /// <summary>HTTPASM_RESPONSE_NO_BODY.</summary>
    public const uint ResponseNoBody = 0x0008;

    /// <summary>HTTPASM_RESPONSE_HEAD_CONTENT_LENGTH.</summary>
    public const uint HeadContentLength = 0x0001;

    /// <summary>HTTPASM_RESPONSE_HEAD_CHUNKED.</summary>
    public const uint HeadChunked = 0x0002;

    /// <summary>HTTPASM_RESPONSE_HEAD_UNTIL_CLOSE.</summary>
    public const uint HeadUntilClose = 0x0004;

    /// <summary>HTTPASM_RESPONSE_HEAD_NO_BODY.</summary>
    public const uint HeadNoBody = 0x0008;

    /// <summary>HTTPASM_RESPONSE_HEAD_TUNNEL.</summary>
    public const uint HeadTunnel = 0x0010;

    /// <summary>HTTPASM_RESPONSE_HEAD_KEEP_ALIVE.</summary>
    public const uint HeadKeepAlive = 0x0020;

    /// <summary>HTTPASM_CHUNKED_TRAILERS.</summary>
    public const uint ChunkedTrailers = 6;

    /// <summary>HTTPASM_CHUNKED_ERROR.</summary>
    public const uint ChunkedError = 7;

    /// <summary>HTTPASM_FIELD_FLAG_TRAILER.</summary>
    public const int FieldTrailer = 0x0001;

    /// <summary>HTTPASM_FIELD_FLAG_NEVER_INDEXED.</summary>
    public const int FieldNeverIndexed = 0x0002;

    /// <summary>HTTPASM_FIELD_FLAG_NO_INDEX.</summary>
    public const int FieldNoIndex = 0x0004;

    /// <summary>HTTPASM_HPACK_HUFFMAN.</summary>
    public const uint HpackHuffman = 0x0001;

    /// <summary>HTTPASM_HPACK_INDEX_ALL.</summary>
    public const uint HpackIndexAll = 0x0002;

    /// <summary>HTTPASM_REQUEST_KEEP_ALIVE.</summary>
    public const uint RequestKeepAlive = 0x0001;

    /// <summary>HTTPASM_REQUEST_CONTENT_LENGTH.</summary>
    public const uint RequestContentLength = 0x0002;

    /// <summary>HTTPASM_REQUEST_CHUNKED.</summary>
    public const uint RequestChunked = 0x0004;

    /// <summary>HTTPASM_REQUEST_EXPECT_CONTINUE.</summary>
    public const uint RequestExpectContinue = 0x0008;

    /// <summary>HTTPASM_REQUEST_HOST.</summary>
    public const uint RequestHost = 0x0010;

    /// <summary>HTTPASM_REQUEST_TE_TRAILERS.</summary>
    public const uint RequestTeTrailers = 0x0020;

    /// <summary>HTTPASM_REQUEST_UPGRADE.</summary>
    public const uint RequestUpgrade = 0x0040;

    /// <summary>HTTPASM_REQUEST_CLOSE.</summary>
    public const uint RequestClose = 0x0080;

    /// <summary>The HTTPASM_METHOD_* ids, by method.</summary>
    public static readonly IReadOnlyDictionary<string, int> Methods = new Dictionary<string, int>
    {
        ["GET"] = 1, ["HEAD"] = 2, ["POST"] = 3, ["PUT"] = 4, ["DELETE"] = 5, ["CONNECT"] = 6,
        ["OPTIONS"] = 7, ["TRACE"] = 8, ["PATCH"] = 9,
    };

    /// <summary>HTTPASM_TARGET_ORIGIN.</summary>
    public const int TargetOrigin = 1;

    /// <summary>HTTPASM_TARGET_ABSOLUTE.</summary>
    public const int TargetAbsolute = 2;

    /// <summary>HTTPASM_TARGET_AUTHORITY.</summary>
    public const int TargetAuthority = 3;

    /// <summary>HTTPASM_TARGET_ASTERISK.</summary>
    public const int TargetAsterisk = 4;
}

/// <summary>httpasm.h's HTTPASM_ERROR_* values (public: theory tests take them as parameters).</summary>
public enum ParseError
{
    /// <summary>No error.</summary>
    None = 0,

    /// <summary>A line ended in LF without CR.</summary>
    BareLf = 1,

    /// <summary>The method is not a token.</summary>
    Method = 2,

    /// <summary>Not single-SP-separated elements.</summary>
    RequestLine = 3,

    /// <summary>An octet or escape a URI may not hold.</summary>
    Target = 4,

    /// <summary>414.</summary>
    TargetTooLong = 5,

    /// <summary>The target's form does not suit the method.</summary>
    TargetForm = 6,

    /// <summary>Not HTTP-version's grammar.</summary>
    Version = 7,

    /// <summary>505.</summary>
    VersionUnsupported = 8,

    /// <summary>A line starts with whitespace.</summary>
    ObsFold = 9,

    /// <summary>A field name is empty or not a token.</summary>
    FieldName = 10,

    /// <summary>Whitespace between a field name and its colon.</summary>
    WhitespaceBeforeColon = 11,

    /// <summary>A control character in a field value.</summary>
    FieldValue = 12,

    /// <summary>431.</summary>
    HeadTooLarge = 13,

    /// <summary>431.</summary>
    TooManyFields = 14,

    /// <summary>An HTTP/1.1 request without Host.</summary>
    HostMissing = 15,

    /// <summary>Two Host lines.</summary>
    HostDuplicate = 16,

    /// <summary>Host is not uri-host [ ":" port ].</summary>
    HostInvalid = 17,

    /// <summary>Content-Length is not 1*DIGIT, or values differ.</summary>
    ContentLength = 18,

    /// <summary>Both Transfer-Encoding and Content-Length.</summary>
    TeAndCl = 19,

    /// <summary>Transfer-Encoding in HTTP/1.0.</summary>
    TeHttp10 = 20,

    /// <summary>chunked missing, repeated, or not final.</summary>
    TeNotChunked = 21,

    /// <summary>A coding not implemented: 501.</summary>
    TeUnknown = 22,

    /// <summary>An expectation other than 100-continue: 417.</summary>
    Expect = 23,

    /// <summary>A writer was given a field it owns.</summary>
    FramingField = 24,

    /// <summary>A status outside 100-599, or a bad status-line.</summary>
    Status = 25,

    /// <summary>Malformed chunked framing.</summary>
    Chunk = 26,

    /// <summary>An authority with octets Host may not hold.</summary>
    Authority = 27,

    /// <summary>HPACK: index 0, or past both tables.</summary>
    HpackIndex = 28,

    /// <summary>HPACK: an integer past 2^32-1 or 5 continuation octets.</summary>
    HpackInteger = 29,

    /// <summary>HPACK: the block ends inside a representation.</summary>
    HpackTruncated = 30,

    /// <summary>HPACK: EOS in a string, or bad padding.</summary>
    HpackHuffman = 31,

    /// <summary>HPACK: a size update after a field, or above the limit.</summary>
    HpackSizeUpdate = 32,

    /// <summary>HPACK: a limit too large, or memory too small.</summary>
    HpackLimit = 33,
}
