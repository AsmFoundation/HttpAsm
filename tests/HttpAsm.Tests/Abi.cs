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

/// <summary>
/// httpasm_sha256_ctx (httpasm.h): a running SHA-256 hash, 112 octets. Its octets are the whole
/// state, so copying the struct forks the hash.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct Sha256Context
{
    /// <summary>H0-H7 of FIPS 180-4 6.2.</summary>
    public fixed uint State[8];

    /// <summary>Octets fed so far.</summary>
    public ulong Length;

    /// <summary>The next block's first <see cref="Buffered"/> octets.</summary>
    public fixed byte Buffer[64];

    /// <summary>How many octets wait in <see cref="Buffer"/> (0-63).</summary>
    public uint Buffered;

    /// <summary>Unused.</summary>
    public uint Reserved;
}

/// <summary>
/// httpasm_hmac_sha256_ctx (httpasm.h): a running HMAC-SHA256, 224 octets: the inner and outer
/// hashes, each already past its key block.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct HmacSha256Context
{
    /// <summary>The inner hash, fed the message.</summary>
    public Sha256Context Inner;

    /// <summary>The outer hash, fed the inner digest at the end.</summary>
    public Sha256Context Outer;
}

/// <summary>
/// httpasm_aes_key (httpasm.h): an expanded AES-128 or AES-256 key, 496 octets, both versions'
/// round keys (FIPS 197's and the constant-time version's compressed ones). No alignment needed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AesKey
{
    /// <summary>FIPS 197's schedule, 16 octets a round (AES-128 uses 11 rows, AES-256 15).</summary>
    public fixed byte RoundKeys[240];

    /// <summary>The constant-time version's round keys, compressed (two qwords a round).</summary>
    public fixed byte Ct[240];

    /// <summary>10 (AES-128) or 14 (AES-256).</summary>
    public uint Rounds;

    /// <summary>Unused.</summary>
    public fixed uint Reserved[3];
}

/// <summary>
/// httpasm_aes_gcm_key (httpasm.h): an AES-GCM key, 1024 octets: the AES key, H, and GHASH's
/// powers of H as the carry-less versions keep them. Every tier's init writes the same octets.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AesGcmKey
{
    /// <summary>The block cipher's key.</summary>
    public AesKey Aes;

    /// <summary>H = E_K(0^128).</summary>
    public fixed byte H[16];

    /// <summary>H^16 .. H^1, reflected and twisted.</summary>
    public fixed byte HTable[256];

    /// <summary>Each power's two halves xored.</summary>
    public fixed byte HKara[256];
}

/// <summary>
/// httpasm_rsa_public_key (httpasm_abi.inc; opaque in httpasm.h), 2080 octets: a public key ready
/// for verification. The tests read its fields to hold the init to a BigInteger model (R^2 mod n,
/// n0, the limbs); a caller only passes it. All zeros after a refused init.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RsaPublicKey
{
    /// <summary>The modulus, 128 little-endian limbs, zero above its own.</summary>
    public fixed ulong N[128];

    /// <summary>R^2 mod n, R = 2^(64 Limbs).</summary>
    public fixed ulong RR[128];

    /// <summary>-n^-1 mod 2^64.</summary>
    public ulong N0;

    /// <summary>The public exponent.</summary>
    public ulong E;

    /// <summary>The limbs the operations run on: n's rounded up to a multiple of 8.</summary>
    public uint Limbs;

    /// <summary>n's bit length (0 for a refused key).</summary>
    public uint Bits;

    /// <summary>Unused.</summary>
    public ulong Reserved;
}

/// <summary>
/// httpasm_rsa_private_key (httpasm_abi.inc; opaque in httpasm.h), 6720 octets: a private key
/// ready to sign, its public key first. The tests read its fields and plant faults in them (a bit
/// flipped in a CRT exponent after the init); a caller only passes it. All zeros after a refused
/// init. Both primes run on <see cref="Limbs"/> limbs, R = 2^(64 Limbs).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RsaPrivateKey
{
    /// <summary>The public key (verifications may run under it).</summary>
    public RsaPublicKey Public;

    /// <summary>The prime p, 64 little-endian limbs.</summary>
    public fixed ulong P[64];

    /// <summary>The prime q.</summary>
    public fixed ulong Q[64];

    /// <summary>d mod (p - 1).</summary>
    public fixed ulong Dp[64];

    /// <summary>d mod (q - 1).</summary>
    public fixed ulong Dq[64];

    /// <summary>R^2 mod p.</summary>
    public fixed ulong RrP[64];

    /// <summary>R^2 mod q.</summary>
    public fixed ulong RrQ[64];

    /// <summary>R^3 mod p.</summary>
    public fixed ulong RrrP[64];

    /// <summary>R^3 mod q.</summary>
    public fixed ulong RrrQ[64];

    /// <summary>q^-1 R mod p.</summary>
    public fixed ulong QinvR[64];

    /// <summary>-p^-1 mod 2^64.</summary>
    public ulong P0;

    /// <summary>-q^-1 mod 2^64.</summary>
    public ulong Q0;

    /// <summary>The primes' limbs: the larger's rounded up to 8.</summary>
    public uint Limbs;

    /// <summary>Unused.</summary>
    public fixed uint Reserved[3];
}

/// <summary>
/// httpasm_rsa_private_numbers (httpasm.h), 112 octets: an RSAPrivateKey's numbers for
/// httpasm_rsa_private_key_init, each a big-endian octet string and its length.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct RsaPrivateNumbers
{
    /// <summary>The modulus.</summary>
    public byte* N;

    /// <summary>Its length.</summary>
    public nuint NLength;

    /// <summary>The public exponent.</summary>
    public byte* E;

    /// <summary>Its length.</summary>
    public nuint ELength;

    /// <summary>The prime p.</summary>
    public byte* P;

    /// <summary>Its length.</summary>
    public nuint PLength;

    /// <summary>The prime q.</summary>
    public byte* Q;

    /// <summary>Its length.</summary>
    public nuint QLength;

    /// <summary>d mod (p - 1).</summary>
    public byte* Dp;

    /// <summary>Its length.</summary>
    public nuint DpLength;

    /// <summary>d mod (q - 1).</summary>
    public byte* Dq;

    /// <summary>Its length.</summary>
    public nuint DqLength;

    /// <summary>q^-1 mod p.</summary>
    public byte* Qinv;

    /// <summary>Its length.</summary>
    public nuint QinvLength;
}

/// <summary>
/// httpasm_hmac_sha384_ctx (httpasm.h): a running HMAC-SHA384, 416 octets: SHA-384's inner and
/// outer hashes past their key blocks. Copying it after init MACs again under the same key.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct HmacSha384Context
{
    /// <summary>The inner hash, fed the message.</summary>
    public Sha512Context Inner;

    /// <summary>The outer hash, fed the inner digest at the end.</summary>
    public Sha512Context Outer;
}

/// <summary>
/// httpasm_sha512_ctx (httpasm.h): a running SHA-512 or SHA-384 hash, 208 octets. The two share
/// the layout: only the start (<see cref="Native.Sha512Init"/> or <see cref="Native.Sha384Init"/>)
/// and the final's length differ, so a context must be finished by the final of its own init.
/// Copying the struct forks the hash.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct Sha512Context
{
    /// <summary>H0-H7 of FIPS 180-4 6.4.</summary>
    public fixed ulong State[8];

    /// <summary>Octets fed so far.</summary>
    public ulong Length;

    /// <summary>The next block's first <see cref="Buffered"/> octets.</summary>
    public fixed byte Buffer[128];

    /// <summary>How many octets wait in <see cref="Buffer"/> (0-127).</summary>
    public uint Buffered;

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

/// <summary>
/// The CPU tiers' bits (httpasm.h, HTTPASM_CPU_*), and an independent model of how the library
/// turns found features and a cap into the features it uses: the tests' oracle for
/// httpasm_cpu_features, httpasm_cpu_limit and the HTTPASM_CPU variable.
/// </summary>
/// <remarks>
/// Written from the documented rules (httpasm.h, cpu.inc), not from the assembly, so a slip in
/// either shows as a difference.
/// </remarks>
internal static class Cpu
{
    /// <summary>x86-64-v2.</summary>
    public const ulong V2 = 1 << 0;

    /// <summary>x86-64-v3.</summary>
    public const ulong V3 = 1 << 1;

    /// <summary>x86-64-v4.</summary>
    public const ulong V4 = 1 << 2;

    /// <summary>AES-NI.</summary>
    public const ulong Aesni = 1 << 8;

    /// <summary>PCLMULQDQ.</summary>
    public const ulong Clmul = 1 << 9;

    /// <summary>SHA-1/SHA-256 extensions.</summary>
    public const ulong Sha = 1 << 10;

    /// <summary>GFNI.</summary>
    public const ulong Gfni = 1 << 11;

    /// <summary>BMI2 (counted with v3).</summary>
    public const ulong Bmi2 = 1 << 12;

    /// <summary>ADX (counted with v3).</summary>
    public const ulong Adx = 1 << 13;

    /// <summary>VAES (needs v3).</summary>
    public const ulong Vaes = 1 << 14;

    /// <summary>VPCLMULQDQ (needs v3).</summary>
    public const ulong Vclmul = 1 << 15;

    /// <summary>SHA512 extensions (needs v3).</summary>
    public const ulong Sha512 = 1 << 16;

    /// <summary>AVX512-IFMA (needs v4).</summary>
    public const ulong Ifma = 1 << 17;

    /// <summary>AVX512-VBMI (needs v4).</summary>
    public const ulong Vbmi = 1 << 18;

    /// <summary>AVX512-VBMI2 (needs v4).</summary>
    public const ulong Vbmi2 = 1 << 19;

    /// <summary>Every bit: no cap.</summary>
    public const ulong All = V2 | V3 | V4 | Aesni | Clmul | Sha | Gfni | Bmi2 | Adx | Vaes | Vclmul | Sha512 | Ifma | Vbmi | Vbmi2;

    /// <summary>The cap "v1" sets: the pure baseline.</summary>
    public const ulong CapV1 = 0;

    /// <summary>The cap "v2" sets: the level and the legacy-SSE groups.</summary>
    public const ulong CapV2 = V2 | Aesni | Clmul | Sha | Gfni;

    /// <summary>The cap "v3" sets.</summary>
    public const ulong CapV3 = CapV2 | V3 | Bmi2 | Adx | Vaes | Vclmul | Sha512;

    /// <summary>The cap "v4" sets.</summary>
    public const ulong CapV4 = CapV3 | V4 | Ifma | Vbmi | Vbmi2;

    /// <summary>The words HTTPASM_CPU may hold as its first item, and their caps.</summary>
    public static readonly IReadOnlyDictionary<string, ulong> Levels = new Dictionary<string, ulong>(StringComparer.Ordinal)
    {
        ["native"] = All, ["v1"] = CapV1, ["v2"] = CapV2, ["v3"] = CapV3, ["v4"] = CapV4,
    };

    /// <summary>The groups a "-group" item may drop.</summary>
    public static readonly IReadOnlyDictionary<string, ulong> Groups = new Dictionary<string, ulong>(StringComparer.Ordinal)
    {
        ["aesni"] = Aesni, ["clmul"] = Clmul, ["sha"] = Sha, ["gfni"] = Gfni, ["bmi2"] = Bmi2, ["adx"] = Adx,
        ["vaes"] = Vaes, ["vclmul"] = Vclmul, ["sha512"] = Sha512, ["ifma"] = Ifma, ["vbmi"] = Vbmi, ["vbmi2"] = Vbmi2,
    };

    /// <summary>
    /// What the library uses given what was found and a cap: found AND cap, then every level
    /// without the one below dropped, and every group without the level its encodings need.
    /// </summary>
    /// <param name="found">httpasm_cpu_found().</param>
    /// <param name="cap">The cap.</param>
    /// <returns>The expected httpasm_cpu_features().</returns>
    public static ulong Effective(ulong found, ulong cap)
    {
        ulong bits = found & cap & All;
        if ((bits & V2) == 0)
        {
            bits &= ~(V3 | V4);
        }

        if ((bits & V3) == 0)
        {
            bits &= ~(V4 | Bmi2 | Adx | Vaes | Vclmul | Sha512);
        }

        if ((bits & V4) == 0)
        {
            bits &= ~(Ifma | Vbmi | Vbmi2);
        }

        return bits;
    }

    /// <summary>
    /// The cap HTTPASM_CPU's text asks for: null or empty is no cap; a level word, then
    /// ",-group" items; without a level, the first item is a "-group". Anything else is the
    /// baseline (CapV1), so a typo never leaves faster code running unnoticed.
    /// </summary>
    /// <param name="text">The variable's value, or null when unset.</param>
    /// <returns>The cap.</returns>
    public static ulong CapFromText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return All;
        }

        string[] items = text.Split(',');
        ulong cap = All;
        int first = 0;
        if (!items[0].StartsWith('-'))
        {
            if (!Levels.TryGetValue(items[0], out cap))
            {
                return CapV1;
            }

            first = 1;
        }

        for (int i = first; i < items.Length; i++)
        {
            string item = items[i];
            if (item.Length < 2 || item[0] != '-' || !Groups.TryGetValue(item[1..], out ulong group))
            {
                return CapV1;
            }

            cap &= ~group;
        }

        return cap;
    }
}

/// <summary>
/// What a server's workers wait and do their I/O with (httpasm.h): the option that asks for
/// io_uring (epoll is the default), and httpasm_server_io's answers.
/// </summary>
internal static class ServerIo
{
    /// <summary>
    /// HTTPASM_SERVER_URING: each worker asks the kernel for its own io_uring, and runs on epoll
    /// if refused (so asking never fails a start; <see cref="TestServer.Io"/> tells what came).
    /// </summary>
    public const ushort AskUring = 0x0001;

    /// <summary>HTTPASM_SERVER_IO_NONE: not running.</summary>
    public const uint None = 0;

    /// <summary>HTTPASM_SERVER_IO_EPOLL: every worker on epoll.</summary>
    public const uint Epoll = 1;

    /// <summary>HTTPASM_SERVER_IO_URING: every worker on its own io_uring.</summary>
    public const uint Uring = 2;

    /// <summary>
    /// HTTPASM_SERVER_IO_MIXED: the kernel gave rings to some workers only (typically the user's
    /// RLIMIT_MEMLOCK running out on a kernel that charges rings to it; see httpasm.h).
    /// </summary>
    public const uint Mixed = 3;
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

    /// <summary>HTTPASM_SERVER_* (<see cref="ServerIo.AskUring"/>).</summary>
    public ushort Flags;

    /// <summary>The heads' limits.</summary>
    public H1Limits Limits;

    /// <summary>Octets a second a transfer must keep to outlive the idle timeout (0: 240).</summary>
    public uint MinDataRate;

    /// <summary>Reserved.</summary>
    public uint Reserved;
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

    /// <summary>HTTP/2: a pseudo-field unknown, repeated, a response's, after a regular field, or in trailers.</summary>
    H2Pseudo = 34,

    /// <summary>HTTP/2: :method, :scheme or :path (CONNECT: :authority) missing or empty.</summary>
    H2Missing = 35,

    /// <summary>HTTP/2: a connection-specific field, or TE other than "trailers".</summary>
    H2ConnectionField = 36,

    /// <summary>HTTP/2: :authority empty or not uri-host [ ":" port ], a CONNECT's without a port of 1-65535, or a Host naming another authority.</summary>
    H2Authority = 37,
}
