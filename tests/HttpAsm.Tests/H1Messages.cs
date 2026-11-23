using System.Runtime.InteropServices;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// Field records in native memory, for the writers: the names and values live in one native
/// block next to the records, so their pointers stay valid until <see cref="Dispose"/>.
/// </summary>
internal sealed unsafe class NativeFields : IDisposable
{
    /// <summary>The records followed by their text.</summary>
    private readonly byte* block;

    /// <summary>Lays out the fields.</summary>
    /// <param name="fields">(name, value) pairs, as Latin-1 text.</param>
    public NativeFields(params (string Name, string Value)[] fields)
    {
        Count = (uint)fields.Length;
        int text = fields.Sum(f => f.Name.Length + f.Value.Length);
        block = (byte*)NativeMemory.AllocZeroed((nuint)(fields.Length * sizeof(HttpField) + text + 1));
        Pointer = (HttpField*)block;
        byte* cursor = block + fields.Length * sizeof(HttpField);
        for (int i = 0; i < fields.Length; i++)
        {
            Pointer[i].Name = cursor;
            Pointer[i].NameLength = (uint)Encoding.Latin1.GetBytes(fields[i].Name, new Span<byte>(cursor, fields[i].Name.Length));
            cursor += fields[i].Name.Length;
            Pointer[i].Value = cursor;
            Pointer[i].ValueLength = (uint)Encoding.Latin1.GetBytes(fields[i].Value, new Span<byte>(cursor, fields[i].Value.Length));
            cursor += fields[i].Value.Length;
        }
    }

    /// <summary>The records.</summary>
    public HttpField* Pointer { get; }

    /// <summary>How many.</summary>
    public uint Count { get; }

    /// <summary>Frees the block.</summary>
    public void Dispose() => NativeMemory.Free(block);
}

/// <summary>A response head as httpasm_h1_parse_response reported it.</summary>
/// <param name="Result">The head's length, 0 incomplete, or -status.</param>
/// <param name="Status">The status code.</param>
/// <param name="Reason">The reason-phrase.</param>
/// <param name="Version">10 or 11.</param>
/// <param name="Flags">HTTPASM_RESPONSE_HEAD_*.</param>
/// <param name="ContentLength">With the CONTENT_LENGTH flag.</param>
/// <param name="Error">Why it was refused.</param>
/// <param name="Fields">The field lines.</param>
internal sealed record ParsedResponse(
    long Result, int Status, string? Reason, int Version, uint Flags, ulong ContentLength, ParseError Error, IReadOnlyList<ParsedField> Fields)
{
    /// <summary>The value of the first field with this name (case-insensitive), or null.</summary>
    /// <param name="name">The name.</param>
    /// <returns>The value, or null.</returns>
    public string? Field(string name) => Fields.FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;
}

/// <summary>Calls the HTTP/1.1 writers, the response parser and the chunked codec.</summary>
internal static unsafe class H1Messages
{
    /// <summary>A fixed IMF-fixdate (RFC 9110 5.6.7's example).</summary>
    public const string Date = "Sun, 06 Nov 1994 08:49:37 GMT";

    /// <summary>Writes a response head.</summary>
    /// <param name="status">The status.</param>
    /// <param name="fields">The handler's fields.</param>
    /// <param name="length">The body's length, or null when unknown.</param>
    /// <param name="version">The request's version.</param>
    /// <param name="method">The request's method id.</param>
    /// <param name="close">Whether the connection closes after.</param>
    /// <param name="date">The Date value, or null.</param>
    /// <param name="capacity">The output's size.</param>
    /// <returns>The result, the head's text, and the flags the writer reported.</returns>
    public static (long Result, string Text, uint Flags) WriteResponse(
        int status, (string, string)[]? fields = null, long? length = null, int version = 11, int method = 1,
        bool close = false, string? date = Date, int capacity = 4096)
    {
        using var native = new NativeFields(fields ?? []);
        byte[] output = new byte[capacity];
        byte[]? dateBytes = date is null ? null : Encoding.ASCII.GetBytes(date);
        fixed (byte* o = output)
        fixed (byte* d = dateBytes)
        {
            var response = new HttpResponse
            {
                Fields = native.Pointer,
                FieldCount = native.Count,
                Date = d,
                Status = (ushort)status,
                RequestVersion = (byte)version,
                RequestMethod = (byte)method,
                ContentLength = (ulong)(length ?? 0),
                Flags = (length.HasValue ? Abi.ResponseLength : 0) | (close ? Abi.ResponseClose : 0),
            };
            long result = Native.H1WriteResponse(o, (nuint)capacity, &response);
            string text = result > 0 ? Encoding.Latin1.GetString(o, (int)result) : "";
            return (result, text, response.Flags);
        }
    }

    /// <summary>Writes a request head.</summary>
    /// <param name="method">The method.</param>
    /// <param name="target">The request-target.</param>
    /// <param name="authority">Host's value.</param>
    /// <param name="fields">The caller's fields.</param>
    /// <param name="flags">HTTPASM_REQUEST_* framing flags.</param>
    /// <param name="length">content_length.</param>
    /// <param name="capacity">The output's size.</param>
    /// <returns>The result and the head's text.</returns>
    public static (long Result, string Text) WriteRequest(
        string method, string target, string authority, (string, string)[]? fields = null, uint flags = 0, ulong length = 0, int capacity = 4096)
    {
        using var native = new NativeFields(fields ?? []);
        byte[] m = Encoding.Latin1.GetBytes(method), t = Encoding.Latin1.GetBytes(target), a = Encoding.Latin1.GetBytes(authority);
        byte[] output = new byte[capacity];
        fixed (byte* o = output)
        fixed (byte* mp = m)
        fixed (byte* tp = t)
        fixed (byte* ap = a)
        {
            var request = new HttpRequest
            {
                Method = mp, MethodLength = (uint)m.Length, Target = tp, TargetLength = (uint)t.Length,
                Authority = ap, AuthorityLength = (uint)a.Length, Fields = native.Pointer, FieldCount = native.Count,
                Flags = flags, ContentLength = length,
            };
            long result = Native.H1WriteRequest(o, (nuint)capacity, &request);
            return (result, result > 0 ? Encoding.Latin1.GetString(o, (int)result) : "");
        }
    }

    /// <summary>Parses a response head from the start of a buffer.</summary>
    /// <param name="text">The octets, as Latin-1 text.</param>
    /// <param name="method">The request's method id.</param>
    /// <param name="joined">Receives the buffer after parsing (obs-fold is joined in place).</param>
    /// <returns>What the parser reported.</returns>
    public static ParsedResponse ParseResponse(string text, int method, out string joined)
    {
        byte[] buffer = Encoding.Latin1.GetBytes(text);
        var fields = new HttpField[64];
        var limits = new H1Limits { MaxFields = 64 };
        nuint scanFrom = 0;
        ResponseHead head;
        fixed (byte* p = buffer)
        fixed (HttpField* f = fields)
        {
            long result = Native.H1ParseResponse(p, (nuint)buffer.Length, &scanFrom, &limits, (uint)method, &head, f);
            var parsed = new List<ParsedField>();
            for (int i = 0; i < head.FieldCount; i++)
            {
                parsed.Add(new ParsedField(
                    Encoding.Latin1.GetString(f[i].Name, (int)f[i].NameLength),
                    Encoding.Latin1.GetString(f[i].Value, (int)f[i].ValueLength), f[i].Id, f[i].Flags));
            }

            joined = Encoding.Latin1.GetString(buffer);
            string? reason = head.Reason == null ? null : Encoding.Latin1.GetString(head.Reason, (int)head.ReasonLength);
            return new ParsedResponse(result, head.Status, reason, head.Version, head.Flags, head.ContentLength, (ParseError)head.Error, parsed);
        }
    }

    /// <summary>Parses a response head from the start of a buffer.</summary>
    /// <param name="text">The octets, as Latin-1 text.</param>
    /// <param name="method">The request's method id (GET by default).</param>
    /// <returns>What the parser reported.</returns>
    public static ParsedResponse ParseResponse(string text, int method = 1) => ParseResponse(text, method, out _);

    /// <summary>Decodes a chunked body fed in pieces, the way a connection receives it.</summary>
    /// <param name="body">The body octets.</param>
    /// <param name="piece">How many octets arrive per read.</param>
    /// <param name="state">Receives the decoder's final state.</param>
    /// <param name="rest">Receives the octets after the last chunk's line: the trailer section and beyond.</param>
    /// <returns>The data, or null when the decoder refused the framing.</returns>
    public static byte[]? DecodeChunked(byte[] body, int piece, out ChunkedState state, out byte[] rest)
    {
        state = default;
        var buffer = new List<byte>();          // received and not yet consumed
        var data = new List<byte>();
        int offset = 0;
        rest = [];
        while (offset < body.Length || buffer.Count > 0)
        {
            int take = Math.Min(piece, body.Length - offset);
            buffer.AddRange(body.AsSpan(offset, take).ToArray());
            offset += take;
            byte[] work = buffer.ToArray();
            nuint produced;
            long consumed;
            fixed (byte* w = work)
            fixed (ChunkedState* s = &state)
            {
                consumed = Native.H1ChunkedDecode(s, w, (nuint)work.Length, &produced);
            }

            if (consumed < 0)
            {
                return null;
            }

            data.AddRange(work.AsSpan(0, (int)produced).ToArray());
            buffer = work.AsSpan((int)consumed).ToArray().ToList();
            if (state.State == Abi.ChunkedTrailers)
            {
                buffer.AddRange(body.AsSpan(offset).ToArray());
                rest = buffer.ToArray();
                return data.ToArray();
            }

            if (take == 0)
            {
                break;                      // no more input and the body has not ended
            }
        }

        return data.ToArray();
    }

    /// <summary>Parses a trailer section.</summary>
    /// <param name="text">The octets after the last chunk's line.</param>
    /// <param name="count">Receives how many trailer fields.</param>
    /// <param name="fields">Receives them.</param>
    /// <returns>The section's length, 0, or -status.</returns>
    public static long ParseTrailers(string text, out uint count, out List<ParsedField> fields)
    {
        byte[] buffer = Encoding.Latin1.GetBytes(text);
        var records = new HttpField[16];
        var limits = new H1Limits { MaxFields = 16 };
        nuint scanFrom = 0;
        uint n;
        long result;
        fields = [];
        fixed (byte* p = buffer)
        fixed (HttpField* f = records)
        {
            result = Native.H1ParseTrailers(p, (nuint)buffer.Length, &scanFrom, &limits, f, &n);
            for (int i = 0; i < n; i++)
            {
                fields.Add(new ParsedField(
                    Encoding.Latin1.GetString(f[i].Name, (int)f[i].NameLength),
                    Encoding.Latin1.GetString(f[i].Value, (int)f[i].ValueLength), f[i].Id, f[i].Flags));
            }
        }

        count = n;
        return result;
    }
}
