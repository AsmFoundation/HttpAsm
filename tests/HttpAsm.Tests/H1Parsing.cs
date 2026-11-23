using System.Text;

namespace HttpAsm.Tests;

/// <summary>A field line as the parser reported it, copied out of the pinned buffer.</summary>
/// <param name="Name">The name as received.</param>
/// <param name="Value">The value, OWS trimmed.</param>
/// <param name="Id">The known-field id, 0 when not known.</param>
/// <param name="Flags">HTTPASM_FIELD_FLAG_*.</param>
internal sealed record ParsedField(string Name, string Value, int Id, int Flags);

/// <summary>A request head as httpasm_h1_parse_request reported it, copied out of the pinned buffer.</summary>
/// <param name="Result">The return value: the head's length, 0 incomplete, or -status.</param>
/// <param name="Method">The method.</param>
/// <param name="MethodId">HTTPASM_METHOD_*.</param>
/// <param name="Target">The request-target.</param>
/// <param name="TargetForm">HTTPASM_TARGET_*.</param>
/// <param name="Authority">The authority, or null.</param>
/// <param name="Scheme">The scheme, or null.</param>
/// <param name="Version">10 or 11.</param>
/// <param name="Flags">HTTPASM_REQUEST_*.</param>
/// <param name="ContentLength">The body's length, with the CONTENT_LENGTH flag.</param>
/// <param name="Error">Why a head was refused.</param>
/// <param name="HeadLength">The head's octets.</param>
/// <param name="Fields">The field lines.</param>
internal sealed record ParsedRequest(
    long Result, string? Method, int MethodId, string? Target, int TargetForm, string? Authority, string? Scheme,
    int Version, uint Flags, ulong ContentLength, ParseError Error, uint HeadLength, IReadOnlyList<ParsedField> Fields)
{
    /// <summary>The value of the first field with this name (case-insensitive), or null.</summary>
    /// <param name="name">The field name.</param>
    /// <returns>The value, or null.</returns>
    public string? Field(string name) => Fields.FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))?.Value;
}

/// <summary>Calls httpasm_h1_parse_request and copies what it reports into managed records.</summary>
internal static unsafe class H1Parsing
{
    /// <summary>Parses one head from the start of a buffer, as a server's first read would.</summary>
    /// <param name="text">The octets, as Latin-1 text.</param>
    /// <param name="limits">The limits (zero fields take the defaults).</param>
    /// <param name="fieldCapacity">How many field records the array holds.</param>
    /// <returns>What the parser reported.</returns>
    public static ParsedRequest Parse(string text, H1Limits limits = default, int fieldCapacity = 128)
    {
        nuint scanFrom = 0;
        byte[] bytes = Encoding.Latin1.GetBytes(text);
        return Parse(bytes, bytes.Length, ref scanFrom, limits, fieldCapacity);
    }

    /// <summary>Parses a buffer's first <paramref name="length"/> octets, carrying the resume point.</summary>
    /// <param name="buffer">The octets.</param>
    /// <param name="length">How many of them have arrived.</param>
    /// <param name="scanFrom">The resume point, carried between calls on one message.</param>
    /// <param name="limits">The limits.</param>
    /// <param name="fieldCapacity">How many field records the array holds.</param>
    /// <returns>What the parser reported, copied while the buffer is pinned.</returns>
    public static ParsedRequest Parse(byte[] buffer, int length, ref nuint scanFrom, H1Limits limits = default, int fieldCapacity = 128)
    {
        var fields = new HttpField[Math.Max(fieldCapacity, 1)];
        if (limits.MaxFields == 0)
        {
            limits.MaxFields = (uint)fieldCapacity;
        }

        HttpRequest request;
        fixed (byte* p = buffer)
        fixed (HttpField* f = fields)
        fixed (nuint* s = &scanFrom)
        {
            long result = Native.H1ParseRequest(p, (nuint)length, s, &limits, &request, f);
            byte* end = p + length;

            var parsed = new List<ParsedField>();
            for (int i = 0; i < request.FieldCount; i++)
            {
                parsed.Add(new ParsedField(
                    Text(f[i].Name, f[i].NameLength, p, end)!, Text(f[i].Value, f[i].ValueLength, p, end)!, f[i].Id, f[i].Flags));
            }

            return new ParsedRequest(
                result, Text(request.Method, request.MethodLength, p, end), request.MethodId,
                Text(request.Target, request.TargetLength, p, end), request.TargetForm,
                Text(request.Authority, request.AuthorityLength, p, end), Text(request.Scheme, request.SchemeLength, p, end),
                request.Version, request.Flags, request.ContentLength, (ParseError)request.Error, request.HeadLength, parsed);
        }
    }

    /// <summary>Copies a reported span out of the buffer, after checking that it lies inside it.</summary>
    /// <param name="at">The span's start, or null.</param>
    /// <param name="count">Its length.</param>
    /// <param name="start">The buffer's start.</param>
    /// <param name="end">The end of the octets the parser was given.</param>
    /// <returns>The span as Latin-1 text, or null when <paramref name="at"/> is null.</returns>
    private static string? Text(byte* at, uint count, byte* start, byte* end)
    {
        if (at == null)
        {
            return null;
        }

        // A pointer the parser reports must lie inside the octets it was given.
        Assert.True(at >= start && at + count <= end, "a reported pointer lies outside the buffer");
        return Encoding.Latin1.GetString(at, (int)count);
    }

    /// <summary>The known-field id of a name, through the C ABI.</summary>
    /// <param name="name">The name.</param>
    /// <returns>The id, 0 when not known.</returns>
    public static int FieldId(string name)
    {
        byte[] bytes = Encoding.Latin1.GetBytes(name);
        fixed (byte* p = bytes)
        {
            return (int)Native.FieldId(p, (nuint)bytes.Length);
        }
    }
}
