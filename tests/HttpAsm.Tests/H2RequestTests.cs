namespace HttpAsm.Tests;

/// <summary>
/// httpasm_h2_request, the request view of a decoded HTTP/2 header list, called directly (the
/// server's frame tests reach it through HPACK and a connection; these hold its edges, which a
/// conforming client never sends).
/// </summary>
public sealed unsafe class H2RequestTests
{
    /// <summary>
    /// content-length is read up to 2^63 - 1, the largest length any HttpAsm reader takes;
    /// 2^63 and above are refused, whether the numeral wraps on its last digit (2^63 itself:
    /// value * 10 + digit turns negative) or is caught before it (more digits). HTTP/1.1's
    /// parser draws the line at the same place, so neither version takes a length the other
    /// refuses.
    /// </summary>
    /// <param name="value">content-length's value.</param>
    /// <param name="valid">Whether it is taken.</param>
    [Theory]
    [InlineData("0", true)]
    [InlineData("9223372036854775807", true)]
    [InlineData("09223372036854775807", true)]
    [InlineData("9223372036854775808", false)]
    [InlineData("9223372036854775809", false)]
    [InlineData("9223372036854775810", false)]
    [InlineData("92233720368547758070", false)]
    [InlineData("99999999999999999999", false)]
    [Requirement("RFC9110-8.6-10", "RFC9110-8.6-2")]
    public void ReadsContentLengthUpTo2To63Minus1(string value, bool valid)
    {
        Platform.RequireLinuxX64();
        (int result, HttpRequest request) = Http2([(":method", "POST"), (":scheme", "http"), (":path", "/"), (":authority", "h"), ("content-length", value)]);
        if (valid)
        {
            Assert.Equal(0, result);
            Assert.Equal(ulong.Parse(value), request.ContentLength);
        }
        else
        {
            Assert.Equal(-(int)ParseError.ContentLength, result);
        }

        ParsedRequest h1 = H1Parsing.Parse($"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {value}\r\n\r\n");
        Assert.Equal(valid, h1.Result > 0);
    }

    /// <summary>
    /// A field with an empty name is malformed (RFC 9110 5.1: field-name = token, one tchar at
    /// least): HPACK can carry one (a literal with a name of length 0), so the request view
    /// must refuse it, whatever its value.
    /// </summary>
    /// <param name="value">The field's value.</param>
    [Theory]
    [InlineData("v")]
    [InlineData("")]
    [Requirement("RFC9110-5.1-2", "RFC9110-5.6.2-2")]
    public void RefusesAnEmptyFieldName(string value)
    {
        Platform.RequireLinuxX64();
        (int result, _) = Http2([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "h"), ("", value)]);
        Assert.Equal(-(int)ParseError.FieldName, result);
    }

    /// <summary>Calls httpasm_h2_request on a decoded header list.</summary>
    /// <param name="fields">The fields, pseudo-fields first.</param>
    /// <returns>Its result (0, or -HTTPASM_ERROR_*) and the request it filled.</returns>
    private static (int Result, HttpRequest Request) Http2((string, string)[] fields)
    {
        using var native = new NativeFields(fields);
        HttpRequest request = default;
        int result = Native.H2Request(native.Pointer, native.Count, &request);
        return (result, request);
    }
}
