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

    /// <summary>
    /// A field name is a token without upper-case letters (RFC 9113 8.2.1, RFC 9110 5.1): one
    /// octet that is not, at any place in a name of any length, makes the request malformed. The
    /// lengths cross the 16-octet steps of the vector check (h2_name from v2), so a flaw in a
    /// step, in the overlapping last step and in a short name's single read is each refused,
    /// at every tier the suite runs on.
    /// </summary>
    /// <param name="flaw">The octet put at each place in turn.</param>
    [Theory]
    [InlineData('A')]
    [InlineData('Z')]
    [InlineData('@')]
    [InlineData(' ')]
    [InlineData('\x7f')]
    [InlineData('\x80')]
    [Requirement("RFC9113-8.2.1-3.1")]
    public void RefusesAnOctetANameMayNotHoldAtEveryPlace(char flaw)
    {
        Platform.RequireLinuxX64();
        for (int length = 1; length <= 40; length++)
        {
            string clean = string.Concat(Enumerable.Range(0, length).Select(i => (char)('a' + i % 26)));
            (int result, _) = Http2([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "h"), (clean, "v")]);
            Assert.True(result == 0, $"a clean name of {length} octets: {result}");
            for (int at = 0; at < length; at++)
            {
                string name = clean[..at] + flaw + clean[(at + 1)..];
                (result, _) = Http2([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "h"), (name, "v")]);
                Assert.True(result == -(int)ParseError.FieldName, $"{(int)flaw:X2} at {at} of {length}: {result}");
            }
        }
    }

    /// <summary>
    /// :path holds the octets an HTTP/1.1 request-target holds, every "%" followed by two HEXDIG
    /// inside the value (RFC 3986 2.1), so neither version takes a target the other refuses: a
    /// percent-encoding at every place of paths of every length to 40 octets, valid, with a
    /// non-HEXDIG, or cut by the value's end, and a space at every place. The lengths cross the
    /// 16-octet steps of the vector check (runs between percent-encodings, from v2).
    /// </summary>
    [Fact]
    public void ChecksEveryPercentEncodingOfAPath()
    {
        Platform.RequireLinuxX64();
        for (int length = 2; length <= 40; length++)
        {
            string clean = "/" + string.Concat(Enumerable.Range(1, length - 1).Select(i => (char)('a' + i % 26)));
            for (int at = 1; at < length; at++)
            {
                foreach (string encoding in new[] { "%2F", "%zz", "%g1" })
                {
                    string path = (clean[..at] + encoding + clean[at..])[..length];   // cut to the length: a late "%" loses HEXDIG
                    int encoded = Math.Min(encoding.Length, length - at);
                    bool valid = encoding == "%2F" && encoded == 3;
                    (int result, _) = Http2([(":method", "GET"), (":scheme", "http"), (":path", path), (":authority", "h")]);
                    Assert.True(valid ? result == 0 : result == -(int)ParseError.Target, $"{path}: {result}");
                    Assert.Equal(valid, H1Parsing.Parse($"GET {path} HTTP/1.1\r\nHost: h\r\n\r\n").Result > 0);
                }

                // A space inside is a target octet missing; at the end, the value's own rule
                // (no whitespace at either end, RFC9113-8.2.1-3.4) refuses it first.
                string spaced = clean[..at] + ' ' + clean[(at + 1)..];
                (int spacedResult, _) = Http2([(":method", "GET"), (":scheme", "http"), (":path", spaced), (":authority", "h")]);
                Assert.Equal(at == length - 1 ? -(int)ParseError.FieldValue : -(int)ParseError.Target, spacedResult);
            }
        }
    }

    /// <summary>
    /// Only the request's four pseudo-fields are taken (RFC 9113 8.3): a name one octet off any of
    /// them, at its start or its end, with a letter's case changed, or of another length, is
    /// malformed. Each is the length of a real one or near it, so the compare's every outcome
    /// is met: the length, the first and the last four octets (names up to 8), the first and the
    /// last eight (":authority"'s 10).
    /// </summary>
    /// <param name="name">The pseudo-field's name.</param>
    [Theory]
    [InlineData(":xethod")]
    [InlineData(":metho_")]
    [InlineData(":Method")]
    [InlineData(":xcheme")]
    [InlineData(":schemE")]
    [InlineData(":xuthority")]
    [InlineData(":unknown-x")]
    [InlineData(":authorit_")]
    [InlineData(":xath")]
    [InlineData(":pat_")]
    [InlineData(":paths")]
    [InlineData(":protocol")]
    [InlineData(":status")]
    [InlineData(":")]
    [Requirement("RFC9113-8.3-3#4")]
    public void RefusesPseudoFieldsItDoesNotDefine(string name)
    {
        Platform.RequireLinuxX64();
        (int result, _) = Http2([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "h"), (name, "v")]);
        Assert.Equal(-(int)ParseError.H2Pseudo, result);
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
