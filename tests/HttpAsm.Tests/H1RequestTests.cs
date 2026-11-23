using System.Runtime.CompilerServices;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// httpasm_h1_parse_request: HTTP/1.1 request heads (RFC 9112), read through the C ABI with no
/// sockets. Each test names the registry rows it proves.
/// </summary>
public sealed class H1RequestTests
{
    /// <summary>A Host line, for the tests that are not about Host.</summary>
    private const string Host = "Host: example.com\r\n";

    /// <summary>The .NET copies of the structures have the library's sizes.</summary>
    [Fact]
    public void StructuresMatchTheLibrary()
    {
        Platform.RequireLinuxX64();
        Assert.Equal((uint)Unsafe.SizeOf<HttpField>(), Native.StructSize(1));
        Assert.Equal((uint)Unsafe.SizeOf<HttpRequest>(), Native.StructSize(2));
        Assert.Equal((uint)Unsafe.SizeOf<H1Limits>(), Native.StructSize(3));
        Assert.Equal(32, Unsafe.SizeOf<HttpField>());
        Assert.Equal(96, Unsafe.SizeOf<HttpRequest>());
        Assert.Equal(0u, Native.StructSize(99));
    }

    /// <summary>A plain GET: every part reported, pointers into the buffer, fields with their ids.</summary>
    [Fact]
    [Requirement("RFC9112-2.1-2", "RFC9112-3-2", "RFC9112-3.1-2", "RFC9112-3.2.1-2", "RFC9112-2.3-3", "RFC9112-5-2", "RFC9110-9.1-4",
        "RFC9112-2.1-4", "RFC9110-5.1-6#2")]
    public void ParsesAGet()
    {
        Platform.RequireLinuxX64();
        string head = "GET /index.html?q=1&x=%2F HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: test/1.0\r\nX-Custom:  padded value \t\r\n\r\n";
        ParsedRequest r = H1Parsing.Parse(head + "body that follows");
        Assert.Equal(head.Length, r.Result);
        Assert.Equal((uint)head.Length, r.HeadLength);
        Assert.Equal(ParseError.None, r.Error);
        Assert.Equal("GET", r.Method);
        Assert.Equal(Abi.Methods["GET"], r.MethodId);
        Assert.Equal("/index.html?q=1&x=%2F", r.Target);
        Assert.Equal(Abi.TargetOrigin, r.TargetForm);
        Assert.Equal("example.com:8080", r.Authority);
        Assert.Null(r.Scheme);
        Assert.Equal(11, r.Version);
        Assert.Equal(Abi.RequestKeepAlive | Abi.RequestHost, r.Flags);
        Assert.Equal(3, r.Fields.Count);
        Assert.Equal(new ParsedField("Host", "example.com:8080", H1Parsing.FieldId("host"), 0), r.Fields[0]);
        Assert.Equal("test/1.0", r.Field("user-agent"));
        Assert.Equal("padded value", r.Field("x-custom"));
        Assert.Equal(0, r.Fields[2].Id);
        Assert.NotEqual(0, r.Fields[1].Id);
    }

    /// <summary>
    /// Bytes arriving one at a time: every prefix is incomplete (0) and the whole head parses, with
    /// the resume point carried so each octet is scanned for the head's end once.
    /// </summary>
    [Fact]
    public void ParsesAHeadArrivingOctetByOctet()
    {
        Platform.RequireLinuxX64();
        byte[] head = Encoding.Latin1.GetBytes("POST /upload HTTP/1.1\r\n" + Host + "Content-Length: 5\r\n\r\nhello");
        int headLength = head.Length - 5;
        nuint scanFrom = 0;
        for (int length = 0; length < headLength; length++)
        {
            ParsedRequest partial = H1Parsing.Parse(head, length, ref scanFrom);
            Assert.True(partial.Result == 0, $"prefix {length}: {partial.Result}");
            Assert.True(scanFrom <= (nuint)length, "the resume point lies past the data");
        }

        ParsedRequest r = H1Parsing.Parse(head, head.Length, ref scanFrom);
        Assert.Equal(headLength, r.Result);
        Assert.Equal(0u, (uint)scanFrom);
        Assert.Equal(5ul, r.ContentLength);
        Assert.Equal(Abi.RequestContentLength, r.Flags & Abi.RequestContentLength);
    }

    /// <summary>Empty lines before the request-line are skipped (and counted in the head's length).</summary>
    [Fact]
    [Requirement("RFC9112-2.2-6")]
    public void SkipsEmptyLinesBeforeTheRequestLine()
    {
        Platform.RequireLinuxX64();
        string head = "\r\n\r\nGET / HTTP/1.1\r\n" + Host + "\r\n";
        ParsedRequest r = H1Parsing.Parse(head);
        Assert.Equal(head.Length, r.Result);
        Assert.Equal("GET", r.Method);
    }

    /// <summary>A bare LF ends no line here: HttpAsm does not take RFC 9112's leniency.</summary>
    /// <param name="head">A head with one LF that lacks its CR.</param>
    [Theory]
    [InlineData("GET / HTTP/1.1\nHost: a\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: a\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: a\r\n\n")]
    [InlineData("\nGET / HTTP/1.1\r\nHost: a\r\n\r\n")]
    [Requirement("RFC9112-2.2-3", "RFC9112-2.1-2")]
    public void RefusesABareLf(string head)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse(head);
        Assert.Equal(-400, r.Result);
        Assert.Equal(ParseError.BareLf, r.Error);
    }

    /// <summary>A bare CR makes its element invalid, wherever it sits.</summary>
    /// <param name="head">A head with a CR not followed by LF.</param>
    /// <param name="error">The element that refuses it.</param>
    [Theory]
    [InlineData("GET /a\rb HTTP/1.1\r\nHost: a\r\n\r\n", ParseError.RequestLine)]
    [InlineData("GET / HTTP/1.1\rX\r\nHost: a\r\n\r\n", ParseError.Version)]
    [InlineData("GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", ParseError.FieldValue)]
    [InlineData("GET / HTTP/1.1\r\nHo\rst: a\r\n\r\n", ParseError.FieldName)]
    [Requirement("RFC9112-2.2-4#2")]
    public void RefusesABareCr(string head, ParseError error)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse(head);
        Assert.Equal(-400, r.Result);
        Assert.Equal(error, r.Error);
    }

    /// <summary>Whitespace before the first field line is refused, as is obsolete line folding.</summary>
    /// <param name="head">The head.</param>
    [Theory]
    [InlineData("GET / HTTP/1.1\r\n Host: a\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\n\tHost: a\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: a\r\nX-Folded: one\r\n two\r\n\r\n")]
    [Requirement("RFC9112-2.2-8", "RFC9112-5.2-4", "RFC9112-5.2-2")]
    public void RefusesLinesThatStartWithWhitespace(string head)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse(head);
        Assert.Equal(-400, r.Result);
        Assert.Equal(ParseError.ObsFold, r.Error);
    }

    /// <summary>Whitespace between a field name and its colon is a 400.</summary>
    /// <param name="head">The head.</param>
    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost : a\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: a\r\nX-A\t: b\r\n\r\n")]
    [Requirement("RFC9112-5.1-2#1")]
    public void RefusesWhitespaceBeforeTheColon(string head)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse(head);
        Assert.Equal(-400, r.Result);
        Assert.Equal(ParseError.WhitespaceBeforeColon, r.Error);
    }

    /// <summary>Field names are tokens, never empty; a line without a colon is not a field line.</summary>
    /// <param name="line">The offending field line.</param>
    [Theory]
    [InlineData(": empty name")]
    [InlineData("No-Colon")]
    [InlineData("Bad(Name): v")]
    [InlineData("Bad\"Name: v")]
    [Requirement("RFC9110-5.1-2", "RFC9112-5-2")]
    public void RefusesInvalidFieldNames(string line)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}{line}\r\n\r\n");
        Assert.Equal(-400, r.Result);
        Assert.Equal(ParseError.FieldName, r.Error);
    }

    /// <summary>A field value holding a control character is refused; HTAB and obs-text are not.</summary>
    [Fact]
    [Requirement("RFC9110-5.5-5#1", "RFC9110-5.5-5#2", "RFC9110-5.5-2", "RFC9110-5.5-4#2", "RFC9112-2.2-2", "RFC9110-5.5-3",
        "RFC9110-5.6.3-7")]
    public void ChecksFieldValues()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(ParseError.FieldValue, H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}X: a\0b\r\n\r\n").Error);
        Assert.Equal(ParseError.FieldValue, H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}X: a\u0001b\r\n\r\n").Error);
        Assert.Equal(ParseError.FieldValue, H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}X: a\u007Fb\r\n\r\n").Error);
        ParsedRequest ok = H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}X: tab\there and café\r\n\r\n");
        Assert.True(ok.Result > 0);
        Assert.Equal("tab\there and café", ok.Field("x"));
        // Whitespace around a value (OWS: SP and HTAB, any amount) is not part of it.
        Assert.Equal("padded", H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}X:\t \tpadded \t \r\n\r\n").Field("x"));
    }

    /// <summary>The request-line's elements are separated by single SPs; any other spacing is a 400.</summary>
    /// <param name="line">The request-line.</param>
    /// <param name="error">The rule that refuses it.</param>
    [Theory]
    [InlineData("GET  / HTTP/1.1", ParseError.RequestLine)]
    [InlineData("GET /  HTTP/1.1", ParseError.Version)]
    [InlineData("GET\t/ HTTP/1.1", ParseError.RequestLine)]
    [InlineData("GET / HTTP/1.1 ", ParseError.Version)]
    [InlineData("GET /", ParseError.RequestLine)]
    [InlineData(" GET / HTTP/1.1", ParseError.Method)]
    [InlineData("G(T / HTTP/1.1", ParseError.Method)]
    [Requirement("RFC9112-3-2", "RFC9112-3-3", "RFC9112-3.2-4#1", "RFC9112-3.2-4#2")]
    public void RefusesMalformedRequestLines(string line, ParseError error)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"{line}\r\n{Host}\r\n");
        Assert.Equal(-400, r.Result);
        Assert.Equal(error, r.Error);
    }

    /// <summary>Methods are case-sensitive tokens; the known ones get ids, any other token is accepted with id 0.</summary>
    [Fact]
    [Requirement("RFC9110-9.1-4", "RFC9112-3.1-2")]
    public void IdentifiesMethods()
    {
        Platform.RequireLinuxX64();
        foreach ((string method, int id) in Abi.Methods)
        {
            string target = method switch { "CONNECT" => "example.com:443", "OPTIONS" => "*", _ => "/" };
            ParsedRequest r = H1Parsing.Parse($"{method} {target} HTTP/1.1\r\n{Host}\r\n");
            Assert.True(r.Result > 0, method);
            Assert.Equal(id, r.MethodId);
        }

        Assert.Equal(0, H1Parsing.Parse($"get / HTTP/1.1\r\n{Host}\r\n").MethodId);
        Assert.Equal(0, H1Parsing.Parse($"PROPFIND / HTTP/1.1\r\n{Host}\r\n").MethodId);
        Assert.Equal(0, H1Parsing.Parse($"GETS / HTTP/1.1\r\n{Host}\r\n").MethodId);
    }

    /// <summary>HTTP/1.0 and HTTP/1.1; a higher minor is read as 1.1; another major is 505; anything else 400.</summary>
    /// <param name="version">The HTTP-version.</param>
    /// <param name="expected">The version reported, or the negative status.</param>
    [Theory]
    [InlineData("HTTP/1.1", 11)]
    [InlineData("HTTP/1.0", 10)]
    [InlineData("HTTP/1.9", 11)]
    [InlineData("HTTP/2.0", -505)]
    [InlineData("HTTP/0.9", -505)]
    [InlineData("http/1.1", -400)]
    [InlineData("HTTP/1.10", -400)]
    [InlineData("HTTP/11", -400)]
    [InlineData("HTTP/1.", -400)]
    [Requirement("RFC9112-2.3-3", "RFC9110-6.2-8")]
    public void ReadsTheVersion(string version, int expected)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET / {version}\r\n{Host}\r\n");
        if (expected > 0)
        {
            Assert.True(r.Result > 0);
            Assert.Equal(expected, r.Version);
        }
        else
        {
            Assert.Equal(expected, r.Result);
        }
    }

    /// <summary>The request-target holds only URI octets, with whole percent-encodings.</summary>
    /// <param name="target">The target.</param>
    [Theory]
    [InlineData("/a b")]
    [InlineData("/a\"b")]
    [InlineData("/a<b")]
    [InlineData("/a{b}")]
    [InlineData("/a|b")]
    [InlineData("/a#fragment")]
    [InlineData("/%zz")]
    [InlineData("/%4")]
    [InlineData("/café")]
    [Requirement("RFC9112-3.2-4#1")]
    public void RefusesTargetsThatAreNotUris(string target)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET {target} HTTP/1.1\r\n{Host}\r\n");
        Assert.Equal(-400, r.Result);
    }

    /// <summary>A target over the limit is a 414; the default limit takes request-lines of 8000 octets.</summary>
    [Fact]
    [Requirement("RFC9112-3-4#2", "RFC9112-3-5")]
    public void AnswersTargetsTooLongWith414()
    {
        Platform.RequireLinuxX64();
        string eightThousand = "/" + new string('a', 7999 - "GET  HTTP/1.1".Length);
        Assert.True(H1Parsing.Parse($"GET {eightThousand} HTTP/1.1\r\n{Host}\r\n").Result > 0);
        ParsedRequest r = H1Parsing.Parse($"GET /{new string('a', 200)} HTTP/1.1\r\n{Host}\r\n", new H1Limits { MaxTarget = 100 });
        Assert.Equal(-414, r.Result);
        Assert.Equal(ParseError.TargetTooLong, r.Error);
    }

    /// <summary>The absolute-form is accepted; its authority is the request's, and Host is ignored.</summary>
    [Fact]
    [Requirement("RFC9112-3.2.2-9", "RFC9112-3.2.2-8", "RFC9112-3.2.2-2", "RFC9110-4.2.1-2", "RFC9110-4.2.2-2", "RFC9110-4.2.4-4")]
    public void AcceptsTheAbsoluteForm()
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse("GET http://origin.example:81/p?q HTTP/1.1\r\nHost: other.example\r\n\r\n");
        Assert.True(r.Result > 0);
        Assert.Equal(Abi.TargetAbsolute, r.TargetForm);
        Assert.Equal("http", r.Scheme);
        Assert.Equal("origin.example:81", r.Authority);

        ParsedRequest secure = H1Parsing.Parse("GET https://origin.example HTTP/1.1\r\nHost: origin.example\r\n\r\n");
        Assert.Equal(("https", "origin.example"), (secure.Scheme, secure.Authority));
        // userinfo in an http(s) URI hides the authority it seems to name: an error.
        ParsedRequest disguised = H1Parsing.Parse("GET http://bank.example@evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n");
        Assert.Equal((-400, ParseError.TargetForm), (disguised.Result, disguised.Error));
    }

    /// <summary>An http or https URI without a host is invalid.</summary>
    /// <param name="target">The target.</param>
    [Theory]
    [InlineData("http:///path")]
    [InlineData("https://:443/")]
    [InlineData("HTTP:/x")]
    [Requirement("RFC9110-4.2.1-4#2", "RFC9110-4.2.2-4#2")]
    public void RefusesHttpUrisWithoutAHost(string target)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET {target} HTTP/1.1\r\n{Host}\r\n");
        Assert.Equal(-400, r.Result);
        Assert.Equal(ParseError.TargetForm, r.Error);
    }

    /// <summary>CONNECT takes exactly host:port; the authority-form serves nothing else; "*" serves OPTIONS only.</summary>
    /// <param name="line">The request-line.</param>
    /// <param name="accepted">Whether it parses.</param>
    [Theory]
    [InlineData("CONNECT example.com:443 HTTP/1.1", true)]
    [InlineData("CONNECT [2001:db8::1]:443 HTTP/1.1", true)]
    [InlineData("CONNECT example.com HTTP/1.1", false)]
    [InlineData("CONNECT example.com: HTTP/1.1", false)]
    [InlineData("CONNECT :443 HTTP/1.1", false)]
    [InlineData("CONNECT /path HTTP/1.1", false)]
    [InlineData("CONNECT user@example.com:443 HTTP/1.1", false)]
    [InlineData("OPTIONS * HTTP/1.1", true)]
    [InlineData("GET * HTTP/1.1", false)]
    [InlineData("OPTIONS *x HTTP/1.1", false)]
    [Requirement("RFC9112-3.2-2", "RFC9112-3.2.3-2", "RFC9112-3.2.4-2", "RFC9110-9.3.6-4", "RFC9110-7.1-6")]
    public void MatchesTheTargetFormToTheMethod(string line, bool accepted)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"{line}\r\n{Host}\r\n");
        if (accepted)
        {
            Assert.True(r.Result > 0, $"{line}: {r.Error}");
        }
        else
        {
            Assert.Equal(-400, r.Result);
            Assert.Equal(ParseError.TargetForm, r.Error);
        }
    }

    /// <summary>CONNECT's authority is its target; OPTIONS * keeps Host's.</summary>
    [Fact]
    [Requirement("RFC9112-3.2.3-2")]
    public void ReportsTheAuthorityOfEachForm()
    {
        Platform.RequireLinuxX64();
        ParsedRequest connect = H1Parsing.Parse("CONNECT tunnel.example:443 HTTP/1.1\r\nHost: tunnel.example:443\r\n\r\n");
        Assert.Equal(Abi.TargetAuthority, connect.TargetForm);
        Assert.Equal("tunnel.example:443", connect.Authority);
        ParsedRequest options = H1Parsing.Parse("OPTIONS * HTTP/1.1\r\nHost: h.example\r\n\r\n");
        Assert.Equal(Abi.TargetAsterisk, options.TargetForm);
        Assert.Equal("h.example", options.Authority);
    }

    /// <summary>HTTP/1.1 needs exactly one Host with a valid value; HTTP/1.0 may omit it.</summary>
    /// <param name="fields">The field lines.</param>
    /// <param name="version">The HTTP-version.</param>
    /// <param name="error">The refusal, or None.</param>
    [Theory]
    [InlineData("", "HTTP/1.1", ParseError.HostMissing)]
    [InlineData("", "HTTP/1.0", ParseError.None)]
    [InlineData("Host: a\r\nHost: a\r\n", "HTTP/1.1", ParseError.HostDuplicate)]
    [InlineData("Host: a\r\nHost: a\r\n", "HTTP/1.0", ParseError.HostDuplicate)]
    [InlineData("Host: \r\n", "HTTP/1.1", ParseError.None)]
    [InlineData("Host: [::1]:8080\r\n", "HTTP/1.1", ParseError.None)]
    [InlineData("Host: 192.0.2.1\r\n", "HTTP/1.1", ParseError.None)]
    [InlineData("Host: ex%41mple.com\r\n", "HTTP/1.1", ParseError.None)]
    [InlineData("Host: a b\r\n", "HTTP/1.1", ParseError.HostInvalid)]
    [InlineData("Host: user@a\r\n", "HTTP/1.1", ParseError.HostInvalid)]
    [InlineData("Host: a/b\r\n", "HTTP/1.1", ParseError.HostInvalid)]
    [InlineData("Host: a:8x\r\n", "HTTP/1.1", ParseError.HostInvalid)]
    [InlineData("Host: [::1\r\n", "HTTP/1.1", ParseError.HostInvalid)]
    [InlineData("Host: a%4\r\n", "HTTP/1.1", ParseError.HostInvalid)]
    [Requirement("RFC9112-3.2-6", "RFC9110-7.2-3")]
    public void RequiresOneValidHost(string fields, string version, ParseError error)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET / {version}\r\n{fields}\r\n");
        if (error == ParseError.None)
        {
            Assert.True(r.Result > 0, $"{fields}: {r.Error}");
        }
        else
        {
            Assert.Equal(-400, r.Result);
            Assert.Equal(error, r.Error);
        }
    }

    /// <summary>Content-Length: digits, or a list of identical values; anything else is a 400, overflow included.</summary>
    /// <param name="value">The field value.</param>
    /// <param name="expected">The length, or -1 for a refusal.</param>
    [Theory]
    [InlineData("0", 0L)]
    [InlineData("42", 42L)]
    [InlineData("42, 42", 42L)]
    [InlineData("42,42 ,  42", 42L)]
    [InlineData("9223372036854775807", 9223372036854775807L)]
    [InlineData("9223372036854775808", -1L)]
    [InlineData("99999999999999999999999", -1L)]
    [InlineData("42, 43", -1L)]
    [InlineData("-1", -1L)]
    [InlineData("+5", -1L)]
    [InlineData("0x10", -1L)]
    [InlineData("4 2", -1L)]
    [InlineData("", -1L)]
    [InlineData("42,", -1L)]
    [Requirement("RFC9110-8.6-2", "RFC9110-8.6-10", "RFC9112-6.3-2.5#1", "RFC9112-6.3-2.5#2")]
    public void ReadsContentLength(string value, long expected)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"POST / HTTP/1.1\r\n{Host}Content-Length: {value}\r\n\r\n");
        if (expected >= 0)
        {
            Assert.True(r.Result > 0, $"{value}: {r.Error}");
            Assert.Equal((ulong)expected, r.ContentLength);
            Assert.Equal(Abi.RequestContentLength, r.Flags & Abi.RequestContentLength);
        }
        else
        {
            Assert.Equal(-400, r.Result);
            Assert.Equal(ParseError.ContentLength, r.Error);
        }
    }

    /// <summary>Two Content-Length lines must agree.</summary>
    [Fact]
    [Requirement("RFC9112-6.3-2.5#1", "RFC9110-8.6-13#2")]
    public void RequiresContentLengthLinesToAgree()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(5ul, H1Parsing.Parse($"POST / HTTP/1.1\r\n{Host}Content-Length: 5\r\nContent-Length: 5\r\n\r\n").ContentLength);
        Assert.Equal(ParseError.ContentLength, H1Parsing.Parse($"POST / HTTP/1.1\r\n{Host}Content-Length: 5\r\nContent-Length: 6\r\n\r\n").Error);
        // One line holding a list of the same value (a duplicate merged upstream) is taken as that
        // value, the recipient's other choice besides rejecting it; a list that disagrees is no
        // length at all.
        Assert.Equal(5ul, H1Parsing.Parse($"POST / HTTP/1.1\r\n{Host}Content-Length: 5, 5\r\n\r\n").ContentLength);
        Assert.Equal(ParseError.ContentLength, H1Parsing.Parse($"POST / HTTP/1.1\r\n{Host}Content-Length: 5, 6\r\n\r\n").Error);
    }

    /// <summary>Transfer-Encoding: chunked as the final coding, once, in HTTP/1.1, without Content-Length.</summary>
    /// <param name="fields">The framing field lines.</param>
    /// <param name="version">The HTTP-version.</param>
    /// <param name="expected">The negative status, or 1 for chunked.</param>
    /// <param name="error">The refusal, or None.</param>
    [Theory]
    [InlineData("Transfer-Encoding: chunked\r\n", "HTTP/1.1", 1, ParseError.None)]
    [InlineData("Transfer-Encoding: CHUNKED\r\n", "HTTP/1.1", 1, ParseError.None)]
    [InlineData("Transfer-Encoding: , chunked\r\n", "HTTP/1.1", 1, ParseError.None)]
    [InlineData("Transfer-Encoding: chunked\r\nContent-Length: 5\r\n", "HTTP/1.1", -400, ParseError.TeAndCl)]
    [InlineData("Content-Length: 5\r\nTransfer-Encoding: chunked\r\n", "HTTP/1.1", -400, ParseError.TeAndCl)]
    [InlineData("Transfer-Encoding: chunked\r\n", "HTTP/1.0", -400, ParseError.TeHttp10)]
    [InlineData("Transfer-Encoding: chunked, gzip\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: chunked, chunked\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: gzip\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: gzip, chunked\r\n", "HTTP/1.1", -501, ParseError.TeUnknown)]
    [InlineData("Transfer-Encoding: \"chunked\"\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: chunkedx\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: chunked;x=1\r\n", "HTTP/1.1", -400, ParseError.TeNotChunked)]
    [InlineData("Transfer-Encoding: gzip;q=1, chunked\r\n", "HTTP/1.1", -501, ParseError.TeUnknown)]
    [Requirement("RFC9112-6.1-2", "RFC9112-6.1-4#2", "RFC9112-6.1-11", "RFC9112-6.1-15#1", "RFC9112-6.1-15#2", "RFC9112-6.1-16", "RFC9112-6.3-2.4.3", "RFC9110-5.6.1.2-1#1",
        "RFC9110-5.6.1.2-1#2", "RFC9112-7.1-6", "RFC9112-7.2-3")]
    public void JudgesTransferEncoding(string fields, string version, int expected, ParseError error)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"POST / {version}\r\n{Host}{fields}\r\n");
        if (expected == 1)
        {
            Assert.True(r.Result > 0, $"{fields}: {r.Error}");
            Assert.Equal(Abi.RequestChunked, r.Flags & Abi.RequestChunked);
        }
        else
        {
            Assert.Equal(expected, r.Result);
            Assert.Equal(error, r.Error);
        }
    }

    /// <summary>Persistence: HTTP/1.1 unless close; HTTP/1.0 only with keep-alive; close always wins.</summary>
    /// <param name="version">The HTTP-version.</param>
    /// <param name="connection">The Connection field line, or empty.</param>
    /// <param name="persists">Whether the connection persists after the response.</param>
    [Theory]
    [InlineData("HTTP/1.1", "", true)]
    [InlineData("HTTP/1.1", "Connection: close\r\n", false)]
    [InlineData("HTTP/1.1", "Connection: Keep-Alive, CLOSE\r\n", false)]
    [InlineData("HTTP/1.1", "Connection: upgrade, x-option\r\n", true)]
    [InlineData("HTTP/1.0", "", false)]
    [InlineData("HTTP/1.0", "Connection: keep-alive\r\n", true)]
    [InlineData("HTTP/1.0", "Connection: , keep-alive ,\r\n", true)]
    [InlineData("HTTP/1.0", "Connection: keep-alive\r\nConnection: close\r\n", false)]
    [Requirement("RFC9112-9.3-1", "RFC9112-9.6-6#1", "RFC9110-7.6.1-2", "RFC9110-5.6.1.2-1#1")]
    public void DecidesPersistence(string version, string connection, bool persists)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET / {version}\r\n{Host}{connection}\r\n");
        Assert.True(r.Result > 0);
        Assert.Equal(persists, (r.Flags & Abi.RequestKeepAlive) != 0);
    }

    /// <summary>Expect: 100-continue is flagged; another expectation is a 417; HTTP/1.0 ignores Expect.</summary>
    /// <param name="version">The HTTP-version.</param>
    /// <param name="value">Expect's value.</param>
    /// <param name="expected">1 flagged, 0 accepted without the flag, or the negative status.</param>
    [Theory]
    [InlineData("HTTP/1.1", "100-continue", 1)]
    [InlineData("HTTP/1.1", "100-Continue", 1)]
    [InlineData("HTTP/1.1", "", 0)]
    [InlineData("HTTP/1.1", "200-ok", -417)]
    [InlineData("HTTP/1.1", "100-continue, x", -417)]
    [InlineData("HTTP/1.0", "100-continue", 0)]
    [InlineData("HTTP/1.0", "anything", 0)]
    [Requirement("RFC9110-10.1.1-2", "RFC9110-10.1.1-5", "RFC9110-10.1.1-13.1")]
    public void ReadsExpect(string version, string value, int expected)
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"POST / {version}\r\n{Host}Expect: {value}\r\nContent-Length: 1\r\n\r\n");
        if (expected < 0)
        {
            Assert.Equal(expected, r.Result);
            Assert.Equal(ParseError.Expect, r.Error);
            return;
        }

        Assert.True(r.Result > 0);
        Assert.Equal(expected == 1, (r.Flags & Abi.RequestExpectContinue) != 0);
    }

    /// <summary>TE: trailers is flagged; Upgrade is noted (HttpAsm does not switch protocols).</summary>
    [Fact]
    [Requirement("RFC9110-10.1.4-5", "RFC9110-7.8-3")]
    public void FlagsTeTrailersAndUpgrade()
    {
        Platform.RequireLinuxX64();
        ParsedRequest r = H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}TE: gzip;q=0.5, Trailers\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        Assert.Equal(Abi.RequestTeTrailers | Abi.RequestUpgrade, r.Flags & (Abi.RequestTeTrailers | Abi.RequestUpgrade));
    }

    /// <summary>More field lines than the array holds, or a head over the limit, is a 431.</summary>
    [Fact]
    public void AnswersOversizedHeadsWith431()
    {
        Platform.RequireLinuxX64();
        string many = string.Concat(Enumerable.Range(0, 10).Select(i => $"X-{i}: v\r\n"));
        ParsedRequest tooMany = H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}{many}\r\n", fieldCapacity: 5);
        Assert.Equal(-431, tooMany.Result);
        Assert.Equal(ParseError.TooManyFields, tooMany.Error);

        string big = $"GET / HTTP/1.1\r\n{Host}X-Big: {new string('x', 2000)}\r\n\r\n";
        ParsedRequest tooLarge = H1Parsing.Parse(big, new H1Limits { MaxHead = 1000 });
        Assert.Equal(-431, tooLarge.Result);
        Assert.Equal(ParseError.HeadTooLarge, tooLarge.Error);

        // Incomplete but already past the limit: refused without waiting for the end.
        ParsedRequest endless = H1Parsing.Parse($"GET / HTTP/1.1\r\n{Host}X-Big: {new string('x', 2000)}", new H1Limits { MaxHead = 1000 });
        Assert.Equal(-431, endless.Result);
    }

    /// <summary>Known fields get their ids whatever the case; others get 0; the ids name the right field.</summary>
    [Fact]
    [Requirement("RFC9110-5.1-2")]
    public unsafe void IdentifiesKnownFields()
    {
        Platform.RequireLinuxX64();
        foreach (string name in new[] { "content-length", "Content-Length", "HOST", "transfer-encoding", "te", "upgrade", "access-control-allow-credentials", "x-frame-options" })
        {
            int id = H1Parsing.FieldId(name);
            Assert.True(id > 0, name);
            nuint length;
            byte* canonical = Native.FieldName((uint)id, &length);
            Assert.Equal(name.ToLowerInvariant(), Encoding.ASCII.GetString(canonical, (int)length));
        }

        foreach (string name in new[] { "x-unknown", "content-lengthx", "t", "", "host:", "ho st" })
        {
            Assert.Equal(0, H1Parsing.FieldId(name));
        }

        nuint none;
        Assert.True(Native.FieldName(0, &none) == null);
        Assert.True(Native.FieldName(1000, null) == null);
    }
}
