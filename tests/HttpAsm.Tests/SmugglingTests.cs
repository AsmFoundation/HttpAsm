using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// The published request-smuggling mutations (<see cref="SmugglingCorpus"/>: defparam/smuggler's
/// and PortSwigger's HTTP Request Smuggler's, octet for octet), each judged twice. The parser
/// (httpasm_h1_parse_request) judges it, and so does <see cref="Judge"/>, a strict RFC 9112 head
/// check written for this test alone, independent of the assembly. The two must agree on every
/// case: refused with the same status, or taken with the same framing. Smuggling needs a server
/// and something in front of it to frame one message two ways. A server that frames every
/// mutation as RFC 9112 does, or refuses it, gives the other side nothing to disagree with.
/// </summary>
public sealed class SmugglingTests
{
    /// <summary>
    /// defparam/smuggler's 750 mutations (default.py's and exhaustive.py's) agree with RFC 9112:
    /// each refused with 400, or framed by Content-Length alone when its octets make the mangled
    /// header another field (a Transfer-Encoding hidden inside X's value, say).
    /// </summary>
    [Fact]
    [Requirement("RFC9112-6.1-15#1", "RFC9112-6.1-16", "RFC9112-5.1-2#1", "RFC9112-5.2-4", "RFC9112-2.2-3")]
    public void FramesSmugglersMutationsAsTheRfcDoes() => AssertAgreement(SmugglingCorpus.Smuggler(), 750);

    /// <summary>
    /// PortSwigger's HTTP Request Smuggler's HTTP/1 permutations (James Kettle's), its Transfer-
    /// Encoding ones and its Content-Length ones, agree with RFC 9112: refused (400, or 417 for an
    /// expectation it does not meet), or framed by Content-Length.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-6.1-15#1", "RFC9112-6.3-2.5#2", "RFC9112-6.1-16", "RFC9112-5.1-2#1", "RFC9112-5.2-4", "RFC9110-10.1.1-5")]
    public void FramesKettlesPermutationsAsTheRfcDoes() => AssertAgreement(SmugglingCorpus.Kettle(), 94);

    /// <summary>
    /// smuggler's mutations again without Content-Length, so each mangled Transfer-Encoding
    /// alone decides the framing: taken as chunked only where chunked really is the final
    /// coding of a valid field (tabs, case, trailing whitespace), 501 where valid codings come
    /// before it, 400 for every element that is no token and every chunked that is not final.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-6.3-2.4.3", "RFC9112-6.1-11")]
    public void ReadsSmugglersCodingsAsTheRfcDoes() => AssertAgreement(SmugglingCorpus.WithoutContentLength(SmugglingCorpus.Smuggler()), 750);

    /// <summary>
    /// PortSwigger's Transfer-Encoding permutations again without Content-Length: each mangled
    /// coding alone decides, and agrees with RFC 9112.
    /// </summary>
    [Fact]
    [Requirement("RFC9112-6.3-2.4.3", "RFC9112-6.1-11")]
    public void ReadsKettlesCodingsAsTheRfcDoes() => AssertAgreement(SmugglingCorpus.WithoutContentLength(SmugglingCorpus.Kettle()), 77);

    /// <summary>
    /// PortSwigger's HTTP/2 permutations (DesyncBox.applyDesync's h2 set, commit 3ecb1af), each a
    /// request whose fields an HTTP/2-to-HTTP/1.1 gateway could turn into a second request, or
    /// into Transfer-Encoding framing. They carry CR LF inside a value (its "^~"), a name with a
    /// space or a backtick, an upper-case name, an unknown pseudo-field, pseudo-fields stuffed
    /// with a request-line, Transfer-Encoding itself (connection-specific in HTTP/2), and a
    /// content-length that the DATA contradicts (h2CL). Each is malformed (RFC 9113 8.2, 8.2.1,
    /// 8.2.2, 8.3, 8.1.1). A malformed head gets 400 and RST_STREAM(PROTOCOL_ERROR); a body that
    /// breaks its content-length gets the reset alone. No handler sees any of them.
    /// </summary>
    /// <param name="name">The permutation, as DesyncBox names it ("te" is the plain header).</param>
    [Theory]
    [InlineData("te")]
    [InlineData("http2hide")]
    [InlineData("h2colon")]
    [InlineData("h2auth")]
    [InlineData("h2path")]
    [InlineData("h2scheme")]
    [InlineData("h2method")]
    [InlineData("http2case")]
    [InlineData("h2name")]
    [InlineData("h2space")]
    [InlineData("h2prefix")]
    [InlineData("h2CL")]
    [Requirement("RFC9113-8.2.1-3.1", "RFC9113-8.2.1-3.3", "RFC9113-8.2.1-5#1", "RFC9113-8.2.1-6", "RFC9113-8.2.2-1#2", "RFC9113-8.3-3#4", "RFC9113-8.1.1-3#2")]
    public void RefusesKettlesHttp2Permutations(string name)
    {
        Platform.RequireLinuxX64();
        int handled = 0;
        using var server = new TestServer(x =>
        {
            Interlocked.Increment(ref handled);
            x.Respond(200, "ok");
        });
        using var c = new H2Connection(server.Port);
        const string crlf = "\r\n";
        (string, string)[] request = name switch
        {
            "te" => Fields(("transfer-encoding", "chunked")),
            "http2hide" => Fields(("foo", "b" + crlf + "transfer-encoding: chunked" + crlf + "x: x")),
            "h2colon" => Fields(("transfer-encoding`chunked ", "chunked")),
            "h2auth" => [(":method", "POST"), (":scheme", "http"), (":path", "/"), (":authority", "t:443" + crlf + "transfer-encoding: chunked" + crlf + "x: x")],
            "h2path" => [(":method", "POST"), (":scheme", "http"), (":path", "/ HTTP/1.1" + crlf + "transfer-encoding: chunked" + crlf + "x: x"), (":authority", "t")],
            "h2scheme" => [(":method", "POST"), (":scheme", "https://t/ HTTP/1.1" + crlf + "transfer-encoding: chunked" + crlf + "x: x"), (":path", "/"), (":authority", "t")],
            "h2method" => [(":method", "POST / HTTP/1.1" + crlf + "transfer-encoding: chunked" + crlf + "x: x"), (":scheme", "http"), (":path", "/"), (":authority", "t")],
            "http2case" => Fields(("x-reject", "1"), ("transfer-Encoding", "chunked")),
            "h2name" => Fields(("transfer-encoding`chunked", "x" + crlf + "xz: x")),
            "h2space" => Fields(("transfer-encoding chunked ", "chunked")),
            "h2prefix" => Fields((":transfer-encoding", "chunked")),
            _ => Fields(("content-length", "0")),                  // h2CL: then a body after all
        };

        c.SendFrame(H2Connection.Headers, H2Connection.EndHeaders, 1, c.Block(request));
        c.SendFrame(H2Connection.Data, H2Connection.EndStream, 1, "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: t\r\n\r\n"u8);
        uint code = c.ExpectReset(1);

        // A malformed head is answered 400 before its reset; h2CL's head was well-formed (its
        // content-length was believed), so only the reset tells the client its body broke it.
        int? expected = name == "h2CL" ? null : 400;
        int? status = c.Decoded.TryGetValue(1, out var head)
            ? int.Parse(head.First(f => f.Name == ":status").Value, System.Globalization.CultureInfo.InvariantCulture)
            : null;
        Assert.Equal(H2Connection.ProtocolError, code);
        Assert.Equal(expected, status);
        Assert.Equal(0, handled);
    }

    /// <summary>A POST request's pseudo-fields, then the given fields.</summary>
    /// <param name="fields">The fields after the pseudo-fields.</param>
    /// <returns>The field list.</returns>
    private static (string, string)[] Fields(params (string, string)[] fields) =>
        [(":method", "POST"), (":scheme", "http"), (":path", "/"), (":authority", "t"), .. fields];

    /// <summary>A body framed by chunked, in a <see cref="Verdict"/>'s length: no Content-Length is this.</summary>
    internal const ulong Chunked = ulong.MaxValue;

    /// <summary>A verdict on a request head: refused with a status, or taken with its framing.</summary>
    /// <param name="Status">0 when taken; else the status it is refused with.</param>
    /// <param name="Length">When taken: the body's length (Content-Length, or 0 without one), or
    /// <see cref="Chunked"/>.</param>
    /// <param name="Why">The rule, for a failure's message.</param>
    internal readonly record struct Verdict(int Status, ulong Length, string Why)
    {
        /// <summary>The verdict as a failure message shows it.</summary>
        /// <returns>"taken, chunked", "taken, length N" or "refused S (rule)".</returns>
        public override string ToString() => Status != 0 ? $"refused {Status} ({Why})" : Length == Chunked ? "taken, chunked" : $"taken, length {Length}";
    }

    /// <summary>
    /// What RFC 9112 makes of a request head, for a server that takes every strict choice the RFCs
    /// leave open, as HttpAsm does (each choice named where it is made). The corpus's requests are
    /// whole and carry Host, so this covers what their mutations can change: line ends,
    /// obs-fold, field names and values, Transfer-Encoding with Content-Length or in HTTP/1.0,
    /// Content-Length's form, and Expect.
    /// </summary>
    /// <param name="request">The request's octets.</param>
    /// <returns>The verdict.</returns>
    internal static Verdict Judge(byte[] request)
    {
        static Verdict Refused(int status, string why) => new(status, 0, why);
        int end = request.AsSpan().IndexOf("\r\n\r\n"u8);
        if (end < 0)
        {
            return Refused(400, "no head end");
        }

        // Lines end in CRLF (RFC 9112 2.2). A CR that does not start one is invalid; a bare LF
        // the RFC lets a recipient accept, and the strict choice refuses (RFC9112-2.2-3).
        ReadOnlySpan<byte> head = request.AsSpan(0, end);
        for (int i = 0; i < head.Length; i++)
        {
            if (head[i] == '\r' && (i + 1 == head.Length || head[i + 1] != '\n'))
            {
                return Refused(400, "a CR that ends no line");
            }

            if (head[i] == '\n' && (i == 0 || head[i - 1] != '\r'))
            {
                return Refused(400, "a bare LF");
            }
        }

        string[] lines = Encoding.Latin1.GetString(head).Split("\r\n");
        string[] requestLine = lines[0].Split(' ');
        if (requestLine.Length != 3 || requestLine[2] is not ("HTTP/1.1" or "HTTP/1.0"))
        {
            return Refused(400, "request-line");
        }

        var fields = new List<(string Name, string Value)>();
        foreach (string line in lines.Skip(1))
        {
            // A line starting with whitespace continues the last (obs-fold): RFC 9112 5.2 lets a
            // server replace it with spaces; the strict choice refuses it.
            if (line.Length > 0 && line[0] is ' ' or '\t')
            {
                return Refused(400, "obs-fold");
            }

            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0 || !line[..colon].All(IsTchar))
            {
                // No whitespace (or any other non-token octet) before the colon: RFC 9112 5.1
                // requires the 400.
                return Refused(400, "field-name");
            }

            string value = line[(colon + 1)..].Trim(' ', '\t');
            if (value.Any(c => c < 0x20 && c != '\t' || c == 0x7F))
            {
                return Refused(400, "a control in a field value");    // RFC 9110 5.5
            }

            fields.Add((line[..colon].ToLowerInvariant(), value));
        }

        bool http10 = requestLine[2] == "HTTP/1.0";
        if (!http10 && fields.Count(f => f.Name == "host") != 1)
        {
            return Refused(400, "Host");                                // RFC 9112 3.2
        }

        bool te = fields.Any(f => f.Name == "transfer-encoding");
        var lengths = fields.Where(f => f.Name == "content-length")
            .SelectMany(f => f.Value.Split(',').Select(v => v.Trim(' ', '\t'))).ToList();
        if (te && http10)
        {
            return Refused(400, "Transfer-Encoding in HTTP/1.0");     // RFC 9112 6.1: faulty framing
        }

        if (te && lengths.Count > 0)
        {
            // RFC 9112 6.3 lets a server reject Transfer-Encoding with Content-Length, the setup of
            // every smuggling attempt; the strict choice does, whatever the codings say.
            return Refused(400, "Transfer-Encoding with Content-Length");
        }

        if (te)
        {
            // Transfer-Encoding = #transfer-coding (RFC 9112 6.1), the field's lines one list;
            // empty elements are ignored (RFC 9110 5.6.1). An element that is no token is
            // malformed: 400. chunked must be the final coding, and in a request is the only
            // way to know the length: anything else is 400 (RFC 9112 6.3, MUST). Codings
            // before it, all tokens, are codings this server does not implement: 501 (RFC 9112
            // 6.1, SHOULD).
            var codings = fields.Where(f => f.Name == "transfer-encoding")
                .SelectMany(f => f.Value.Split(',').Select(v => v.Trim(' ', '\t'))).Where(v => v.Length > 0).ToList();
            if (codings.Count == 0 || codings.Any(c => !c.All(IsTchar)))
            {
                return Refused(400, "a coding that is no token");
            }

            int chunked = codings.FindIndex(c => c.Equals("chunked", StringComparison.OrdinalIgnoreCase));
            if (chunked != codings.Count - 1)
            {
                return Refused(400, "chunked not the final coding, once");
            }

            return codings.Count > 1 ? Refused(501, "a coding not implemented") : new Verdict(0, Chunked, "chunked");
        }

        ulong length = 0;
        if (lengths.Count > 0)
        {
            // 1*DIGIT; a list of identical ones the RFC lets a recipient take as one (RFC 9112 6.3).
            if (lengths.Any(l => l.Length == 0 || !l.All(char.IsAsciiDigit)) || lengths.Distinct().Count() > 1)
            {
                return Refused(400, "Content-Length");
            }

            length = ulong.Parse(lengths[0], System.Globalization.CultureInfo.InvariantCulture);
        }

        foreach ((string name, string value) in fields.Where(f => f.Name == "expect"))
        {
            if (!value.Equals("100-continue", StringComparison.OrdinalIgnoreCase))
            {
                return Refused(417, "an expectation not met");     // RFC 9110 10.1.1 MAY
            }
        }

        return new Verdict(0, length, "framed by Content-Length");
    }

    /// <summary>HttpAsm's verdict on a request head: the parser's result, as a <see cref="Verdict"/>.</summary>
    /// <param name="request">The request's octets.</param>
    /// <returns>The verdict: refused with the parser's status; taken framed by chunked
    /// (<see cref="Chunked"/>) or by Content-Length (its length, 0 without one); an incomplete head
    /// (never right: every case is whole) as status -2, so it matches nothing.</returns>
    internal static Verdict Parse(byte[] request)
    {
        nuint scanFrom = 0;
        ParsedRequest r = H1Parsing.Parse(request, request.Length, ref scanFrom);
        if (r.Result < 0)
        {
            return new Verdict((int)-r.Result, 0, r.Error.ToString());
        }

        if (r.Result == 0)
        {
            return new Verdict(-2, 0, "incomplete");
        }

        if ((r.Flags & Abi.RequestChunked) != 0)
        {
            return new Verdict(0, Chunked, "chunked");
        }

        return new Verdict(0, (r.Flags & Abi.RequestContentLength) != 0 ? r.ContentLength : 0, "framed by Content-Length");
    }

    /// <summary>Asserts that the parser and RFC 9112 agree on every case of a corpus.</summary>
    /// <param name="corpus">The cases.</param>
    /// <param name="expected">How many there are: a corpus that loses cases (a changed loop, a
    /// name dropped from the union) fails here instead of passing with less.</param>
    private static void AssertAgreement(IReadOnlyList<SmugglingCase> corpus, int expected)
    {
        Platform.RequireLinuxX64();
        Assert.Equal(expected, corpus.Count);
        var disagreements = new List<string>();
        int taken = 0;
        foreach (SmugglingCase c in corpus)
        {
            Verdict rfc = Judge(c.Request);
            Verdict httpasm = Parse(c.Request);
            if (rfc.Status != httpasm.Status || rfc.Length != httpasm.Length)
            {
                disagreements.Add($"{c.Name}: RFC 9112 {rfc}, HttpAsm {httpasm}");
            }

            taken += rfc.Status == 0 ? 1 : 0;
        }

        Assert.True(disagreements.Count == 0, $"{disagreements.Count} of {corpus.Count} disagree:\n" + string.Join("\n", disagreements));
        Assert.InRange(taken, 1, corpus.Count - 1);     // both kinds of verdict are exercised
    }

    /// <summary>Whether a character is a tchar (RFC 9110 5.6.2).</summary>
    /// <param name="c">The character (an octet, as Latin-1).</param>
    /// <returns>True for a tchar.</returns>
    private static bool IsTchar(char c) => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal);
}
