using System.Text;

namespace HttpAsm.Tests;

/// <summary>One published request-smuggling mutation: its name in its source, and the request's octets.</summary>
/// <param name="Name">The mutation's name, as its source names it.</param>
/// <param name="Request">The whole request: head, then body.</param>
internal sealed record SmugglingCase(string Name, byte[] Request)
{
    /// <summary>The name, for theory output.</summary>
    /// <returns>The name.</returns>
    public override string ToString() => Name;
}

/// <summary>
/// The published HTTP/1.1 request-smuggling mutations, reproduced octet for octet from the tools
/// that publish them (docs/DESIGN.md phase H step 3, "the published attack corpora"):
/// <list type="bullet">
/// <item>defparam/smuggler (Evan Custodio, MIT), commit 2be871e6151ce85167a277fab21c74c851d8b20b:
/// configs/default.py (SHA-256 df3aaf82c68da7e0e0718917bc1395c83298a56e2894d2be6dd4b6799fc4ae66)
/// and configs/exhaustive.py (fd79a932efc530cc5735b0ab7e9f7b0fab355773aedd9a294633477d524737df),
/// sent the way smuggler.py (e05870f98e044527418cb8bbf9ed3409a4a0c6ea9b6bd6c1af49acd33be330fc)
/// sends them: str(payload).encode(), UTF-8, so a character from 0x80 up is two octets.</item>
/// <item>PortSwigger/http-request-smuggler (James Kettle), commit 3ecb1afa6a1d21ef1ec4e6eb1337818b53a2b4c0:
/// src/burp/DesyncBox.java (15bda68a2dea50c037d5ac0f098e45e9e592f73336e5415c2fc45a2c41ed9f72),
/// its HTTP/1 and Content-Length permutations, each applied as applyDesync applies it. Strings are
/// UTF-8 (Java's default charset); spaceFF, unispace, accentTE and accentCH write their single
/// raw octet, as the source does.</item>
/// </list>
/// Every request carries Content-Length, as both tools' do: the question each asks a server is
/// whether some mangled Transfer-Encoding still counts, and against which length.
/// </summary>
internal static class SmugglingCorpus
{
    /// <summary>smuggler's TE.CL probe body: EndChunk + "X", 6 octets.</summary>
    private const string SmugglerBody = "0\r\n\r\nX";

    /// <summary>
    /// The Content-Length both templates send: smuggler's TE.CL probe's "good value", 5. A reader
    /// of Content-Length takes the chunked body's end and leaves the "X" over; a reader of chunked
    /// takes the same 5 octets. Only a server that takes something else reads the "X" as its own.
    /// </summary>
    private const int ProbeLength = 5;

    /// <summary>The PortSwigger requests' body, the same probe.</summary>
    private const string KettleBody = SmugglerBody;

    /// <summary>
    /// defparam/smuggler's mutations: render_template(gadget) with POST, "/", a fixed "random", host
    /// "t", and Content-Length 5 (its TE.CL probe). default.py's set, then exhaustive.py's (the
    /// union by name; where both define a name, they define the same octets).
    /// </summary>
    /// <returns>The cases, in the sources' order.</returns>
    public static IReadOnlyList<SmugglingCase> Smuggler()
    {
        var cases = new Dictionary<string, string>();
        void Add(string name, string gadget) => cases.TryAdd(name, gadget);

        // configs/default.py
        Add("nameprefix1", " Transfer-Encoding: chunked");
        Add("tabprefix1", "Transfer-Encoding:\tchunked");
        Add("tabprefix2", "Transfer-Encoding\t:\tchunked");
        Add("space1", "Transfer-Encoding : chunked");
        foreach (int i in new[] { 0x1, 0x4, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0x1F, 0x20, 0x7f, 0xA0, 0xFF })
        {
            char c = (char)i;
            Add($"midspace-{i:x2}", $"Transfer-Encoding:{c}chunked");
            Add($"postspace-{i:x2}", $"Transfer-Encoding{c}: chunked");
            Add($"prespace-{i:x2}", $"{c}Transfer-Encoding: chunked");
            Add($"endspace-{i:x2}", $"Transfer-Encoding: chunked{c}");
            Add($"xprespace-{i:x2}", $"X: X{c}Transfer-Encoding: chunked");
            Add($"endspacex-{i:x2}", $"Transfer-Encoding: chunked{c}X: X");
            Add($"rxprespace-{i:x2}", $"X: X\r{c}Transfer-Encoding: chunked");
            Add($"xnprespace-{i:x2}", $"X: X{c}\nTransfer-Encoding: chunked");
            Add($"endspacerx-{i:x2}", $"Transfer-Encoding: chunked\r{c}X: X");
            Add($"endspacexn-{i:x2}", $"Transfer-Encoding: chunked{c}\nX: X");
        }

        // configs/exhaustive.py
        Add("spacejoin1", "Transfer Encoding: chunked");
        Add("underjoin1", "Transfer_Encoding: chunked");
        Add("smashed", "Transfer Encoding:chunked");
        Add("valueprefix1", "Transfer-Encoding:  chunked");
        Add("vertprefix1", "Transfer-Encoding:\u000Bchunked");
        Add("commaCow", "Transfer-Encoding: chunked, cow");
        Add("cowComma", "Transfer-Encoding: cow, chunked");
        Add("contentEnc", "Content-Encoding: chunked");
        Add("linewrapped1", "Transfer-Encoding:\n chunked");
        Add("quoted", "Transfer-Encoding: \"chunked\"");
        Add("aposed", "Transfer-Encoding: 'chunked'");
        Add("lazygrep", "Transfer-Encoding: chunk");
        Add("sarcasm", "TrAnSFer-EnCODinG: cHuNkeD");
        Add("yelling", "TRANSFER-ENCODING: CHUNKED");
        Add("0dsuffix", "Transfer-Encoding: chunked\r");
        Add("tabsuffix", "Transfer-Encoding: chunked\t");
        Add("revdualchunk", "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked");
        Add("0dspam", "Transfer\r-Encoding: chunked");
        Add("nested", "Transfer-Encoding: cow chunked bar");
        Add("spaceFF", "Transfer-Encoding:\u00FFchunked");      // \u: C#'s \x is greedy ("\xFFc" would be U+0FFC)
        Add("accentCH", "Transfer-Encoding: ch\u0096nked");
        Add("accentTE", "Transf\u0082r-Encoding: chunked");
        Add("x-rout", "X:X\rTransfer-Encoding: chunked");
        Add("x-nout", "X:X\nTransfer-Encoding: chunked");
        for (int i = 0x1; i < 0x20; i++)
        {
            char c = (char)i;
            Add($"midspace-{i:x2}", $"Transfer-Encoding:{c}chunked");
            Add($"postspace-{i:x2}", $"Transfer-Encoding{c}: chunked");
            Add($"prespace-{i:x2}", $"{c}Transfer-Encoding: chunked");
            Add($"endspace-{i:x2}", $"Transfer-Encoding: chunked{c}");
        }

        for (int i = 0x7F; i < 0x100; i++)
        {
            char c = (char)i;
            Add($"midspace-{i:x2}", $"Transfer-Encoding:{c}chunked");
            Add($"postspace-{i:x2}", $"Transfer-Encoding{c}: chunked");
            Add($"prespace-{i:x2}", $"{c}Transfer-Encoding: chunked");
            Add($"endspace-{i:x2}", $"Transfer-Encoding: chunked{c}");
        }

        return cases.Select(c => new SmugglingCase("smuggler/" + c.Key, Encoding.UTF8.GetBytes(
            "POST /?cb=1 HTTP/1.1\r\n" + c.Value + "\r\n" + "Host: t\r\n"
            + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36\r\n"
            + "Content-type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
            + $"Content-Length: {ProbeLength}\r\n" + "\r\n" + SmugglerBody))).ToList();
    }

    /// <summary>
    /// PortSwigger's HTTP Request Smuggler: every HTTP/1 Transfer-Encoding permutation of
    /// DesyncBox.applyDesync (its shared and h1 sets, the special-character families with
    /// getSpecialChars' 0, 9, 11, 12, 13 and 127), applied to a request with Content-Length and
    /// "Transfer-Encoding: chunked"; then its Content-Length permutations, applied to a request
    /// with Content-Length alone. The HTTP/2 permutations are HTTP/2's (Http2FrameTests).
    /// </summary>
    /// <returns>The cases.</returns>
    public static IReadOnlyList<SmugglingCase> Kettle()
    {
        const string te = "Transfer-Encoding: ";
        const string value = "chunked";
        string request = "POST / HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            + $"Content-Length: {ProbeLength}\r\n" + te + value + "\r\n\r\n" + KettleBody;
        var cases = new List<SmugglingCase>();
        void Text(string name, string text) => cases.Add(new SmugglingCase("kettle/" + name, Encoding.UTF8.GetBytes(text)));
        void Header(string name, string permuted) => Text(name, request.Replace(te, permuted, StringComparison.Ordinal));

        Text("vanilla", request);
        Header("underjoin1", te.Replace("-", "_", StringComparison.Ordinal));
        Header("spacejoin1", te.Replace("-", " ", StringComparison.Ordinal));
        Header("space1", te.Replace(":", " :", StringComparison.Ordinal));
        Header("nameprefix1", "Foo: bar\r\n " + te);
        Header("nameprefix2", "Foo: bar\r\n\t" + te);
        Header("valueprefix1", te + " ");
        Header("nospace1", te.Replace(" ", string.Empty, StringComparison.Ordinal));
        Header("linewrapped1", te.Replace(" ", "\n ", StringComparison.Ordinal));
        Header("doublewrapped", te.Replace(" ", "\r\n \r\n ", StringComparison.Ordinal));
        Header("gareth1", te.Replace(":", "\n :", StringComparison.Ordinal));
        Header("badsetupCR", "Foo: bar\r" + te);
        Header("badsetupLF", "Foo: bar\n" + te);
        Header("vertwrap", te + "\n\u000B");
        Header("tabwrap", te + "\r\n\t");
        Header("multiCase", "t" + te.ToUpperInvariant()[1..]);
        Header("UPPERCASE", te.ToUpperInvariant());
        Header("0dwrap", "Foo: bar\r\n\r" + te);
        Header("0dspam", te[..3] + "\r" + te[3..]);
        Header("connection", "Connection: Transfer-Encoding\r\n" + te);
        Header("spjunk", te.Replace(":", " x:", StringComparison.Ordinal));
        Header("backslash", te.Replace("-", "\\", StringComparison.Ordinal));
        Header("nel", te.Replace(":", "\u0085:", StringComparison.Ordinal));
        Header("nbsp", te.Replace(":", "\u00A0:", StringComparison.Ordinal));
        Header("shy2", te.Replace(":", "\u00AD:", StringComparison.Ordinal));
        Header("shy", te.Replace("-", "\u00AD", StringComparison.Ordinal));
        foreach (int i in new[] { 0, 9, 11, 12, 13, 127 })
        {
            Header($"spacefix1:{i}", te.Replace(" ", string.Empty, StringComparison.Ordinal) + (char)i);
            Header($"prefix1:{i}", te + (char)i);
            Header($"namesuffix1:{i}", te.Replace(":", (char)i + ":", StringComparison.Ordinal));
            Text($"suffix1:{i}", request.Replace(te + value, te + value + (char)i, StringComparison.Ordinal));
        }

        // badwrap: the header becomes X-Blah-Ignore, and a folded copy follows the request-line.
        string badwrap = request.Replace(te, "X-Blah-Ignore: ", StringComparison.Ordinal);
        int firstLineEnd = badwrap.IndexOf("\r\n", StringComparison.Ordinal);
        Text("badwrap", badwrap[..firstLineEnd] + "\r\n " + te + value + "\r\n" + badwrap[(firstLineEnd + 2)..]);
        cases.Add(new SmugglingCase("kettle/spaceFF", Raw(request, te, Encoding.ASCII.GetBytes("Transfer-Encoding:").Append((byte)0xFF).ToArray())));
        cases.Add(new SmugglingCase("kettle/unispace", Raw(request, te, Encoding.ASCII.GetBytes("Transfer-Encoding:").Append((byte)0xA0).ToArray())));
        Text("http1.0", request.Replace("HTTP/1.1", "HTTP/1.0", StringComparison.Ordinal));
        Text("0dsuffix", request.Replace(te + value, te + value + "\r", StringComparison.Ordinal));
        Text("tabsuffix", request.Replace(te + value, te + value + "\t", StringComparison.Ordinal));
        Text("removed", request.Replace(te + value, "Nothing-interesting: 1", StringComparison.Ordinal));
        Text("get", "GET" + request[4..]);
        Text("options", "OPTIONS" + request[4..]);
        Text("head", "HEAD" + request[4..]);
        Text("range", First(request, "\r\n\r\n", "\r\nRange: bytes=0-0\r\n\r\n"));
        Text("commaCow", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunked, identity", StringComparison.Ordinal));
        Text("cowComma", request.Replace("Transfer-Encoding: ", "Transfer-Encoding: identity, ", StringComparison.Ordinal));
        Text("contentEnc", request.Replace("Transfer-Encoding: ", "Content-Encoding: ", StringComparison.Ordinal));
        Text("quoted", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: \"chunked\"", StringComparison.Ordinal));
        Text("aposed", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: 'chunked'", StringComparison.Ordinal));
        // dualchunk: addOrReplaceHeader("Transfer-encoding", "identity") finds the header by name and replaces its value.
        Text("dualchunk", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: identity", StringComparison.Ordinal));
        Text("lazygrep", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: chunk", StringComparison.Ordinal));
        Text("revdualchunk", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked", StringComparison.Ordinal));
        Text("bodysplit", request.Replace("Transfer-Encoding: chunked", "X: y\r\nFoo: barn\n\nTransfer-Encoding: chunked", StringComparison.Ordinal));
        Text("nested", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: identity, chunked, identity", StringComparison.Ordinal));
        Text("encode", request.Replace("Transfer-Encoding: chunked", "Transfer-%45ncoding: chunked", StringComparison.Ordinal));
        Text("h1case", request.Replace(te + value, te.ToUpperInvariant() + value, StringComparison.Ordinal));
        Text("qencode", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=", StringComparison.Ordinal));
        Text("qencodeutf", request.Replace("Transfer-Encoding: chunked", "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?=", StringComparison.Ordinal));
        cases.Add(new SmugglingCase("kettle/accentTE", Raw(request, te, [.. "Transf"u8, 0x82, .. "r-Encoding: "u8])));
        cases.Add(new SmugglingCase("kettle/accentCH", Raw(request, "Transfer-Encoding: chu", [.. "Transfer-Encoding: ch"u8, 0x96])));

        // The Content-Length permutations: applied to a request framed by Content-Length alone.
        const string cl = "Content-Length: ";
        string length = "5";
        string plain = "POST / HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\n" + cl + length + "\r\n\r\nhello";
        void Length(string name, string text) => cases.Add(new SmugglingCase("kettle/" + name, Encoding.UTF8.GetBytes(text)));
        Length("CL-dualCL", plain.Replace(cl + length, cl + length + "\r\n" + cl + length, StringComparison.Ordinal));
        Length("CL-plus", plain.Replace(cl, cl + "+", StringComparison.Ordinal));
        Length("CL-minus", plain.Replace(cl, cl + "-", StringComparison.Ordinal));
        Length("CL-pad", plain.Replace(cl, cl + "0", StringComparison.Ordinal));
        Length("CL-bigpad", plain.Replace(cl, cl + "00000000000", StringComparison.Ordinal));
        Length("CL-spacepad", plain.Replace(cl, cl + "0 ", StringComparison.Ordinal));
        Length("CL-e", plain.Replace(cl + length, cl + length + "e0", StringComparison.Ordinal));
        Length("CL-dec", plain.Replace(cl + length, cl + length + ".0", StringComparison.Ordinal));
        Length("CL-commaprefix", plain.Replace(cl, cl + "0, ", StringComparison.Ordinal));
        Length("CL-commasuffix", plain.Replace(cl + length, cl + length + ", 0", StringComparison.Ordinal));
        Length("CL-expect", First(plain, "\r\n\r\n", "\r\nExpect: 100-continue\r\n\r\n"));
        Length("CL-expect-obfs", First(plain, "\r\n\r\n", "\r\nExpect: x 100-continue\r\n\r\n"));
        Length("CL-error", plain.Replace(cl + length, "X-Invalid Y: \r\n" + cl + length, StringComparison.Ordinal));
        Length("CL-byteranges", plain.Replace("application/x-www-form-urlencoded", "multipart/byteranges; boundary=canary1", StringComparison.Ordinal));
        Length("CL-multiform", plain.Replace("application/x-www-form-urlencoded", "multipart/form-data; boundary=canary1", StringComparison.Ordinal));
        Length("CL-deleteMaxforward", "DELETE" + First(plain[4..], "\r\n\r\n", "\r\nMax-Forwards: 0\r\n\r\n"));
        Length("CL-gzip10", First(plain.Replace("HTTP/1.1", "HTTP/1.0", StringComparison.Ordinal), "\r\n\r\n", "\r\nTransfer-Encoding: gzip\r\n\r\n"));
        return cases;
    }

    /// <summary>
    /// Each Transfer-Encoding mutation again, without its Content-Length line. Both tools send
    /// Content-Length with every mutation, so a server that refuses the two together (HttpAsm
    /// does) never reads the mangled coding at all: the published sets alone would not notice a
    /// coding read wrongly (tests/fuzz/h1_request_diff found "chunked\xD8" read as chunked).
    /// Without Content-Length, each mutation's Transfer-Encoding alone decides the framing. The
    /// Content-Length permutations (kettle/CL-*) are about that header, and are left out.
    /// </summary>
    /// <param name="cases">The cases.</param>
    /// <returns>The variants, each named "&lt;name&gt; without Content-Length".</returns>
    /// <exception cref="InvalidDataException">A case has no "Content-Length: 5" line: the corpus's
    /// templates changed, and the variants would silently test something else.</exception>
    public static IReadOnlyList<SmugglingCase> WithoutContentLength(IEnumerable<SmugglingCase> cases)
    {
        var variants = new List<SmugglingCase>();
        foreach (SmugglingCase c in cases.Where(c => !c.Name.StartsWith("kettle/CL-", StringComparison.Ordinal)))
        {
            int at = c.Request.AsSpan().IndexOf("\r\nContent-Length: 5\r\n"u8);
            if (at < 0)
            {
                throw new InvalidDataException($"{c.Name}: no Content-Length line to take out.");
            }

            // The line goes from its CR LF (the one ending the line before) to its own end.
            variants.Add(new SmugglingCase(c.Name + " without Content-Length", [.. c.Request.AsSpan(0, at), .. c.Request.AsSpan(at + 19)]));
        }

        return variants;
    }

    /// <summary>A text with only its first occurrence of <paramref name="find"/> replaced: a head's
    /// end (CR LF CR LF) appears again in a chunked body, which must stay as it is.</summary>
    /// <param name="text">The text.</param>
    /// <param name="find">What to replace.</param>
    /// <param name="replacement">The replacement.</param>
    /// <returns>The text.</returns>
    private static string First(string text, string find, string replacement)
    {
        int at = text.IndexOf(find, StringComparison.Ordinal);
        return text[..at] + replacement + text[(at + find.Length)..];
    }

    /// <summary>A request with its first occurrence of <paramref name="find"/> replaced by raw octets.</summary>
    /// <param name="request">The request (ASCII).</param>
    /// <param name="find">What to replace.</param>
    /// <param name="octets">The replacement, as octets.</param>
    /// <returns>The request's octets.</returns>
    private static byte[] Raw(string request, string find, byte[] octets)
    {
        int at = request.IndexOf(find, StringComparison.Ordinal);
        return [.. Encoding.ASCII.GetBytes(request[..at]), .. octets, .. Encoding.ASCII.GetBytes(request[(at + find.Length)..])];
    }
}
