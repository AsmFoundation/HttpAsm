using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// One authority rule for every entry point (semantics/authority.inc and semantics/ipv6.asm).
/// Each authority of <see cref="Authorities"/> goes to all eight entry points: HTTP/1.1's Host,
/// absolute-form target and CONNECT target, as parsed and as written, and HTTP/2's :authority
/// (a GET's and a CONNECT's) and Host. Each must give the verdict of RFC 3986's uri-host
/// [ ":" port ], plus only that entry point's own documented rule:
/// <list type="bullet">
/// <item>an http(s) URI's host may not be empty (RFC 9110 4.2.1);</item>
/// <item>CONNECT needs a host and a port of 1 to 65535 (RFC 9112 3.2.3);</item>
/// <item>HTTP/2's :authority may not be empty.</item>
/// </list>
/// The rule is one macro assembled into each version's code. An authority one entry point
/// accepts and another refuses can be played against a hop of the other version, which is how
/// tests/fuzz/h2_request found the first difference (2026-11-26). Each expansion has its own
/// code, so each has to see every branch of the grammar, which the coverage report showed it
/// did not (146 markers of the writer's expansions never ran).
/// </summary>
public sealed unsafe class AuthorityTests
{
    /// <summary>
    /// The authorities, each with its RFC 3986 verdict as uri-host [ ":" port ] (a Host), and
    /// as a CONNECT target (that, with a host and a port of 1 to 65535).
    /// </summary>
    /// <remarks>
    /// The IPv6address vectors are RFC 4291 2.2's text forms and RFC 3986 3.2.2's grammar at
    /// each of its edges: eight pieces, or seven at most with one "::"; h16 of 1 to 4 HEXDIG; an
    /// IPv4 tail last, counting two pieces, its dec-octets 255 at most without a leading zero;
    /// no zone identifier. Then IPvFuture's, reg-name's (with pct-encoding and sub-delims),
    /// ports, and octets no authority may hold.
    /// </remarks>
    public static TheoryData<string, bool, bool> Authorities => new()
    {
        // IPv6address, valid (RFC 4291 2.2's forms, then the grammar's edges)
        { "[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]", true, false },
        { "[2001:DB8:0:0:8:800:200C:417A]:443", true, true },
        { "[2001:DB8::8:800:200C:417A]", true, false },
        { "[FF01::101]:1", true, true },
        { "[::1]:8080", true, true },
        { "[::]:65535", true, true },
        { "[0:0:0:0:0:0:13.1.68.3]", true, false },
        { "[::13.1.68.3]:80", true, true },
        { "[::FFFF:129.144.52.38]", true, false },
        { "[1:2:3:4:5:6:7::]", true, false },
        { "[::2:3:4:5:6:7:8]", true, false },
        { "[1::8]", true, false },
        { "[1:2:3:4:5:6:1.2.3.4]", true, false },
        { "[::255.255.255.255]", true, false },
        { "[::0.0.0.0]", true, false },
        { "[fe80::1]:", true, false },
        // IPv6address, invalid
        { "[2001:DB8:0:0:8:800:200C:417A:221]", false, false },
        { "[FF01::101::2]", false, false },
        { "[1:2:3:4:5:6:7]", false, false },
        { "[1::2:3:4:5:6:7:8]", false, false },
        { "[12345::]", false, false },
        { "[::g]", false, false },
        { "[:1::]", false, false },
        { "[1:::2]", false, false },
        { "[1::2:]", false, false },
        { "[::1.2.3.256]", false, false },
        { "[::01.2.3.4]", false, false },
        { "[::1.2.3]", false, false },
        { "[::1.2.3.4.5]", false, false },
        { "[1.2.3.4]", false, false },
        { "[::1.2.3.4:5]", false, false },
        { "[1:2:3:4:5:6:7:1.2.3.4]", false, false },
        { "[::1", false, false },
        { "[::1]x", false, false },
        { "[::1%25eth0]", false, false },
        { "[::1.2.3.04]", false, false },
        { "[::1.2.3.1000]", false, false },
        { "[]", false, false },
        { "[", false, false },
        { "[::1]:8x", false, false },
        // IPv6address, the range ending in each state (Host's value is the whole range; an
        // absolute-form's authority ends at the "/" after it)
        { "[:", false, false },
        { "[::", false, false },
        { "[1:", false, false },
        { "[1::", false, false },
        { "[1:2", false, false },
        { "[::1.", false, false },
        { "[::1.2.", false, false },
        { "[::1.2.3.4", false, false },
        { "[::1.2.3.0", false, false },
        { "[::1.2.3.0]", true, false },
        { "[::0.0.0.0]:1", true, true },
        // IPvFuture
        { "[v1.x]", true, false },
        { "[vF.a:b]:9", true, true },
        { "[v1.!$&'()*+,;=-._~]", true, false },
        { "[v.x]", false, false },
        { "[vZ.x]", false, false },
        { "[v1.]", false, false },
        { "[v1x]", false, false },
        { "[v1.x", false, false },
        { "[v1.%41]", false, false },
        { "[v1.x/y]", false, false },
        { "[v1.x]y", false, false },
        { "[v12.x]", true, false },
        { "[vAb.x:y]:80", true, true },
        { "[v", false, false },
        { "[v1", false, false },
        { "[v1.", false, false },
        { "[v1.\"]", false, false },
        { "[v1. ]", false, false },
        { "[v1.?]", false, false },
        { "[v1.@]", false, false },
        { "[v1.[]", false, false },
        // reg-name and IPv4address
        { "example.com", true, false },
        { "example.com:443", true, true },
        { "ex%41mple.com", true, false },
        { "a-b.c_d~e!$&'()*+,;=", true, false },
        { "127.0.0.1:1", true, true },
        { "h:", true, false },
        { "h:0", true, false },
        { "h:65535", true, true },
        { "h:65536", true, false },
        { "h:0443", true, true },
        { "h:000000000443", true, true },
        { "h:100443", true, false },                                // a sixth digit, not a leading zero
        { "1234", true, false },                                    // all digits: a host, and no port
        { ":80", true, false },
        { "", true, false },
        { "exa mple", false, false },
        { "a@b", false, false },
        { "a/b", false, false },
        { "a?b", false, false },
        { "a[b", false, false },
        { "a]b", false, false },
        { "%4", false, false },
        { "%zz", false, false },
        { "h:8x", false, false },
        { "h:-1", false, false },
        { "a\tb", false, false },
        { "a\"b", false, false },
        { "a{b", false, false },
        { "hé", false, false },
    };

    /// <summary>
    /// Every entry point gives the authority RFC 3986's verdict, plus only its own rule: see
    /// this class's summary. Each failure names the entry point, so a difference between two
    /// expansions of the one macro shows which.
    /// </summary>
    /// <param name="authority">The authority.</param>
    /// <param name="host">Its verdict as uri-host [ ":" port ].</param>
    /// <param name="connect">Its verdict as a CONNECT target.</param>
    [Theory]
    [MemberData(nameof(Authorities))]
    [Requirement("RFC9112-3.2-6", "RFC9110-4.2.1-2", "RFC9110-4.2.1-4#1", "RFC9110-4.2.1-4#2", "RFC9110-4.2.4-4", "RFC9110-9.3.6-4")]
    public void HoldsEveryEntryPointToOneAuthorityRule(string authority, bool host, bool connect)
    {
        Platform.RequireLinuxX64();
        // An http(s) URI needs a host (RFC 9110 4.2.1): its host part, before any port.
        bool namesHost = authority.Length > 0 && !authority.StartsWith(':');
        var verdicts = new List<string>();
        void Expect(string entry, bool expected, bool actual)
        {
            if (expected != actual)
            {
                verdicts.Add($"{entry}: expected {(expected ? "accepted" : "refused")}, got {(actual ? "accepted" : "refused")}");
            }
        }

        Expect("HTTP/1.1 Host, parsed", host, Parsed($"GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n"));
        Expect("HTTP/1.1 CONNECT, parsed", connect, Parsed($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"));
        Expect("HTTP/1.1 Host, written", host, H1Messages.WriteRequest("GET", "/", authority).Result > 0);
        // In an absolute-form URI the authority ends at the first "/" or "?" (RFC 3986 3.2):
        // "http://a/b/" names authority "a" and path "/b/", rightly taken. Such an authority
        // cannot be written there at all, so those two entry points have nothing to say of it.
        if (authority.IndexOfAny(['/', '?']) < 0)
        {
            Expect("HTTP/1.1 absolute-form, parsed", host && namesHost, Parsed($"GET http://{authority}/ HTTP/1.1\r\nHost: h\r\n\r\n"));
            Expect("HTTP/1.1 absolute-form, written", host && namesHost, H1Messages.WriteRequest("GET", $"http://{authority}/", "h").Result > 0);
        }

        Expect("HTTP/1.1 CONNECT, written", connect, H1Messages.WriteRequest("CONNECT", authority, authority).Result > 0);
        Expect("HTTP/2 :authority", host && authority.Length > 0, Http2([(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", authority)]));
        Expect("HTTP/2 CONNECT :authority", connect, Http2([(":method", "CONNECT"), (":authority", authority)]));
        Expect("HTTP/2 Host", host, Http2([(":method", "GET"), (":scheme", "http"), (":path", "/"), ("host", authority)]));

        Assert.True(verdicts.Count == 0, $"\"{authority}\":\n" + string.Join("\n", verdicts));
    }

    /// <summary>
    /// No two octets an authority may hold differ only in bit 5 (0x20), but a letter and its
    /// other case. httpasm_h2_request compares :authority with Host after both passed
    /// uri-host's grammar, folding case by setting that bit, and refuses a pair that folds
    /// alike without being letters: tests/coverage/unreachable.tsv lists that refusal as one
    /// no input can reach, on the strength of this test. If the grammar ever admits such a
    /// pair, this fails first, and the refusal becomes reachable (and needed).
    /// </summary>
    [Fact]
    public void AdmitsNoOctetPairThatFoldsAlikeButLetters()
    {
        Platform.RequireLinuxX64();
        // An octet counts as allowed when a Host takes it inside a reg-name or an IPvFuture's
        // tail: the grammar's two widest octet sets (an IPv6address holds HEXDIG, ":" and ".",
        // a port DIGIT, both inside them; "%" is allowed only before two HEXDIG, and 0x05, its
        // partner, never is).
        var allowed = Enumerable.Range(0, 256).Where(octet =>
        {
            string c = Encoding.Latin1.GetString([(byte)octet]);
            return Parsed($"GET / HTTP/1.1\r\nHost: a{c}b\r\n\r\n") || Parsed($"GET / HTTP/1.1\r\nHost: [v1.a{c}b]\r\n\r\n")
                || Parsed($"GET / HTTP/1.1\r\nHost: a{c}41\r\n\r\n");
        }).ToHashSet();
        Assert.Contains('~', allowed.Select(o => (char)o));
        var pairs = allowed.Where(o => allowed.Contains(o ^ 0x20) && !char.IsAsciiLetter((char)o)).Select(o => $"0x{o:X2}").ToList();
        Assert.True(pairs.Count == 0, "pairs that fold alike: " + string.Join(", ", pairs));
    }

    /// <summary>Whether httpasm_h1_parse_request takes a head.</summary>
    /// <param name="head">The head, as Latin-1 text.</param>
    /// <returns>True when parsed whole.</returns>
    private static bool Parsed(string head) => H1Parsing.Parse(head).Result > 0;

    /// <summary>Whether httpasm_h2_request takes a decoded request head.</summary>
    /// <param name="fields">The fields, pseudo-fields first.</param>
    /// <returns>True when it returns 0.</returns>
    private static bool Http2((string, string)[] fields)
    {
        using var native = new NativeFields(fields);
        HttpRequest request = default;
        return Native.H2Request(native.Pointer, native.Count, &request) == 0;
    }
}
