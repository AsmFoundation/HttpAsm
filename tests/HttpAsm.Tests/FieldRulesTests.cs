using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// The field rules every HTTP version shares (src/HttpAsm.Core/include/semantics/fields.inc),
/// through the C ABI functions that assemble them: proven octet by octet against references
/// written from the ABNF here, independently of the assembler's class table.
/// </summary>
public sealed unsafe class FieldRulesTests
{
    /// <summary>tchar, from RFC 9110 section 5.6.2's ABNF (RFC9110-5.6.2-2).</summary>
    /// <param name="c">An octet value.</param>
    /// <returns>True when the octet may appear in a token.</returns>
    private static bool IsTchar(int c) =>
        c is (>= '0' and <= '9') or (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') || "!#$%&'*+-.^_`|~".Contains((char)c);

    /// <summary>
    /// The octets a field value may hold, as HttpAsm reads RFC 9110 section 5.5: field-vchar
    /// (VCHAR 0x21-0x7E, obs-text 0x80-0xFF), SP and HTAB (RFC9110-5.5-2). Every CTL other than
    /// HTAB is refused: CR, LF and NUL as RFC9110-5.5-5#1 and RFC9113-8.2.1-3.3 require, the
    /// others by the choice RFC9110-5.5-5#2 leaves open.
    /// </summary>
    /// <param name="c">An octet value.</param>
    /// <returns>True when the octet may appear in a field value.</returns>
    private static bool IsValueOctet(int c) => c is 0x09 or (>= 0x20 and <= 0x7E) or >= 0x80;

    /// <summary>Calls httpasm_token_length on a managed array.</summary>
    /// <param name="value">The octets.</param>
    /// <returns>The function's result.</returns>
    private static ulong TokenLength(byte[] value)
    {
        fixed (byte* p = value)
        {
            return Native.TokenLength(p, (nuint)value.Length);
        }
    }

    /// <summary>Calls httpasm_field_value_scan on a managed array.</summary>
    /// <param name="value">The octets.</param>
    /// <returns>The function's result.</returns>
    private static ulong FieldValueScan(byte[] value)
    {
        fixed (byte* p = value)
        {
            return Native.FieldValueScan(p, (nuint)value.Length);
        }
    }

    /// <summary>Before the first release the ABI promises nothing, and says so with version 0.</summary>
    [Fact]
    public void AbiVersionIsZeroBeforeTheFirstRelease()
    {
        Platform.RequireLinuxX64();
        Assert.Equal(0u, Native.AbiVersion());
    }

    /// <summary>Every octet value, between two tchars: a token runs exactly to the first non-tchar.</summary>
    [Fact]
    [Requirement("RFC9110-5.6.2-2", "RFC9110-5.1-2")]
    public void TokenLengthAcceptsExactlyTheTchars()
    {
        Platform.RequireLinuxX64();
        for (int c = 0; c < 256; c++)
        {
            byte[] value = [(byte)'a', (byte)'b', (byte)c, (byte)'d'];
            Assert.True((IsTchar(c) ? 4UL : 2UL) == TokenLength(value), $"octet 0x{c:X2}");
        }
    }

    /// <summary>Methods and field names as they appear on the wire, and the octets that end them.</summary>
    /// <param name="text">The octets, as Latin-1 text.</param>
    /// <param name="expected">The token's length.</param>
    [Theory]
    [InlineData("GET", 3)]
    [InlineData("M-SEARCH", 8)]
    [InlineData("content-type", 12)]
    [InlineData("Content-Type: text/html", 12)]
    [InlineData("x-custom_header.v1~", 19)]
    [InlineData("two words", 3)]
    [InlineData("\"quoted\"", 0)]
    [InlineData("", 0)]
    [Requirement("RFC9110-5.6.2-2", "RFC9110-5.1-2")]
    public void TokenLengthOfWireTokens(string text, int expected)
    {
        Platform.RequireLinuxX64();
        Assert.Equal((ulong)expected, TokenLength(Encoding.Latin1.GetBytes(text)));
    }

    /// <summary>
    /// Every octet value at every position of values from 1 to 48 octets long: the short path,
    /// whole vectors, and every overlapping tail. The result is the position when the octet is
    /// forbidden, the length otherwise.
    /// </summary>
    [Fact]
    [Requirement("RFC9110-5.5-2", "RFC9110-5.5-5#1", "RFC9110-5.5-5#2", "RFC9113-8.2.1-3.3")]
    public void FieldValueScanFindsEveryForbiddenOctetAtEveryPosition()
    {
        Platform.RequireLinuxX64();
        for (int length = 1; length <= 48; length++)
        {
            for (int at = 0; at < length; at++)
            {
                for (int c = 0; c < 256; c++)
                {
                    byte[] value = new byte[length];
                    value.AsSpan().Fill((byte)'v');
                    value[at] = (byte)c;
                    ulong expected = IsValueOctet(c) ? (ulong)length : (ulong)at;
                    ulong actual = FieldValueScan(value);
                    if (actual != expected)
                    {
                        Assert.Fail($"length {length}, octet 0x{c:X2} at {at}: expected {expected}, got {actual}");
                    }
                }
            }
        }
    }

    /// <summary>CR, LF and NUL are the dangerous three: found wherever they hide in a value.</summary>
    /// <param name="text">A value, as Latin-1 text.</param>
    /// <param name="expected">The index of its first forbidden octet.</param>
    [Theory]
    [InlineData("evil\r\nSet-Cookie: x=1", 4)]
    [InlineData("a\nb", 1)]
    [InlineData("nul\0inside", 3)]
    [InlineData("0123456789abcdef0123456789\r", 26)]
    [Requirement("RFC9110-5.5-5#1", "RFC9113-8.2.1-3.3")]
    public void FieldValueScanFindsCrLfAndNul(string text, int expected)
    {
        Platform.RequireLinuxX64();
        Assert.Equal((ulong)expected, FieldValueScan(Encoding.Latin1.GetBytes(text)));
    }

    /// <summary>Values that are valid as they stand: visible text, inner SP and HTAB, obs-text.</summary>
    /// <param name="text">A value, as Latin-1 text (obs-text as Latin-1 letters).</param>
    [Theory]
    [InlineData("")]
    [InlineData("text/html; charset=utf-8")]
    [InlineData("a\tb c")]
    [InlineData("café ÿ\u0080")]
    [InlineData("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)")]
    [Requirement("RFC9110-5.5-2")]
    public void FieldValueScanAcceptsValidValues(string text)
    {
        Platform.RequireLinuxX64();
        byte[] value = Encoding.Latin1.GetBytes(text);
        Assert.Equal((ulong)value.Length, FieldValueScan(value));
    }

    /// <summary>Of two forbidden octets, the first one is reported, wherever the vectors cut.</summary>
    [Fact]
    [Requirement("RFC9110-5.5-5#1")]
    public void FieldValueScanReportsTheFirstOfSeveral()
    {
        Platform.RequireLinuxX64();
        for (int length = 2; length <= 40; length++)
        {
            for (int first = 0; first < length - 1; first++)
            {
                for (int second = first + 1; second < length; second++)
                {
                    byte[] value = new byte[length];
                    value.AsSpan().Fill((byte)'v');
                    value[first] = (byte)'\n';
                    value[second] = 0;
                    Assert.True((ulong)first == FieldValueScan(value), $"length {length}, forbidden at {first} and {second}");
                }
            }
        }
    }

    /// <summary>
    /// Values that end where an inaccessible page begins, from 0 to 64 octets: neither scan may
    /// read past the value. A read past it faults and kills the test run. A 1-to-15-octet value
    /// there also takes the field scan's octet-by-octet path.
    /// </summary>
    [Fact]
    public void NeitherScanReadsPastTheValue()
    {
        Platform.RequireLinuxX64();
        using var buffer = new GuardedBuffer();
        for (int length = 0; length <= 64; length++)
        {
            byte[] value = new byte[length];
            value.AsSpan().Fill((byte)'t');
            byte* p = buffer.AtPageEnd(value);
            Assert.Equal((nuint)length, Native.TokenLength(p, (nuint)length));
            Assert.Equal((nuint)length, Native.FieldValueScan(p, (nuint)length));

            if (length > 0)
            {
                // A forbidden last octet: found, and still nothing read past it.
                value[^1] = (byte)'\r';
                p = buffer.AtPageEnd(value);
                Assert.Equal((nuint)(length - 1), Native.TokenLength(p, (nuint)length));
                Assert.Equal((nuint)(length - 1), Native.FieldValueScan(p, (nuint)length));
            }
        }
    }
}
