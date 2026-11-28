namespace HttpAsm.Tests;

/// <summary>
/// The tests' own reading of TLS 1.3's handshake messages and extension blocks (RFC 9846 4,
/// 4.3, and the extensions' documents), written apart from tls/messages.asm and
/// tls/extensions.asm from the same rules, so the two can be compared on any octets: the same
/// answer (0 or minus the same alert) and, for what both accept, the same fields. Offsets are
/// into the octets given. Each rule is the RFC's; where the documents leave an alert open, the
/// library's choice is written here too (illegal_parameter for a type twice, decode_error for a
/// server_name type no document defines).
/// </summary>
internal static class TlsModel
{
    private const int DecodeError = -50, IllegalParameter = -47, MissingExtension = -109;

    /// <summary>An extension block as read: the known extensions by index (their data's offset and
    /// length), the count, the last type.</summary>
    /// <param name="Known">Index to (offset, length).</param>
    /// <param name="Count">The block's extensions.</param>
    /// <param name="Last">The last one's type.</param>
    internal sealed record Block(Dictionary<int, (int Offset, int Length)> Known, int Count, int Last)
    {
        /// <summary>The present bits.</summary>
        public ulong Present => Known.Keys.Aggregate(0ul, (p, i) => p | (1ul << i));
    }

    /// <summary>A big-endian uint16.</summary>
    /// <param name="s">The octets.</param>
    /// <param name="at">Where it starts.</param>
    /// <returns>Its value.</returns>
    private static int U16(ReadOnlySpan<byte> s, int at) => (s[at] << 8) | s[at + 1];

    /// <summary>The walk over an extension block (4.3).</summary>
    /// <param name="input">The octets the block is in.</param>
    /// <param name="start">The block's first octet (after its length).</param>
    /// <param name="length">Its octets.</param>
    /// <param name="message">The message's HTTPASM_TLS_IN_* bit.</param>
    /// <param name="block">The block, when 0 is returned.</param>
    /// <returns>0, or minus an alert.</returns>
    public static int Walk(ReadOnlySpan<byte> input, int start, int length, int message, out Block block)
    {
        var known = new Dictionary<int, (int, int)>();
        var seen = new HashSet<int>();
        int at = start, end = start + length, count = 0, last = 0;
        block = new Block(known, 0, 0);
        while (at < end)
        {
            if (end - at < 4)
            {
                return DecodeError;
            }

            int type = U16(input, at), n = U16(input, at + 2);
            if (n > end - at - 4)
            {
                return DecodeError;
            }

            if (!seen.Add(type))
            {
                return IllegalParameter;
            }

            count++;
            last = type;
            int index = TlsExtension.IndexOf(type);
            if (index >= 0)
            {
                if ((TlsExtension.Allowed[index] & message) == 0)
                {
                    return IllegalParameter;
                }

                known[index] = (at + 4, n);
            }

            at += 4 + n;
        }

        if (message == 1 && known.ContainsKey(TlsExtension.PreSharedKey) && last != 41)
        {
            return IllegalParameter;
        }

        block = new Block(known, count, last);
        return 0;
    }

    /// <summary>The syntax of each known extension the library reads, in index order (the first
    /// failure's alert is the answer).</summary>
    /// <param name="input">The octets.</param>
    /// <param name="block">The walked block.</param>
    /// <param name="message">The message's bit.</param>
    /// <returns>0, or minus an alert.</returns>
    public static int Check(ReadOnlySpan<byte> input, Block block, int message)
    {
        foreach (int index in block.Known.Keys.Order())
        {
            (int offset, int length) = block.Known[index];
            ReadOnlySpan<byte> d = input.Slice(offset, length);
            int answer = index switch
            {
                0 => ServerName(d, message),
                3 or 5 or 28 => Pairs16(d),
                8 => Alpn(d, message),
                15 => Compression(d),
                16 => d.Length != 2 ? DecodeError : U16(d, 0) < 64 ? IllegalParameter : 0,
                20 => PreSharedKey(d, message),
                21 => message == 32 ? (d.Length == 4 ? 0 : DecodeError) : (d.Length == 0 ? 0 : DecodeError),
                22 => message == 1 ? Vector8Pairs(d) : (d.Length == 2 ? 0 : DecodeError),
                23 => Vector16(d, out int c) && c >= 1 ? 0 : DecodeError,
                24 => Vector8(d, out int m) && m >= 1 ? 0 : DecodeError,
                25 => Authorities(d),
                26 => OidFilters(d),
                27 => d.Length == 0 ? 0 : DecodeError,
                29 => KeyShare(d, message),
                34 => d.Length == (message == 1 ? 2 : 1) ? 0 : DecodeError,
                _ => 0,
            };
            if (answer != 0)
            {
                return answer;
            }
        }

        return 0;
    }

    /// <summary>A uint16-length vector filling d exactly.</summary>
    /// <param name="d">The data.</param>
    /// <param name="length">Its contents' length.</param>
    /// <returns>Whether it is one.</returns>
    private static bool Vector16(ReadOnlySpan<byte> d, out int length)
    {
        length = d.Length >= 2 ? U16(d, 0) : -1;
        return d.Length >= 2 && length == d.Length - 2;
    }

    /// <summary>A uint8-length vector filling d exactly.</summary>
    /// <param name="d">The data.</param>
    /// <param name="length">Its contents' length.</param>
    /// <returns>Whether it is one.</returns>
    private static bool Vector8(ReadOnlySpan<byte> d, out int length)
    {
        length = d.Length >= 1 ? d[0] : -1;
        return d.Length >= 1 && length == d.Length - 1;
    }

    /// <summary>A uint16 vector of pairs, one at least.</summary>
    /// <param name="d">The data.</param>
    /// <returns>0 or decode_error.</returns>
    private static int Pairs16(ReadOnlySpan<byte> d) => Vector16(d, out int n) && n >= 2 && n % 2 == 0 ? 0 : DecodeError;

    /// <summary>A uint8 vector of pairs, one at least.</summary>
    /// <param name="d">The data.</param>
    /// <returns>0 or decode_error.</returns>
    private static int Vector8Pairs(ReadOnlySpan<byte> d) => Vector8(d, out int n) && n >= 2 && n % 2 == 0 ? 0 : DecodeError;

    /// <summary>compress_certificate's algorithms (RFC 8879).</summary>
    /// <param name="d">The data.</param>
    /// <returns>0 or decode_error.</returns>
    private static int Compression(ReadOnlySpan<byte> d) => Vector8Pairs(d);

    /// <summary>server_name (RFC 6066 3).</summary>
    /// <param name="d">The data.</param>
    /// <param name="message">The message's bit.</param>
    /// <returns>0 or minus an alert.</returns>
    private static int ServerName(ReadOnlySpan<byte> d, int message)
    {
        if (message == 16)
        {
            return 0;
        }

        if (message != 1)
        {
            return d.Length == 0 ? 0 : DecodeError;
        }

        if (!Vector16(d, out int n) || n == 0)
        {
            return DecodeError;
        }

        int at = 2;
        bool host = false;
        while (at < d.Length)
        {
            if (d[at] != 0)
            {
                return DecodeError;
            }

            if (host)
            {
                return IllegalParameter;
            }

            host = true;
            if (d.Length - at < 3)
            {
                return DecodeError;
            }

            int len = U16(d, at + 1);
            if (len == 0 || len > d.Length - at - 3)
            {
                return DecodeError;
            }

            at += 3 + len;
        }

        return 0;
    }

    /// <summary>ALPN (RFC 7301 3.1).</summary>
    /// <param name="d">The data.</param>
    /// <param name="message">The message's bit.</param>
    /// <returns>0 or decode_error.</returns>
    private static int Alpn(ReadOnlySpan<byte> d, int message)
    {
        if (!Vector16(d, out int n) || n < 2)
        {
            return DecodeError;
        }

        int at = 2, names = 0;
        while (at < d.Length)
        {
            int len = d[at];
            if (len == 0 || len > d.Length - at - 1)
            {
                return DecodeError;
            }

            at += 1 + len;
            names++;
        }

        return message == 4 && names != 1 ? DecodeError : 0;
    }

    /// <summary>pre_shared_key (4.3.11).</summary>
    /// <param name="d">The data.</param>
    /// <param name="message">The message's bit.</param>
    /// <returns>0 or minus an alert.</returns>
    private static int PreSharedKey(ReadOnlySpan<byte> d, int message)
    {
        if (message != 1)
        {
            return d.Length == 2 ? 0 : DecodeError;
        }

        if (d.Length < 2)
        {
            return DecodeError;
        }

        int ids = U16(d, 0);
        if (ids < 7 || ids > d.Length - 2)
        {
            return DecodeError;
        }

        int at = 2, end = 2 + ids, identities = 0;
        while (at < end)
        {
            if (end - at < 2)
            {
                return DecodeError;
            }

            int len = U16(d, at);
            if (len == 0 || len + 4 > end - at - 2)
            {
                return DecodeError;
            }

            at += 2 + len + 4;
            identities++;
        }

        if (d.Length - at < 2)
        {
            return DecodeError;
        }

        int binders = U16(d, at);
        at += 2;
        if (binders != d.Length - at || binders < 33)
        {
            return DecodeError;
        }

        while (at < d.Length)
        {
            int len = d[at];
            if (len < 32 || len > d.Length - at - 1)
            {
                return DecodeError;
            }

            at += 1 + len;
            identities--;
        }

        return identities == 0 ? 0 : IllegalParameter;
    }

    /// <summary>certificate_authorities (4.3.4).</summary>
    /// <param name="d">The data.</param>
    /// <returns>0 or decode_error.</returns>
    private static int Authorities(ReadOnlySpan<byte> d)
    {
        if (!Vector16(d, out int n) || n < 3)
        {
            return DecodeError;
        }

        int at = 2;
        while (at < d.Length)
        {
            if (d.Length - at < 2)
            {
                return DecodeError;
            }

            int len = U16(d, at);
            if (len == 0 || len > d.Length - at - 2)
            {
                return DecodeError;
            }

            at += 2 + len;
        }

        return 0;
    }

    /// <summary>oid_filters (4.3.5).</summary>
    /// <param name="d">The data.</param>
    /// <returns>0 or decode_error.</returns>
    private static int OidFilters(ReadOnlySpan<byte> d)
    {
        if (!Vector16(d, out _))
        {
            return DecodeError;
        }

        int at = 2;
        while (at < d.Length)
        {
            int oid = d[at];
            if (oid == 0 || oid > d.Length - at - 1)
            {
                return DecodeError;
            }

            at += 1 + oid;
            if (d.Length - at < 2)
            {
                return DecodeError;
            }

            int values = U16(d, at);
            if (values > d.Length - at - 2)
            {
                return DecodeError;
            }

            at += 2 + values;
        }

        return 0;
    }

    /// <summary>key_share (4.3.8).</summary>
    /// <param name="d">The data.</param>
    /// <param name="message">The message's bit.</param>
    /// <returns>0 or minus an alert.</returns>
    private static int KeyShare(ReadOnlySpan<byte> d, int message)
    {
        if (message == 64)
        {
            return d.Length == 2 ? 0 : DecodeError;
        }

        if (message == 2)
        {
            return d.Length >= 4 && U16(d, 2) >= 1 && U16(d, 2) + 4 == d.Length ? 0 : DecodeError;
        }

        if (!Vector16(d, out _))
        {
            return DecodeError;
        }

        var groups = new HashSet<int>();
        int at = 2;
        while (at < d.Length)
        {
            if (d.Length - at < 4)
            {
                return DecodeError;
            }

            int len = U16(d, at + 2);
            if (len == 0 || len > d.Length - at - 4)
            {
                return DecodeError;
            }

            if (!groups.Add(U16(d, at)))
            {
                return IllegalParameter;
            }

            at += 4 + len;
        }

        return 0;
    }

    /// <summary>A ClientHello or ServerHello as the model reads it.</summary>
    /// <param name="Answer">0 or minus an alert.</param>
    /// <param name="Fields">The fields' offsets and values (for what was accepted).</param>
    /// <param name="Block">The extensions.</param>
    internal sealed record Hello(int Answer, Dictionary<string, int> Fields, Block? Block);

    /// <summary>Reads a ClientHello's (type 1) or ServerHello's (type 2) body (4.2.2, 4.2.3).</summary>
    /// <param name="b">The body.</param>
    /// <param name="type">1 or 2.</param>
    /// <returns>What it reads.</returns>
    public static Hello ReadHello(ReadOnlySpan<byte> b, int type)
    {
        var f = new Dictionary<string, int>();
        Hello Fail(int alert) => new(alert, f, null);
        if (b.Length < 34)
        {
            return Fail(DecodeError);
        }

        f["legacy_version"] = U16(b, 0);
        f["random"] = 2;
        int at = 34;
        if (b.Length - at < 1 || b[at] > 32 || b[at] > b.Length - at - 1)
        {
            return Fail(DecodeError);
        }

        f["session_id"] = at + 1;
        f["session_id_length"] = b[at];
        at += 1 + b[at];
        int message = 1;
        if (type == 1)
        {
            if (b.Length - at < 2)
            {
                return Fail(DecodeError);
            }

            int suites = U16(b, at);
            if (suites < 2 || suites % 2 != 0 || suites > b.Length - at - 2)
            {
                return Fail(DecodeError);
            }

            f["cipher_suites"] = at + 2;
            f["cipher_suites_length"] = suites;
            at += 2 + suites;
            if (b.Length - at < 1 || b[at] == 0 || b[at] > b.Length - at - 1)
            {
                return Fail(DecodeError);
            }

            f["compression"] = at + 1;
            f["compression_length"] = b[at];
            at += 1 + b[at];
            if (at == b.Length)
            {
                return new Hello(0, f, null);
            }
        }
        else
        {
            if (b.Length - at < 3)
            {
                return Fail(DecodeError);
            }

            f["cipher_suite"] = U16(b, at);
            f["compression_method"] = b[at + 2];
            if (b[at + 2] != 0)
            {
                return Fail(IllegalParameter);
            }

            at += 3;
            bool retry = b.Slice(2, 32).SequenceEqual(RetryRandom);
            f["retry"] = retry ? 1 : 0;
            message = retry ? 64 : 2;
        }

        int least = type == 1 ? 7 : 6;
        if (b.Length - at < 2 || U16(b, at) != b.Length - at - 2 || U16(b, at) < least)
        {
            return Fail(DecodeError);
        }

        f["extensions_block"] = at + 2;
        f["extensions_length"] = U16(b, at);
        int answer = Walk(b, at + 2, U16(b, at), message, out Block block);
        if (answer == 0)
        {
            answer = Check(b, block, message);
        }

        if (answer == 0 && type == 1 && block.Known.TryGetValue(TlsExtension.SupportedVersions, out (int Offset, int Length) v))
        {
            bool offers13 = false;
            for (int i = 1; i < v.Length; i += 2)
            {
                offers13 |= b[v.Offset + i] == 3 && b[v.Offset + i + 1] == 4;
            }

            if (offers13 && (f["compression_length"] != 1 || b[f["compression"]] != 0))
            {
                answer = IllegalParameter;
            }
        }

        return new Hello(answer, f, answer == 0 ? block : null);
    }

    /// <summary>A body that is an extension block with its length (EncryptedExtensions, an
    /// entry's).</summary>
    /// <param name="b">The octets.</param>
    /// <param name="start">Where the block's length is.</param>
    /// <param name="length">The octets from there that are the block with its length.</param>
    /// <param name="message">The message's bit.</param>
    /// <param name="block">The block, when 0 is returned.</param>
    /// <returns>0 or minus an alert.</returns>
    public static int ReadBlock(ReadOnlySpan<byte> b, int start, int length, int message, out Block? block)
    {
        block = null;
        if (length < 2 || U16(b, start) != length - 2)
        {
            return DecodeError;
        }

        int answer = Walk(b, start + 2, length - 2, message, out Block walked);
        if (answer == 0)
        {
            answer = Check(b, walked, message);
        }

        block = answer == 0 ? walked : null;
        return answer;
    }

    /// <summary>A CertificateRequest (4.4.2).</summary>
    /// <param name="b">The body.</param>
    /// <returns>0 or minus an alert.</returns>
    public static int ReadCertificateRequest(ReadOnlySpan<byte> b)
    {
        if (b.Length < 1 || b[0] + 1 > b.Length)
        {
            return DecodeError;
        }

        int answer = ReadBlock(b, 1 + b[0], b.Length - 1 - b[0], 16, out Block? block);
        return answer != 0 ? answer : block!.Known.ContainsKey(TlsExtension.SignatureAlgorithms) ? 0 : MissingExtension;
    }

    /// <summary>A Certificate message (4.5.1): its entries' count, or minus an alert.</summary>
    /// <param name="b">The body.</param>
    /// <returns>The entries, or minus an alert.</returns>
    public static long ReadCertificate(ReadOnlySpan<byte> b)
    {
        if (b.Length < 1 || b[0] + 1 > b.Length)
        {
            return DecodeError;
        }

        int at = 1 + b[0];
        if (b.Length - at < 3)
        {
            return DecodeError;
        }

        int list = (b[at] << 16) | (b[at + 1] << 8) | b[at + 2];
        at += 3;
        if (list != b.Length - at)
        {
            return DecodeError;
        }

        int entries = 0;
        while (at < b.Length)
        {
            if (b.Length - at < 3)
            {
                return DecodeError;
            }

            int cert = (b[at] << 16) | (b[at + 1] << 8) | b[at + 2];
            if (cert == 0 || cert > b.Length - at - 3)
            {
                return DecodeError;
            }

            at += 3 + cert;
            if (b.Length - at < 2)
            {
                return DecodeError;
            }

            int ext = U16(b, at) + 2;
            if (ext > b.Length - at)
            {
                return DecodeError;
            }

            int answer = ReadBlock(b, at, ext, 8, out _);
            if (answer != 0)
            {
                return answer;
            }

            at += ext;
            entries++;
        }

        return entries;
    }

    /// <summary>A NewSessionTicket (4.7.1).</summary>
    /// <param name="b">The body.</param>
    /// <returns>0 or minus an alert.</returns>
    public static int ReadNewSessionTicket(ReadOnlySpan<byte> b)
    {
        if (b.Length < 9 || b[8] + 9 > b.Length)
        {
            return DecodeError;
        }

        int at = 9 + b[8];
        if (b.Length - at < 2)
        {
            return DecodeError;
        }

        int ticket = U16(b, at);
        if (ticket == 0 || ticket > b.Length - at - 2)
        {
            return DecodeError;
        }

        at += 2 + ticket;
        if (b.Length - at > 2 + 65534)
        {
            return DecodeError;
        }

        return ReadBlock(b, at, b.Length - at, 32, out _);
    }

    /// <summary>SHA-256 of "HelloRetryRequest".</summary>
    private static readonly byte[] RetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
}
