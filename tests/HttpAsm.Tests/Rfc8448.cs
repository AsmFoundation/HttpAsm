using System.Text.RegularExpressions;

namespace HttpAsm.Tests;

/// <summary>
/// RFC 8448's example handshake traces, read from the pinned text (specs/rfc/rfc8448.txt) so no
/// octet of them is copied by hand: each section's steps, "{server}  derive secret "tls13 c hs
/// traffic":" and the like, with the labeled octets under each ("PRK (32 octets):  1d c8 ...").
/// A field's octets run over its continuation lines and across the page breaks (the footer and
/// header lines are skipped) until the count its label announces is read, so a dump split by a
/// page reads whole. Steps that say "(same as ...)" carry no octets of their own.
/// </summary>
internal static partial class Rfc8448
{
    /// <summary>One step of a trace.</summary>
    /// <param name="Section">The section's number: 3 (a simple 1-RTT handshake), 4 (resumed with
    /// 0-RTT), 5 (HelloRetryRequest), 6 (client authentication) or 7 (compatibility mode).</param>
    /// <param name="Who">"client" or "server".</param>
    /// <param name="Action">What the step does, as its line says it, without the final colon
    /// ("derive secret \"tls13 c hs traffic\"").</param>
    /// <param name="Fields">Its labeled octets, by label ("PRK", "hash", "complete record").</param>
    internal sealed record Step(int Section, string Who, string Action, IReadOnlyDictionary<string, byte[]> Fields)
    {
        /// <summary>The label in quotes in the action, without RFC 9846's "tls13 " prefix:
        /// "c hs traffic" for derive secret "tls13 c hs traffic"; null when there is none.</summary>
        public string? Label
        {
            get
            {
                Match m = QuotedLabel().Match(Action);
                return m.Success ? m.Groups[1].Value : null;
            }
        }
    }

    /// <summary>Every step of every trace, in the RFC's order.</summary>
    public static IReadOnlyList<Step> Steps { get; } = Parse();

    /// <summary>A step's header line: three spaces, the party in braces, two spaces, the action.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^   \{(client|server)\}  (.*)$")]
    private static partial Regex StepLine();

    /// <summary>A field's first line: six spaces, the label, its octet count, then octets.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^      (\S.*?) \((\d+) octets?\):\s*(.*)$")]
    private static partial Regex FieldLine();

    /// <summary>A section heading: its number at the margin.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^(\d+)\.  \S")]
    private static partial Regex SectionLine();

    /// <summary>The quoted label of an action, "tls13 " stripped.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex("\"(?:tls13 )?([^\"]+)\"")]
    private static partial Regex QuotedLabel();

    /// <summary>Two hex digits: one octet of a dump.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"\b[0-9a-f]{2}\b")]
    private static partial Regex HexOctet();

    /// <summary>Reads the pinned text into its steps.</summary>
    /// <returns>The steps.</returns>
    /// <exception cref="InvalidDataException">A field's dump ends before the octets its label
    /// announces (the parser or the file is not what the tests expect).</exception>
    private static List<Step> Parse()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc8448.txt"));
        var steps = new List<Step>();
        int section = 0;
        string? who = null, action = null;
        Dictionary<string, byte[]>? fields = null;
        void Finish()
        {
            if (who is not null)
            {
                steps.Add(new Step(section, who, action!, fields!));
            }

            who = null;
        }

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            Match sectionMatch = SectionLine().Match(line);
            if (sectionMatch.Success)
            {
                Finish();
                section = int.Parse(sectionMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                continue;
            }

            Match stepMatch = StepLine().Match(line);
            if (stepMatch.Success)
            {
                Finish();
                who = stepMatch.Groups[1].Value;
                action = stepMatch.Groups[2].Value.TrimEnd().TrimEnd(':');
                fields = [];
                continue;
            }

            Match fieldMatch = FieldLine().Match(line);
            if (fieldMatch.Success && who is not null)
            {
                int count = int.Parse(fieldMatch.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture);
                var octets = new List<byte>();
                string rest = fieldMatch.Groups[3].Value;
                int j = i;
                while (true)
                {
                    foreach (Match o in HexOctet().Matches(rest))
                    {
                        octets.Add(Convert.ToByte(o.Value, 16));
                    }

                    if (octets.Count >= count)
                    {
                        break;
                    }

                    // the next line of the dump: past blank lines and a page's footer and header
                    do
                    {
                        j++;
                        if (j >= lines.Length)
                        {
                            throw new InvalidDataException($"RFC 8448: {fieldMatch.Groups[1].Value} ends after {octets.Count} of {count} octets");
                        }
                    }
                    while (lines[j].Trim().Length == 0 || lines[j].StartsWith("Thomson", StringComparison.Ordinal)
                           || lines[j].StartsWith("RFC 8448", StringComparison.Ordinal));
                    rest = lines[j];
                }

                if (octets.Count != count)
                {
                    throw new InvalidDataException($"RFC 8448: {fieldMatch.Groups[1].Value} has {octets.Count} octets, not {count}");
                }

                fields![fieldMatch.Groups[1].Value] = [.. octets];
                i = j;
            }
        }

        Finish();
        return steps;
    }

    /// <summary>A number of section 2's key: three spaces, its name, a colon, octets, and more
    /// octets on lines of six spaces.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^   (modulus \(public\)|public exponent|private exponent|prime1|prime2|exponent1|exponent2|coefficient):\s+(.*)$")]
    private static partial Regex KeyLine();

    /// <summary>A continuation line of section 2's numbers: six spaces, then octets only.</summary>
    /// <returns>The pattern.</returns>
    [GeneratedRegex(@"^      [0-9a-f]{2}( [0-9a-f]{2})*\s*$")]
    private static partial Regex KeyContinuation();

    /// <summary>
    /// The server's RSA key of section 2 ("The server in most examples uses an RSA certificate
    /// with a private key of"), read from the pinned text as an RSAPrivateKey (PKCS#1, RFC 8017
    /// A.1.2) in DER: version 0, n, e, d, p, q, dp, dq, qinv.
    /// </summary>
    public static byte[] ServerRsaKey { get; } = ParseServerKey();

    /// <summary>Reads section 2's numbers and encodes them.</summary>
    /// <returns>The DER.</returns>
    /// <exception cref="InvalidDataException">A number is missing (the file is not what the tests expect).</exception>
    private static byte[] ParseServerKey()
    {
        string[] lines = File.ReadAllLines(Path.Combine(AppContext.BaseDirectory, "specs", "rfc", "rfc8448.txt"));
        var numbers = new Dictionary<string, byte[]>();
        for (int i = 0; i < lines.Length && numbers.Count < 8; i++)
        {
            Match m = KeyLine().Match(lines[i]);
            if (!m.Success)
            {
                continue;
            }

            var octets = new List<byte>();
            string rest = m.Groups[2].Value;
            int j = i;
            while (true)
            {
                foreach (Match o in HexOctet().Matches(rest))
                {
                    octets.Add(Convert.ToByte(o.Value, 16));
                }

                if (j + 1 >= lines.Length || !KeyContinuation().IsMatch(lines[j + 1]))
                {
                    break;
                }

                rest = lines[++j];
            }

            numbers[m.Groups[1].Value] = [.. octets];
            i = j;
        }

        string[] order = ["modulus (public)", "public exponent", "private exponent", "prime1", "prime2", "exponent1", "exponent2", "coefficient"];
        if (order.Any(name => !numbers.ContainsKey(name)))
        {
            throw new InvalidDataException("RFC 8448: section 2's key is not whole");
        }

        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(0);
            foreach (string name in order)
            {
                w.WriteIntegerUnsigned(numbers[name]);
            }
        }

        return w.Encode();
    }
}
