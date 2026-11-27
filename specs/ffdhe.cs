// =============================================================================
// ffdhe.cs - the five finite-field Diffie-Hellman groups of RFC 7919 (TLS's ffdhe2048, ffdhe3072,
// ffdhe4096, ffdhe6144 and ffdhe8192) for crypto/ffdhe.asm, each prime proven before anything is
// written, from the pinned specs/rfc/rfc7919.txt.
//
// Writes src/HttpAsm.Core/include/generated/ffdhe_groups.inc, per group b (2048 .. 8192):
//   ffdhe<b>_p        p, b / 64 little-endian qwords: the modulus the Montgomery products take
//   ffdhe<b>_rr       R^2 mod p (R = 2^b): the way into Montgomery form
//   ffdhe<b>_n0       -p^-1 mod 2^64
//   FFDHE<b>_MIN_BITS the shortest private exponent RFC 7919 Appendix A advises (225 to 400 bits)
//
// The proofs, all in BigInteger arithmetic independent of the assembly and of the RFC's hex:
//   - each p is rebuilt from Appendix A's formula, p = 2^b - 2^(b-64) + {[2^(b-130) e] + X} 2^64 - 1,
//     with b and X read from the formula's line and [2^(b-130) e] from Euler's number summed as
//     floor(2^(b-130+G) / k!) over k (G guard bits; the floor is accepted only when the sum's
//     fraction keeps its distance from the next integer by more than the terms' rounding could
//     move it), and must equal the RFC's hexadecimal p; q = (p - 1) / 2 must equal its q;
//   - p and q pass Miller-Rabin to 32 prime bases (p is a safe prime), 2 generates the subgroup
//     of order q (2^q = 1 mod p, 2 != 1), p's top 64 bits and low 64 bits are all ones;
//   - each constant against its definition (R^2 R^-2 = 1 modulo p, p n0 = -1 modulo 2^64).
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/ffdhe.cs            write the file
//   dotnet run specs/ffdhe.cs -- --check fail when the committed file differs (CI)
// Exit status: 0 success; 1 a proof or a check failed; 2 wrong usage.
// =============================================================================
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/ffdhe.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
string rfc = Path.Combine(root, "specs", "rfc", "rfc7919.txt");
string target = Path.Combine(root, "src", "HttpAsm.Core", "include", "generated", "ffdhe_groups.inc");
if (!File.Exists(rfc) || !Directory.Exists(Path.GetDirectoryName(target)))
{
    Console.Error.WriteLine("ffdhe: run this from the repository root (specs/rfc/rfc7919.txt or the generated folder was not found)");
    return 2;
}

try
{
    var groups = Rfc7919.Read(File.ReadAllLines(rfc));
    foreach (var g in groups)
        Proofs.Prove(g);
    string text = Emitter.Write(groups);
    if (check)
    {
        string committed = File.Exists(target) ? File.ReadAllText(target).Replace("\r\n", "\n") : "";
        if (committed != text)
        {
            Console.Error.WriteLine($"ffdhe: {target} differs from what the proofs produce: run dotnet run specs/ffdhe.cs");
            return 1;
        }
        Console.WriteLine("ffdhe: the committed groups are proven and current");
        return 0;
    }
    File.WriteAllText(target, text);
    Console.WriteLine($"ffdhe: wrote {target}");
    return 0;
}
catch (ProofFailed e)
{
    Console.Error.WriteLine($"ffdhe: {e.Message}");
    return 1;
}

/// <summary>A proof that did not hold: the groups are not written.</summary>
/// <param name="message">What failed, with the values that show it.</param>
sealed class ProofFailed(string message) : Exception(message);

/// <summary>One group as RFC 7919 Appendix A states it.</summary>
/// <param name="Bits">b: p's size in bits.</param>
/// <param name="X">The formula's added constant.</param>
/// <param name="P">The hexadecimal p.</param>
/// <param name="Q">The hexadecimal q = (p - 1) / 2.</param>
/// <param name="MinBits">The shortest secret key its "should choose a secret key of at least" advises.</param>
sealed record Group(int Bits, BigInteger X, BigInteger P, BigInteger Q, int MinBits);

/// <summary>Reads Appendix A of the pinned RFC text: page breaks (the footer and header lines a
/// hexadecimal block can straddle) are skipped.</summary>
static class Rfc7919
{
    /// <summary>The five groups, in the appendix's order.</summary>
    /// <param name="lines">rfc7919.txt's lines.</param>
    /// <returns>Each group's b, X, p, q and minimum exponent size.</returns>
    /// <exception cref="ProofFailed">A group's formula, numbers or advice is not where the appendix has them.</exception>
    public static List<Group> Read(string[] lines)
    {
        var result = new List<Group>();
        var formula = new Regex(@"^\s*p = 2\^(\d+) - 2\^(\d+) \+ \{\[2\^(\d+) \* e\] \+ (\d+) ?\} \* 2\^64 - 1\s*$");
        var advice = new Regex(@"^\s*(\d+) bits\.\s*$");
        for (int i = 0; i < lines.Length; i++)
        {
            var m = formula.Match(lines[i]);
            if (!m.Success)
                continue;
            int b = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            if (int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture) != b - 64 || int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture) != b - 130)
                throw new ProofFailed($"the formula at line {i + 1} is not the appendix's shape: {lines[i].Trim()}");
            var x = BigInteger.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture);
            int at = i;
            var p = Hex(lines, ref at, "The hexadecimal representation of p is:");
            var q = Hex(lines, ref at, "The hexadecimal representation of q is:");
            int minBits = 0;
            for (; at < lines.Length && minBits == 0; at++)
            {
                var a = advice.Match(lines[at]);
                if (a.Success && lines[at - 1].Contains("should choose a secret key of at least"))
                    minBits = int.Parse(a.Groups[1].Value, CultureInfo.InvariantCulture);
            }
            if (minBits == 0)
                throw new ProofFailed($"ffdhe{b}: no minimum exponent size after its numbers");
            result.Add(new Group(b, x, p, q, minBits));
        }
        if (result.Count != 5 || !result.Select(g => g.Bits).SequenceEqual(new[] { 2048, 3072, 4096, 6144, 8192 }))
            throw new ProofFailed($"Appendix A should hold ffdhe2048 .. ffdhe8192; found {string.Join(", ", result.Select(g => g.Bits))}");
        return result;
    }

    /// <summary>The hexadecimal number after a heading: the groups of eight hex digits on the lines
    /// that follow, up to the first line that is neither digits nor a page break.</summary>
    /// <param name="lines">The RFC's lines.</param>
    /// <param name="at">Where to look from; left after the number.</param>
    /// <param name="heading">The line before the digits.</param>
    /// <returns>The number.</returns>
    /// <exception cref="ProofFailed">The heading or the digits are missing.</exception>
    static BigInteger Hex(string[] lines, ref int at, string heading)
    {
        while (at < lines.Length && lines[at].Trim() != heading)
            at++;
        if (at == lines.Length)
            throw new ProofFailed($"no \"{heading}\" after line {at}");
        at++;
        var digits = new StringBuilder();
        var hexLine = new Regex(@"^\s+([0-9A-F]{8})( [0-9A-F]{8})*\s*$");
        bool started = false;
        for (; at < lines.Length; at++)
        {
            string line = lines[at];
            if (hexLine.IsMatch(line))
            {
                digits.Append(line.Replace(" ", "").Trim());
                started = true;
                continue;
            }
            bool pageBreak = line.Trim().Length == 0 || line.StartsWith("Gillmor") || line.StartsWith("RFC 7919") || line == "\f";
            if (pageBreak || line.Trim() == "\f")
            {
                if (started && line.Trim().Length != 0 && !line.StartsWith("Gillmor") && !line.StartsWith("RFC 7919"))
                    break;
                continue;
            }
            if (started)
                break;
        }
        if (digits.Length == 0)
            throw new ProofFailed($"no digits after \"{heading}\"");
        return BigInteger.Parse("0" + digits, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }
}

/// <summary>The proofs each group passes before it is written.</summary>
static class Proofs
{
    static readonly int[] Bases = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131 };

    /// <summary>Checks a group: p from the formula equals the RFC's hex, q = (p - 1) / 2, both prime,
    /// 2 of order q, the all-ones ends.</summary>
    /// <param name="g">The group as read.</param>
    /// <exception cref="ProofFailed">Any check fails.</exception>
    public static void Prove(Group g)
    {
        int b = g.Bits;
        var floorE = FloorTimesE(b - 130);
        var p = BigInteger.Pow(2, b) - BigInteger.Pow(2, b - 64) + (floorE + g.X) * BigInteger.Pow(2, 64) - 1;
        if (p != g.P)
            throw new ProofFailed($"ffdhe{b}: the formula's p differs from the RFC's hexadecimal p");
        if ((p - 1) / 2 != g.Q)
            throw new ProofFailed($"ffdhe{b}: (p - 1) / 2 differs from the RFC's q");
        var ones = BigInteger.Pow(2, 64) - 1;
        if ((p & ones) != ones || (p >> (b - 64)) != ones || p.GetBitLength() != b)
            throw new ProofFailed($"ffdhe{b}: p's ends are not 64 ones each, or its size is not {b}");
        if (!Prime(p) || !Prime(g.Q))
            throw new ProofFailed($"ffdhe{b}: p or q fails Miller-Rabin");
        if (BigInteger.ModPow(2, g.Q, p) != 1)
            throw new ProofFailed($"ffdhe{b}: 2 is not of order q");
        Console.WriteLine($"ffdhe: ffdhe{b} proven (formula = RFC hex, p and q prime, 2 of order q; secret keys of at least {g.MinBits} bits)");
    }

    /// <summary>floor(2^n e) from e's series: the sum of floor(2^(n+G) / k!) over k, with G guard bits;
    /// each floor loses less than 1, so the true value lies within the term count of the sum, and
    /// the result is accepted only when that window cannot reach an integer boundary.</summary>
    /// <param name="n">The power of two.</param>
    /// <returns>floor(2^n e).</returns>
    /// <exception cref="ProofFailed">The window straddles a boundary (more guard bits needed).</exception>
    static BigInteger FloorTimesE(int n)
    {
        const int guard = 128;
        var scale = BigInteger.Pow(2, n + guard);
        BigInteger sum = 0, term = scale;
        int k = 0;
        while (term > 0)
        {
            sum += term;
            k++;
            term /= k;
        }
        // The true 2^(n+G) e is in [sum, sum + k): its floor by 2^G is the same at both ends.
        var low = sum >> guard;
        var high = (sum + k) >> guard;
        if (low != high)
            throw new ProofFailed($"2^{n} e: the guard bits do not settle the floor");
        return low;
    }

    /// <summary>Miller-Rabin to the 32 smallest primes as bases.</summary>
    /// <param name="n">An odd candidate above them.</param>
    /// <returns>Whether every base calls it a probable prime.</returns>
    static bool Prime(BigInteger n)
    {
        var d = n - 1;
        int s = 0;
        while (d.IsEven)
        {
            d >>= 1;
            s++;
        }
        foreach (int a in Bases)
        {
            var x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
                continue;
            bool composite = true;
            for (int r = 1; r < s && composite; r++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                    composite = false;
            }
            if (composite)
                return false;
        }
        return true;
    }
}

/// <summary>Writes the include file.</summary>
static class Emitter
{
    /// <summary>The file's text: a header, then per group its limbs, R^2 mod p, n0 and the advice.</summary>
    /// <param name="groups">The proven groups.</param>
    /// <returns>The text, with \n line ends.</returns>
    /// <exception cref="ProofFailed">A derived constant fails its own check.</exception>
    public static string Write(List<Group> groups)
    {
        var s = new StringBuilder();
        s.Append("; =============================================================================\n");
        s.Append("; generated/ffdhe_groups.inc - written by specs/ffdhe.cs (do not edit: run it). The five\n");
        s.Append("; finite-field groups of RFC 7919 for crypto/ffdhe.asm, each p proven equal to Appendix A's\n");
        s.Append("; formula (with Euler's number) and to its hexadecimal p, p and (p - 1) / 2 prime, 2 of order q.\n");
        s.Append(";   ffdhe<b>_p   p, little-endian qwords      ffdhe<b>_rr  R^2 mod p (R = 2^b)\n");
        s.Append(";   ffdhe<b>_n0  -p^-1 mod 2^64                FFDHE<b>_MIN_BITS  the shortest secret key advised\n");
        s.Append("; =============================================================================\n");
        var two64 = BigInteger.Pow(2, 64);
        foreach (var g in groups)
        {
            int k = g.Bits / 64;
            var r = BigInteger.Pow(2, g.Bits);
            var rr = r * r % g.P;
            var inv = BigInteger.ModPow(g.P % two64, two64 / 2 - 1, two64);   // p^-1 mod 2^64 (odd p: Euler's phi = 2^63)
            var n0 = (two64 - inv) % two64;
            if ((g.P * n0 + 1) % two64 != 0)
                throw new ProofFailed($"ffdhe{g.Bits}: n0 is not -p^-1 mod 2^64");
            if (rr * BigInteger.ModPow(r, g.P - 3, g.P) % g.P != 1)
                throw new ProofFailed($"ffdhe{g.Bits}: R^2 R^-2 is not 1 modulo p");
            s.Append('\n');
            s.Append($"FFDHE{g.Bits}_MIN_BITS equ {g.MinBits}\n");
            s.Append($"align 64\nffdhe{g.Bits}_p:\n");
            Limbs(s, g.P, k);
            s.Append($"align 64\nffdhe{g.Bits}_rr:\n");
            Limbs(s, rr, k);
            s.Append($"ffdhe{g.Bits}_n0:\n    dq 0x{n0.ToString("X16", CultureInfo.InvariantCulture).TrimStart('0').PadLeft(16, '0')}\n");
        }
        return s.ToString();
    }

    /// <summary>k little-endian qwords, four a line.</summary>
    /// <param name="s">Where to write.</param>
    /// <param name="v">The number (below 2^(64k)).</param>
    /// <param name="k">How many qwords.</param>
    static void Limbs(StringBuilder s, BigInteger v, int k)
    {
        var mask = BigInteger.Pow(2, 64) - 1;
        for (int i = 0; i < k; i += 4)
        {
            s.Append("    dq ");
            for (int j = i; j < i + 4 && j < k; j++)
            {
                var limb = (v >> (64 * j)) & mask;
                string hex = limb.ToString("X", CultureInfo.InvariantCulture);
                hex = hex.Length > 16 ? hex[^16..] : hex.PadLeft(16, '0');
                s.Append(j > i ? ", " : "").Append("0x").Append(hex);
            }
            s.Append('\n');
        }
    }
}
