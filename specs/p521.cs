// =============================================================================
// p521.cs - the constants and the fixed-base table of crypto/p521.asm (NIST P-521, the curve TLS
// calls secp521r1), each proven before anything is written. specs/p384.cs's twin, with P-521's
// differences: the field's values are PLAIN (p = 2^521 - 1 is a Mersenne prime, and
// include/crypto/p521.inc reduces its products by the form, not by Montgomery), the table's
// windows are 6 bits wide (32 points each, 87 windows), and the numbers are nine qwords.
//
// Writes src/HttpAsm.Core/include/generated/p521_table.inc:
//   p521_p, p521_one, p521_b             p, the integer 1 and the curve's b: nine little-endian
//                                        qwords, plain (the field has no Montgomery form)
//   p521_n, p521_n_r2, p521_n0, p521_n_p n, R^2 mod n (R = 2^576: the scalars' Montgomery
//                                        radix, nine 64-bit limbs), -n^-1 mod 2^64, and p - n
//                                        (ECDSA's scalars; verification's r + n < p)
//   p521_mod_p, p521_mod_n               the inversion's records: the modulus in nine signed
//                                        62-bit limbs, then its inverse modulo 2^62
//   P521_W, P521_WINDOWS, P521_ENTRIES   the fixed-base windows: 6 bits, 87 of them, 32 points
//   p521_base_table                      87 windows of 32 points: window i holds m 2^(6i) G for
//                                        m = 1..32, affine, x then y, plain, nine little-endian
//                                        qwords each (400,896 octets)
//
// The proofs, all in BigInteger arithmetic independent of the assembly:
//   - the curve: p = 2^521 - 1 and n pass Miller-Rabin to 32 prime bases; G satisfies
//     y^2 = x^3 - 3x + b; n G is the point at infinity (G's order is n, a prime, and the
//     cofactor is 1: every point but infinity has order n); (n - 1) G = -G;
//   - each constant against its definition (n n0 = -1 modulo 2^64, R^2 R^-1 = R modulo n, the
//     records' limbs rebuild the modulus and their inverses multiply it to 1 modulo 2^62);
//   - the table twice: built by repeated affine addition (window i's entries are B_i, B_i + B_i,
//     ..., where B_i is G doubled 6i times), and every entry checked against its scalar multiple
//     computed by double-and-add from G alone (m 2^(6i) reduced modulo n, in Jacobian
//     coordinates with the textbook formulas: another route and other formulas than both the
//     table's and the assembly's); every entry on the curve, none at infinity.
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/p521.cs            write the file
//   dotnet run specs/p521.cs -- --check fail when the committed file differs (CI)
// Exit status: 0 success; 1 a proof or a check failed; 2 wrong usage.
// =============================================================================
using System.Globalization;
using System.Numerics;
using System.Text;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/p521.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
string target = Path.Combine(root, "src", "HttpAsm.Core", "include", "generated", "p521_table.inc");
if (!Directory.Exists(Path.GetDirectoryName(target)))
{
    Console.Error.WriteLine("p521: run this from the repository root (src/HttpAsm.Core/include/generated was not found)");
    return 2;
}

try
{
    Curve.Prove();
    string text = Emitter.Write();
    if (check)
    {
        string committed = File.Exists(target) ? File.ReadAllText(target).ReplaceLineEndings("\n") : "";
        if (committed != text)
        {
            Console.Error.WriteLine($"p521: {Path.GetRelativePath(root, target)} differs from what specs/p521.cs writes: run it and commit the result");
            return 1;
        }

        Console.WriteLine($"p521: p521_table.inc is current ({Curve.Windows} windows of {Curve.Entries} points, proven)");
        return 0;
    }

    File.WriteAllText(target, text);
    Console.WriteLine($"p521: wrote {Path.GetRelativePath(root, target)}: {Curve.Windows} windows of {Curve.Entries} points, proven");
    return 0;
}
catch (ProofException e)
{
    Console.Error.WriteLine("p521: " + e.Message);
    return 1;
}

/// <summary>A failed proof: a constant or a table entry is not what its definition gives.</summary>
/// <param name="message">What failed, for the console.</param>
sealed class ProofException(string message) : Exception(message);

/// <summary>
/// The curve (SP 800-186 3.2.1.5: y^2 = x^3 - 3x + b over GF(p), p = 2^521 - 1), its affine
/// arithmetic with an explicit point at infinity (null), and the proofs of everything the
/// generated file holds.
/// </summary>
static class Curve
{
    /// <summary>The field's prime, 2^521 - 1 (a Mersenne prime).</summary>
    public static readonly BigInteger P = (BigInteger.One << 521) - 1;

    /// <summary>The order of G (the group's order: the cofactor is 1).</summary>
    public static readonly BigInteger N = Hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");

    /// <summary>The curve's b (a is -3).</summary>
    public static readonly BigInteger B = Hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00");

    /// <summary>The base point G.</summary>
    public static readonly (BigInteger X, BigInteger Y) G = (
        Hex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
        Hex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));

    /// <summary>R = 2^576, the Montgomery radix of the scalars (nine 64-bit limbs).</summary>
    public static readonly BigInteger R = BigInteger.One << 576;

    /// <summary>The fixed-base window: bits per Booth digit.</summary>
    public const int W = 6;

    /// <summary>Windows of 6 bits covering 521 bits and the Booth carry: ceil(522 / 6).</summary>
    public const int Windows = (521 + W) / W;

    /// <summary>Points per window: the digits' magnitudes 1..2^(W - 1).</summary>
    public const int Entries = 1 << (W - 1);

    /// <summary>The table, built and proven by <see cref="Prove"/>: [window][m - 1].</summary>
    public static (BigInteger X, BigInteger Y)[][] Table { get; private set; } = [];

    /// <summary>Parses a big-endian hexadecimal constant as a nonnegative integer.</summary>
    /// <param name="hex">The digits.</param>
    /// <returns>The integer.</returns>
    public static BigInteger Hex(string hex) =>
        BigInteger.Parse("0" + hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    /// <summary>x modulo m in [0, m), for any sign of x.</summary>
    /// <param name="x">The value.</param>
    /// <param name="m">The modulus (positive).</param>
    /// <returns>The residue.</returns>
    public static BigInteger Mod(BigInteger x, BigInteger m)
    {
        BigInteger r = x % m;
        return r.Sign < 0 ? r + m : r;
    }

    /// <summary>The inverse of x modulo the prime m (Fermat: x^(m - 2)).</summary>
    /// <param name="x">A value not divisible by m.</param>
    /// <param name="m">A prime modulus.</param>
    /// <returns>x^-1 mod m.</returns>
    public static BigInteger Inverse(BigInteger x, BigInteger m) => BigInteger.ModPow(Mod(x, m), m - 2, m);

    /// <summary>Whether a point satisfies the curve's equation (infinity does not: callers check it).</summary>
    /// <param name="q">The affine point.</param>
    /// <returns>True when y^2 = x^3 - 3x + b modulo p.</returns>
    public static bool OnCurve((BigInteger X, BigInteger Y) q) =>
        Mod(q.Y * q.Y - (q.X * q.X * q.X - 3 * q.X + B), P).IsZero;

    /// <summary>
    /// The affine sum of two points, null standing for infinity: the chord's slope, or the
    /// tangent's for equal points (a = -3), and infinity for opposite points.
    /// </summary>
    /// <param name="a">The first point or null.</param>
    /// <param name="b">The second point or null.</param>
    /// <returns>a + b, or null for infinity.</returns>
    public static (BigInteger X, BigInteger Y)? Add((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b)
    {
        if (a is null)
        {
            return b;
        }

        if (b is null)
        {
            return a;
        }

        var (x1, y1) = a.Value;
        var (x2, y2) = b.Value;
        BigInteger slope;
        if (x1 == x2)
        {
            if (Mod(y1 + y2, P).IsZero)
            {
                return null;
            }

            slope = Mod((3 * x1 * x1 - 3) * Inverse(2 * y1, P), P);
        }
        else
        {
            slope = Mod((y2 - y1) * Inverse(x2 - x1, P), P);
        }

        BigInteger x3 = Mod(slope * slope - x1 - x2, P);
        return (x3, Mod(slope * (x1 - x3) - y1, P));
    }

    /// <summary>k q by double-and-add from the low bit (an independent route to the curve's facts).</summary>
    /// <param name="k">A nonnegative scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>k q, or null for infinity.</returns>
    public static (BigInteger X, BigInteger Y)? Multiply(BigInteger k, (BigInteger X, BigInteger Y) q)
    {
        (BigInteger X, BigInteger Y)? result = null;
        (BigInteger X, BigInteger Y)? addend = q;
        for (; !k.IsZero; k >>= 1)
        {
            if (!k.IsEven)
            {
                result = Add(result, addend);
            }

            addend = Add(addend, addend);
        }

        return result;
    }

    /// <summary>
    /// k q in Jacobian coordinates (x = X / Z^2, y = Y / Z^3) by double-and-add from the top bit,
    /// with the textbook formulas (doubling with M = 3 (X - Z^2)(X + Z^2) for a = -3; addition as
    /// Cohen, Miyaji and Ono's, falling back to doubling or infinity when H = 0) and one inversion
    /// at the end: the per-entry check, written apart from the assembly's arrangements and fast
    /// enough for all 2,784 entries.
    /// </summary>
    /// <param name="k">A nonnegative scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>k q, or null for infinity.</returns>
    public static (BigInteger X, BigInteger Y)? MultiplyJacobian(BigInteger k, (BigInteger X, BigInteger Y) q)
    {
        (BigInteger X, BigInteger Y, BigInteger Z) acc = (1, 1, 0);
        for (int bit = (int)k.GetBitLength() - 1; bit >= 0; bit--)
        {
            acc = Double(acc);
            if (!(k >> bit).IsEven)
            {
                acc = Sum(acc, (q.X, q.Y, 1));
            }
        }

        if (acc.Z.IsZero)
        {
            return null;
        }

        BigInteger zi = Inverse(acc.Z, P);
        return (Mod(acc.X * zi * zi, P), Mod(acc.Y * zi * zi * zi, P));

        static (BigInteger, BigInteger, BigInteger) Double((BigInteger X, BigInteger Y, BigInteger Z) a)
        {
            if (a.Z.IsZero || a.Y.IsZero)
            {
                return (1, 1, 0);
            }

            BigInteger zz = a.Z * a.Z % P;
            BigInteger m = Mod(3 * (a.X - zz) * (a.X + zz), P);
            BigInteger yy = a.Y * a.Y % P;
            BigInteger s = 4 * a.X * yy % P;
            BigInteger x3 = Mod(m * m - 2 * s, P);
            return (x3, Mod(m * (s - x3) - 8 * yy * yy, P), 2 * a.Y * a.Z % P);
        }

        static (BigInteger, BigInteger, BigInteger) Sum((BigInteger X, BigInteger Y, BigInteger Z) a, (BigInteger X, BigInteger Y, BigInteger Z) b)
        {
            if (a.Z.IsZero)
            {
                return b;
            }

            BigInteger z1z1 = a.Z * a.Z % P, z2z2 = b.Z * b.Z % P;
            BigInteger u1 = a.X * z2z2 % P, u2 = b.X * z1z1 % P;
            BigInteger s1 = a.Y * z2z2 % P * b.Z % P, s2 = b.Y * z1z1 % P * a.Z % P;
            BigInteger h = Mod(u2 - u1, P), r = Mod(s2 - s1, P);
            if (h.IsZero)
            {
                return r.IsZero ? Double(a) : (1, 1, 0);
            }

            BigInteger hh = h * h % P, hhh = hh * h % P;
            BigInteger x3 = Mod(r * r - hhh - 2 * u1 * hh, P);
            return (x3, Mod(r * (u1 * hh - x3) - s1 * hhh, P), a.Z * b.Z % P * h % P);
        }
    }

    /// <summary>Miller-Rabin to the first 32 primes as bases: a consistency check of the published primes.</summary>
    /// <param name="m">An odd candidate.</param>
    /// <returns>True when no base witnesses compositeness.</returns>
    public static bool ProbablyPrime(BigInteger m)
    {
        BigInteger d = m - 1;
        int s = 0;
        while (d.IsEven)
        {
            d >>= 1;
            s++;
        }

        int[] bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131];
        foreach (int a in bases)
        {
            BigInteger x = BigInteger.ModPow(a, d, m);
            if (x.IsOne || x == m - 1)
            {
                continue;
            }

            bool witness = true;
            for (int r = 1; r < s && witness; r++)
            {
                x = BigInteger.ModPow(x, 2, m);
                witness = x != m - 1;
            }

            if (witness)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Proves the curve and every constant, then builds the table by repeated addition and checks
    /// each entry against double-and-add from G; keeps the table for the emitter.
    /// </summary>
    /// <exception cref="ProofException">Any check fails.</exception>
    public static void Prove()
    {
        Require(ProbablyPrime(P), "p = 2^521 - 1 is not prime");
        Require(ProbablyPrime(N), "n is not prime");
        Require(N.GetBitLength() == 521 && N < P, "n is not a 521-bit number below p");
        Require(B < P && G.X < P && G.Y < P, "b or G's coordinates are not field elements");
        Require(OnCurve(G), "G is not on the curve");
        Require(Multiply(N, G) is null, "n G is not the point at infinity");
        Require(Multiply(N - 1, G) is { } last && last.X == G.X && Mod(last.Y + G.Y, P).IsZero, "(n - 1) G is not -G");

        // The table: window i holds B_i, 2 B_i, ..., 32 B_i with B_i = 2^(6i) G.
        var table = new (BigInteger X, BigInteger Y)[Windows][];
        (BigInteger X, BigInteger Y) basePoint = G;
        for (int i = 0; i < Windows; i++)
        {
            table[i] = new (BigInteger, BigInteger)[Entries];
            (BigInteger X, BigInteger Y)? running = null;
            for (int m = 1; m <= Entries; m++)
            {
                running = Add(running, basePoint);
                Require(running is not null, $"window {i}, entry {m}: infinity");
                table[i][m - 1] = running!.Value;
            }

            for (int d = 0; d < W; d++)
            {
                basePoint = Add(basePoint, basePoint) ?? throw new ProofException($"window {i}: the base doubled to infinity");
            }
        }

        // Every entry again from G by double-and-add (Jacobian, one inversion each), on the curve.
        // The entries are independent: checked in parallel (2,784 multiplications of 521 bits).
        var failures = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, Windows, i =>
        {
            for (int m = 1; m <= Entries; m++)
            {
                BigInteger k = Mod(m * (BigInteger.One << (W * i)), N);
                var expected = MultiplyJacobian(k, G);
                if (expected is null || expected.Value != table[i][m - 1])
                {
                    failures.Add($"window {i}, entry {m}: not {m} 2^{W * i} G");
                }
                else if (!OnCurve(table[i][m - 1]))
                {
                    failures.Add($"window {i}, entry {m}: not on the curve");
                }
            }
        });
        Require(failures.IsEmpty, failures.FirstOrDefault() ?? "");
        Table = table;
    }

    /// <summary>Throws a proof failure unless the condition holds.</summary>
    /// <param name="condition">The checked fact.</param>
    /// <param name="message">What failed when it does not.</param>
    /// <exception cref="ProofException">The condition is false.</exception>
    public static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new ProofException(message);
        }
    }
}

/// <summary>Writes p521_table.inc from the proven constants and table.</summary>
static class Emitter
{
    /// <summary>Nine little-endian qwords of a value below 2^576, as dq operands.</summary>
    /// <param name="x">The value.</param>
    /// <returns>"0x..., 0x..., ..." (nine).</returns>
    /// <exception cref="ProofException">The value is negative or does not fit nine qwords.</exception>
    static string Qwords(BigInteger x)
    {
        Curve.Require(x.Sign >= 0 && x < Curve.R, "a constant does not fit nine qwords");
        var parts = new string[9];
        for (int i = 0; i < 9; i++)
        {
            parts[i] = "0x" + ((ulong)((x >> (64 * i)) & ulong.MaxValue)).ToString("X16", CultureInfo.InvariantCulture);
        }

        return string.Join(", ", parts);
    }

    /// <summary>
    /// An inversion record: the modulus in nine signed 62-bit limbs (eight of 62 bits, the ninth
    /// the rest: 521 - 496 = 25 bits) and m^-1 mod 2^62, checked to rebuild m and to invert it.
    /// </summary>
    /// <param name="m">An odd modulus below 2^521.</param>
    /// <returns>Ten dq operands.</returns>
    /// <exception cref="ProofException">The limbs do not rebuild m, or the inverse is wrong.</exception>
    static string Record(BigInteger m)
    {
        BigInteger mask = (BigInteger.One << 62) - 1;
        var limbs = new BigInteger[9];
        for (int i = 0; i < 8; i++)
        {
            limbs[i] = (m >> (62 * i)) & mask;
        }

        limbs[8] = m >> 496;
        BigInteger rebuilt = 0;
        for (int i = 8; i >= 0; i--)
        {
            rebuilt = (rebuilt << 62) + limbs[i];
        }

        Curve.Require(rebuilt == m && limbs[8] < BigInteger.One << 62, "a record's limbs do not rebuild its modulus");
        BigInteger inverse = BigInteger.ModPow(m, (BigInteger.One << 61) - 1, BigInteger.One << 62);
        Curve.Require(((m * inverse) & mask).IsOne, "a record's inverse modulo 2^62 is wrong");
        return string.Join(", ", limbs.Append(inverse).Select(l => "0x" + ((ulong)l).ToString("X16", CultureInfo.InvariantCulture)));
    }

    /// <summary>The whole generated file.</summary>
    /// <returns>Its text, LF line ends.</returns>
    /// <exception cref="ProofException">A constant fails its check.</exception>
    public static string Write()
    {
        BigInteger p = Curve.P, n = Curve.N, r = Curve.R;
        BigInteger n0 = Curve.Mod(-BigInteger.ModPow(n, (BigInteger.One << 63) - 1, BigInteger.One << 64), BigInteger.One << 64);
        Curve.Require(((n * n0 + 1) & ulong.MaxValue).IsZero, "n0 is not -n^-1 mod 2^64");
        BigInteger nr2 = r * r % n;
        Curve.Require(nr2 * Curve.Inverse(r, n) % n == r % n, "R^2 mod n");
        Curve.Require(p - n > 0 && p - n < BigInteger.One << 261, "p - n is not a positive number below 2^261");

        var s = new StringBuilder();
        s.Append("""
            ; =============================================================================
            ; p521_table.inc - GENERATED by specs/p521.cs (dotnet run specs/p521.cs): do not edit.
            ; The constants and the fixed-base table of crypto/p521.asm, each proven by the generator
            ; first (its header says how). Values are nine little-endian qwords unless said, plain:
            ; P-521's field has no Montgomery form (include/crypto/p521.inc reduces by p's form).
            ; =============================================================================

            align 64
            """);
        s.Append('\n');
        s.Append($"p521_p:     dq {Qwords(p)}   ; p = 2^521 - 1\n");
        s.Append($"p521_one:   dq {Qwords(BigInteger.One)}   ; the integer 1: an affine point's Z\n");
        s.Append($"p521_b:     dq {Qwords(Curve.B)}   ; the curve's b\n");
        s.Append($"p521_n:     dq {Qwords(n)}   ; the group order n\n");
        s.Append($"p521_n_r2:  dq {Qwords(nr2)}   ; R^2 mod n (R = 2^576): a Montgomery product by it gives the plain product\n");
        s.Append($"p521_n_p:   dq {Qwords(p - n)}   ; p - n: r + n < p when r < p - n\n");
        s.Append($"p521_n0:    dq 0x{(ulong)n0:X16}   ; -n^-1 mod 2^64\n");
        s.Append("align 16\n");
        s.Append($"p521_mod_p: dq {Record(p)}   ; p: nine signed 62-bit limbs, p^-1 mod 2^62\n");
        s.Append($"p521_mod_n: dq {Record(n)}   ; n: the same\n");
        s.Append('\n');
        s.Append($"%define P521_W {Curve.W}                  ; the fixed base's window: bits per Booth digit\n");
        s.Append($"%define P521_WINDOWS {Curve.Windows}           ; windows: ceil(522 / P521_W)\n");
        s.Append($"%define P521_ENTRIES {Curve.Entries}           ; points a window: 2^(P521_W - 1)\n");
        s.Append('\n');
        s.Append($"; {Curve.Windows} windows of {Curve.Entries} points: window i holds m 2^({Curve.W}i) G for m = 1..{Curve.Entries}, affine (x, then\n");
        s.Append("; y), 144 octets a point: a digit's point is at p521_base_table + 144 (32 i + m - 1).\n");
        s.Append("align 64\n");
        s.Append("p521_base_table:\n");
        for (int i = 0; i < Curve.Windows; i++)
        {
            for (int m = 1; m <= Curve.Entries; m++)
            {
                var (x, y) = Curve.Table[i][m - 1];
                s.Append($"    dq {Qwords(x)}   ; {i}.{m} x\n");
                s.Append($"    dq {Qwords(y)}   ; {i}.{m} y\n");
            }
        }

        return s.ToString();
    }
}
