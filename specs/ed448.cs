// =============================================================================
// ed448.cs - the constants and the fixed-base table of crypto/ed448.asm (Ed448, RFC 8032 5.2,
// over edwards448: x^2 + y^2 = 1 + d x^2 y^2 modulo p = 2^448 - 2^224 - 1, d = -39081), each
// proven before anything is written. specs/ed25519.cs's way: every value checked against its
// definition in BigInteger arithmetic independent of the assembly, the table built one way and
// every entry checked by another.
//
// Writes src/HttpAsm.Core/include/generated/ed448_table.inc:
//   ed448_l, ed448_l0                    L, the group's prime order, and -L^-1 mod 2^64 (the
//                                        scalars' Montgomery products over seven limbs)
//   ed448_r2, ed448_r3, ed448_r4         R^2, R^3, R^4 modulo L (R = 2^448): into the form, and a
//                                        912-bit hash's upper parts R^2 and R^3 times
//   ED448_W, ED448_WINDOWS, ED448_ENTRIES  the fixed-base windows: 5 bits, 90 of them (450 bits:
//                                        a scalar below 2^448 and the recoding's carry), 16 points
//   ed448_base_table                     90 windows of 16 points: window i holds m 32^i B for
//                                        m = 1..16 as (x, y, d x y), each coordinate eight 56-bit
//                                        limbs in qwords (x448.asm's field), fully reduced:
//                                        276,480 octets, read by both field versions as they are
// The table covers every scalar below 2^448, not only those below L: X448's public key takes its
// clamped 448-bit scalar through it unreduced (see below).
//
// The proofs:
//   - the curve: p and L pass Miller-Rabin to 32 prime bases; d = -39081 is not a square modulo p
//     (so the unified formulas are complete); B (RFC 8032 5.2's) is on the curve; L B is the
//     neutral point (0, 1) and (L - 1) B is -B;
//   - X448's base point: RFC 7748 4.2's 4-isogeny takes B to u = y^2 / x^2 = 5, curve448's base
//     point, so X448(k, 5) is (y / x)^2 of k B: X448's public key may come from this table;
//   - each scalar constant against its definition (L L0 = -1 modulo 2^64, R^k modulo L);
//   - the table twice: built by repeated affine addition (window i's entries are B_i, B_i + B_i,
//     ..., where B_i is B doubled 5i times), and every entry checked against its multiple computed
//     by double-and-add from B alone in extended coordinates with the textbook formulas for a = 1
//     (Hisil, Wong, Carter and Dawson's dbl-2008-hwcd and add-2008-hwcd: another route and other
//     arrangements than both the table's and the assembly's); every entry on the curve, none the
//     neutral point.
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/ed448.cs            write the file
//   dotnet run specs/ed448.cs -- --check fail when the committed file differs (CI)
// Exit status: 0 success; 1 a proof or a check failed; 2 wrong usage.
// =============================================================================
using System.Globalization;
using System.Numerics;
using System.Text;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/ed448.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
string target = Path.Combine(root, "src", "HttpAsm.Core", "include", "generated", "ed448_table.inc");
if (!Directory.Exists(Path.GetDirectoryName(target)))
{
    Console.Error.WriteLine("ed448: run this from the repository root (src/HttpAsm.Core/include/generated was not found)");
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
            Console.Error.WriteLine($"ed448: {Path.GetRelativePath(root, target)} differs from what specs/ed448.cs writes: run it and commit the result");
            return 1;
        }

        Console.WriteLine($"ed448: ed448_table.inc is current ({Curve.Windows} windows of {Curve.Entries} points, proven)");
        return 0;
    }

    File.WriteAllText(target, text);
    Console.WriteLine($"ed448: wrote {Path.GetRelativePath(root, target)}: {Curve.Windows} windows of {Curve.Entries} points, proven");
    return 0;
}
catch (ProofException e)
{
    Console.Error.WriteLine("ed448: " + e.Message);
    return 1;
}

/// <summary>A failed proof: a constant or a table entry is not what its definition gives.</summary>
/// <param name="message">What failed, for the console.</param>
sealed class ProofException(string message) : Exception(message);

/// <summary>
/// edwards448 (RFC 8032 5.2: x^2 + y^2 = 1 + d x^2 y^2 over GF(2^448 - 2^224 - 1), d = -39081),
/// its affine arithmetic (the unified addition has no exceptional case on this curve: d is not a
/// square), and the proofs of everything the generated file holds.
/// </summary>
static class Curve
{
    /// <summary>The field's prime, 2^448 - 2^224 - 1.</summary>
    public static readonly BigInteger P = (BigInteger.One << 448) - (BigInteger.One << 224) - 1;

    /// <summary>The prime order of B: 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.</summary>
    public static readonly BigInteger L = (BigInteger.One << 446) - BigInteger.Parse("13818066809895115352007386748515426880336692474882178609894547503885", CultureInfo.InvariantCulture);

    /// <summary>The curve's d = -39081 modulo p.</summary>
    public static readonly BigInteger D = P - 39081;

    /// <summary>The base point B (RFC 8032 5.2).</summary>
    public static readonly (BigInteger X, BigInteger Y) B = (
        BigInteger.Parse("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710", CultureInfo.InvariantCulture),
        BigInteger.Parse("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660", CultureInfo.InvariantCulture));

    /// <summary>R = 2^448, the scalars' Montgomery radix (seven 64-bit limbs).</summary>
    public static readonly BigInteger R = BigInteger.One << 448;

    /// <summary>The fixed-base window: bits per signed digit.</summary>
    public const int W = 5;

    /// <summary>Windows of 5 bits covering a scalar below 2^448 and the recoding's carry: 90 (450 bits).</summary>
    public const int Windows = 90;

    /// <summary>Points per window: the digits' magnitudes 1..2^(W - 1).</summary>
    public const int Entries = 1 << (W - 1);

    /// <summary>The table, built and proven by <see cref="Prove"/>: [window][m - 1], affine.</summary>
    public static (BigInteger X, BigInteger Y)[][] Table { get; private set; } = [];

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

    /// <summary>Whether a point satisfies x^2 + y^2 = 1 + d x^2 y^2 modulo p.</summary>
    /// <param name="q">The affine point.</param>
    /// <returns>True when it does.</returns>
    public static bool OnCurve((BigInteger X, BigInteger Y) q) =>
        Mod(q.X * q.X + q.Y * q.Y - 1 - D * q.X * q.X % P * q.Y * q.Y, P).IsZero;

    /// <summary>The affine sum by the unified formula (complete: d is not a square modulo p).</summary>
    /// <param name="a">A point.</param>
    /// <param name="b">A point.</param>
    /// <returns>a + b.</returns>
    public static (BigInteger X, BigInteger Y) Add((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
    {
        BigInteger t = D * a.X % P * b.X % P * a.Y % P * b.Y % P;
        BigInteger x = Mod((a.X * b.Y + a.Y * b.X) * Inverse(1 + t, P), P);
        BigInteger y = Mod((a.Y * b.Y - a.X * b.X) * Inverse(1 - t, P), P);
        return (x, y);
    }

    /// <summary>k q by double-and-add from the low bit with the affine formula.</summary>
    /// <param name="k">A nonnegative scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>k q ((0, 1) for k = 0).</returns>
    public static (BigInteger X, BigInteger Y) Multiply(BigInteger k, (BigInteger X, BigInteger Y) q)
    {
        (BigInteger X, BigInteger Y) result = (0, 1), addend = q;
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
    /// k q in extended coordinates (X : Y : Z : T, x = X / Z, y = Y / Z, x y = T / Z) by
    /// double-and-add from the top bit, with Hisil, Wong, Carter and Dawson's formulas for a = 1
    /// (dbl-2008-hwcd and add-2008-hwcd: H = B - A) and one inversion at the end: the per-entry
    /// check, written apart from both the table's affine route and the assembly's arrangements.
    /// </summary>
    /// <param name="k">A nonnegative scalar.</param>
    /// <param name="q">The point.</param>
    /// <returns>k q, affine.</returns>
    public static (BigInteger X, BigInteger Y) MultiplyExtended(BigInteger k, (BigInteger X, BigInteger Y) q)
    {
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) acc = (0, 1, 1, 0);
        (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) addend = (q.X, q.Y, 1, q.X * q.Y % P);
        for (int bit = (int)k.GetBitLength() - 1; bit >= 0; bit--)
        {
            acc = Double(acc);
            if (!(k >> bit).IsEven)
            {
                acc = Sum(acc, addend);
            }
        }

        BigInteger zi = Inverse(acc.Z, P);
        return (Mod(acc.X * zi, P), Mod(acc.Y * zi, P));

        static (BigInteger, BigInteger, BigInteger, BigInteger) Double((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) a)
        {
            BigInteger aa = a.X * a.X % P, bb = a.Y * a.Y % P, cc = 2 * a.Z * a.Z % P;
            BigInteger e = Mod((a.X + a.Y) * (a.X + a.Y) - aa - bb, P);
            BigInteger g = Mod(aa + bb, P), f = Mod(g - cc, P), h = Mod(aa - bb, P);
            return (e * f % P, g * h % P, f * g % P, e * h % P);
        }

        static (BigInteger, BigInteger, BigInteger, BigInteger) Sum((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) a, (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) b)
        {
            BigInteger aa = a.X * b.X % P, bb = a.Y * b.Y % P;
            BigInteger cc = D * a.T % P * b.T % P, dd = a.Z * b.Z % P;
            BigInteger e = Mod((a.X + a.Y) * (b.X + b.Y) - aa - bb, P);
            BigInteger f = Mod(dd - cc, P), g = Mod(dd + cc, P), h = Mod(bb - aa, P);
            return (e * f % P, g * h % P, f * g % P, e * h % P);
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
    /// Proves the curve and every constant, then builds the table by repeated affine addition and
    /// checks each entry against double-and-add from B in extended coordinates; keeps the table.
    /// </summary>
    /// <exception cref="ProofException">Any check fails.</exception>
    public static void Prove()
    {
        Require(ProbablyPrime(P), "p is not prime");
        Require(ProbablyPrime(L), "L is not prime");
        Require(BigInteger.ModPow(D, (P - 1) / 2, P) == P - 1, "d is a square: the addition would not be complete");
        Require(OnCurve(B), "B is not on the curve");
        Require(Multiply(L, B) == (0, 1), "L B is not the neutral point");
        Require(Multiply(L - 1, B) == (P - B.X, B.Y), "(L - 1) B is not -B");
        Require(Mod(B.Y * B.Y * Inverse(B.X * B.X, P), P) == 5, "B's 4-isogeny image is not u = 5 (X448's base point)");

        var table = new (BigInteger X, BigInteger Y)[Windows][];
        (BigInteger X, BigInteger Y) basePoint = B;
        for (int i = 0; i < Windows; i++)
        {
            table[i] = new (BigInteger, BigInteger)[Entries];
            (BigInteger X, BigInteger Y) running = (0, 1);
            for (int m = 1; m <= Entries; m++)
            {
                running = Add(running, basePoint);
                Require(running != (0, 1), $"window {i}, entry {m}: the neutral point");
                table[i][m - 1] = running;
            }

            for (int d = 0; d < W; d++)
            {
                basePoint = Add(basePoint, basePoint);
            }
        }

        var failures = new System.Collections.Concurrent.ConcurrentBag<string>();
        Parallel.For(0, Windows, i =>
        {
            for (int m = 1; m <= Entries; m++)
            {
                BigInteger k = Mod(m * (BigInteger.One << (W * i)), L);
                if (MultiplyExtended(k, B) != table[i][m - 1])
                {
                    failures.Add($"window {i}, entry {m}: not {m} 2^{W * i} B");
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

/// <summary>Writes ed448_table.inc from the proven constants and table.</summary>
static class Emitter
{
    /// <summary>Seven little-endian qwords of a value below 2^448 (a scalar), as dq operands.</summary>
    /// <param name="x">The value.</param>
    /// <returns>"0x..., ..." (seven).</returns>
    /// <exception cref="ProofException">The value is negative or does not fit seven qwords.</exception>
    static string Qwords(BigInteger x)
    {
        Curve.Require(x.Sign >= 0 && x < Curve.R, "a constant does not fit seven qwords");
        var parts = new string[7];
        for (int i = 0; i < 7; i++)
        {
            parts[i] = "0x" + ((ulong)((x >> (64 * i)) & ulong.MaxValue)).ToString("X16", CultureInfo.InvariantCulture);
        }

        return string.Join(", ", parts);
    }

    /// <summary>Eight 56-bit limbs of a field element below p, as dq operands (x448.asm's form).</summary>
    /// <param name="x">The value, fully reduced.</param>
    /// <returns>"0x..., ..." (eight).</returns>
    /// <exception cref="ProofException">The value is not below p.</exception>
    static string Limbs(BigInteger x)
    {
        Curve.Require(x.Sign >= 0 && x < Curve.P, "a coordinate is not fully reduced");
        var parts = new string[8];
        for (int i = 0; i < 8; i++)
        {
            parts[i] = "0x" + ((ulong)((x >> (56 * i)) & ((BigInteger.One << 56) - 1))).ToString("X14", CultureInfo.InvariantCulture);
        }

        return string.Join(", ", parts);
    }

    /// <summary>The whole generated file.</summary>
    /// <returns>Its text, LF line ends.</returns>
    /// <exception cref="ProofException">A constant fails its check.</exception>
    public static string Write()
    {
        BigInteger p = Curve.P, l = Curve.L, r = Curve.R;
        BigInteger l0 = Curve.Mod(-BigInteger.ModPow(l, (BigInteger.One << 63) - 1, BigInteger.One << 64), BigInteger.One << 64);
        Curve.Require(((l * l0 + 1) & ulong.MaxValue).IsZero, "L0 is not -L^-1 mod 2^64");
        BigInteger r2 = r * r % l, r3 = r2 * r % l, r4 = r3 * r % l;
        Curve.Require(r2 * Curve.Inverse(r, l) % l == r % l && r3 * Curve.Inverse(r * r, l) % l == r % l
            && r4 * Curve.Inverse(r * r * r, l) % l == r % l, "R^2, R^3 or R^4 mod L");

        var s = new StringBuilder();
        s.Append("""
            ; =============================================================================
            ; ed448_table.inc - GENERATED by specs/ed448.cs (dotnet run specs/ed448.cs): do not edit.
            ; The constants and the fixed-base table of crypto/ed448.asm, each proven by the generator
            ; first (its header says how). Scalars are seven little-endian qwords; field elements
            ; eight 56-bit limbs in qwords (crypto/x448.asm's field), fully reduced.
            ; =============================================================================

            align 64
            """);
        s.Append('\n');
        s.Append($"ed448_l:   dq {Qwords(l)}, 0   ; L, the prime order of B\n");
        s.Append($"ed448_r2:  dq {Qwords(r2)}, 0   ; R^2 mod L (R = 2^448)\n");
        s.Append($"ed448_r3:  dq {Qwords(r3)}, 0   ; R^3 mod L\n");
        s.Append($"ed448_r4:  dq {Qwords(r4)}, 0   ; R^4 mod L\n");
        s.Append($"ed448_l0:  dq 0x{(ulong)l0:X16}   ; -L^-1 mod 2^64\n");
        s.Append('\n');
        s.Append($"%define ED448_W {Curve.W}                  ; the fixed base's window: bits per signed digit\n");
        s.Append($"%define ED448_WINDOWS {Curve.Windows}           ; windows: 450 bits (a scalar below 2^448 and the carry)\n");
        s.Append($"%define ED448_ENTRIES {Curve.Entries}           ; points a window: the digits' magnitudes 1..16\n");
        s.Append('\n');
        s.Append($"; {Curve.Windows} windows of {Curve.Entries} points: window i holds m 32^i B for m = 1..{Curve.Entries} as (x, y, d x y),\n");
        s.Append("; 192 octets a point: a digit's point is at ed448_base_table + 192 (16 i + m - 1).\n");
        s.Append("align 64\n");
        s.Append("ed448_base_table:\n");
        for (int i = 0; i < Curve.Windows; i++)
        {
            for (int m = 1; m <= Curve.Entries; m++)
            {
                var (x, y) = Curve.Table[i][m - 1];
                s.Append($"    dq {Limbs(x)}   ; {i}.{m} x\n");
                s.Append($"    dq {Limbs(y)}   ; {i}.{m} y\n");
                s.Append($"    dq {Limbs(Curve.Mod(Curve.D * x % p * y, p))}   ; {i}.{m} d x y\n");
            }
        }

        return s.ToString();
    }
}
