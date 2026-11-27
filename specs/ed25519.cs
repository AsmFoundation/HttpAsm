// =============================================================================
// ed25519.cs - the constants and the fixed-base table of crypto/ed25519.asm (Ed25519, RFC 8032,
// over edwards25519: -x^2 + y^2 = 1 + d x^2 y^2 modulo p = 2^255 - 19), each proven before
// anything is written. specs/p256.cs's way: every value checked against its definition in
// BigInteger arithmetic independent of the assembly, the table built one way and every entry
// checked by another.
//
// Writes src/HttpAsm.Core/include/generated/ed25519_table.inc:
//   ed25519_d, ed25519_2d                d and 2d modulo p (the curve's constant; the additions take
//                                        2d)
//   ed25519_sqrtm1                       sqrt(-1) = 2^((p - 1) / 4) modulo p (decompression's fix-up)
//   ed25519_one                          1 (a projective point's Z)
//   ed25519_l, ed25519_l0                L, the group's prime order, and -L^-1 mod 2^64 (the
//                                        scalars' Montgomery products)
//   ed25519_l_r2, ed25519_l_r3           R^2 and R^3 modulo L (R = 2^256): into the form, and a
//                                        512-bit hash's high half R^2 times
//   ED25519_W, ED25519_WINDOWS           the fixed-base windows: 6 bits, 43 of them
//   ed25519_base_table                   43 windows of 32 points: window i holds m 2^(6i) B for
//                                        m = 1..32 in the precomputed form the mixed addition
//                                        takes, (y + x, y - x, 2d x y), each coordinate 32 octets
//                                        little-endian, fully reduced (132,096 octets): both field
//                                        versions read them (v1 converts to its 51-bit limbs)
// All values are plain little-endian qwords (fe25519.inc's representations keep no Montgomery
// form), the four limbs of a value below 2^256.
//
// Read and checked, never written: include/crypto/fe25519.inc's FE25519_INVERSE_RECORD, the
// modulus record crypto/inverse.asm's ha_modinv256 takes for 2^255 - 19 (Ed25519's and X25519's
// inversions): p in five signed 62-bit limbs, then p^-1 mod 2^62. A hand-written line, so the
// generator proves it rather than owns it.
//
// The proofs:
//   - the curve: p and L pass Miller-Rabin to 32 prime bases; d = -121665/121666; B = (x, 4/5)
//     with x even (RFC 8032 5.1) satisfies the curve's equation; L B is the neutral point (0, 1)
//     and (L - 1) B is -B; sqrt(-1)^2 = -1;
//   - each scalar constant against its definition (L L0 = -1 modulo 2^64, R^2 and R^3 modulo L);
//   - the table twice: built by repeated affine addition (window i's entries are B_i, B_i + B_i,
//     ..., where B_i is B doubled 6i times), and every entry checked against its multiple
//     computed by double-and-add from B alone in extended coordinates with the textbook formulas
//     (Hisil, Wong, Carter and Dawson's: another route and other formulas than both the table's
//     and the assembly's); every entry on the curve, none the neutral point.
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/ed25519.cs            write the file
//   dotnet run specs/ed25519.cs -- --check fail when the committed file differs (CI)
// Exit status: 0 success; 1 a proof or a check failed; 2 wrong usage.
// =============================================================================
using System.Globalization;
using System.Numerics;
using System.Text;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/ed25519.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
string target = Path.Combine(root, "src", "HttpAsm.Core", "include", "generated", "ed25519_table.inc");
if (!Directory.Exists(Path.GetDirectoryName(target)))
{
    Console.Error.WriteLine("ed25519: run this from the repository root (src/HttpAsm.Core/include/generated was not found)");
    return 2;
}

try
{
    Curve.Prove();
    Curve.ProveInverseRecord(Path.Combine(root, "src", "HttpAsm.Core", "include", "crypto", "fe25519.inc"));
    string text = Emitter.Write();
    if (check)
    {
        string committed = File.Exists(target) ? File.ReadAllText(target).ReplaceLineEndings("\n") : "";
        if (committed != text)
        {
            Console.Error.WriteLine($"ed25519: {Path.GetRelativePath(root, target)} differs from what specs/ed25519.cs writes: run it and commit the result");
            return 1;
        }

        Console.WriteLine($"ed25519: ed25519_table.inc is current ({Curve.Windows} windows of {Curve.Entries} points, proven)");
        return 0;
    }

    File.WriteAllText(target, text);
    Console.WriteLine($"ed25519: wrote {Path.GetRelativePath(root, target)}: {Curve.Windows} windows of {Curve.Entries} points, proven");
    return 0;
}
catch (ProofException e)
{
    Console.Error.WriteLine("ed25519: " + e.Message);
    return 1;
}

/// <summary>A failed proof: a constant or a table entry is not what its definition gives.</summary>
/// <param name="message">What failed, for the console.</param>
sealed class ProofException(string message) : Exception(message);

/// <summary>
/// edwards25519 (RFC 8032 5.1: -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19)), its affine
/// arithmetic (the unified addition has no exceptional case on this curve: d is not a square),
/// and the proofs of everything the generated file holds.
/// </summary>
static class Curve
{
    /// <summary>The field's prime, 2^255 - 19.</summary>
    public static readonly BigInteger P = (BigInteger.One << 255) - 19;

    /// <summary>The prime order of B: 2^252 + 27742317777372353535851937790883648493.</summary>
    public static readonly BigInteger L = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);

    /// <summary>The curve's d = -121665 / 121666 modulo p.</summary>
    public static readonly BigInteger D = Mod(-121665 * Inverse(121666, P), P);

    /// <summary>The base point B: y = 4/5, x the even root (RFC 8032 5.1).</summary>
    public static readonly (BigInteger X, BigInteger Y) B = BasePoint();

    /// <summary>R = 2^256, the scalars' Montgomery radix (four 64-bit limbs).</summary>
    public static readonly BigInteger R = BigInteger.One << 256;

    /// <summary>The fixed-base window: bits per signed digit.</summary>
    public const int W = 6;

    /// <summary>Windows of 6 bits covering a scalar below L (253 bits) and the recoding's carry: ceil(254 / 6).</summary>
    public const int Windows = (253 + W) / W;

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

    /// <summary>sqrt(-1) modulo p: 2^((p - 1) / 4).</summary>
    /// <returns>The root RFC 8032 5.1.3 multiplies by.</returns>
    public static BigInteger SqrtM1() => BigInteger.ModPow(2, (P - 1) / 4, P);

    /// <summary>
    /// B from y = 4/5 by RFC 8032 5.1.3's recovery: x^2 = (y^2 - 1) / (d y^2 + 1), the candidate
    /// x = u v^3 (u v^7)^((p - 5) / 8), times sqrt(-1) when its square is -x^2, then the even root.
    /// </summary>
    /// <returns>B.</returns>
    /// <exception cref="ProofException">No root: y = 4/5 would not be on the curve.</exception>
    static (BigInteger X, BigInteger Y) BasePoint()
    {
        BigInteger y = Mod(4 * Inverse(5, P), P);
        BigInteger u = Mod(y * y - 1, P), v = Mod(D * y * y + 1, P);
        BigInteger x = Mod(u * BigInteger.ModPow(v, 3, P) * BigInteger.ModPow(u * BigInteger.ModPow(v, 7, P) % P, (P - 5) / 8, P), P);
        if (Mod(v * x * x - u, P) != 0)
        {
            x = Mod(x * SqrtM1(), P);
        }

        if (Mod(v * x * x - u, P) != 0)
        {
            throw new ProofException("4/5 is no y of the curve");
        }

        return (x.IsEven ? x : P - x, y);
    }

    /// <summary>Whether a point satisfies -x^2 + y^2 = 1 + d x^2 y^2 modulo p.</summary>
    /// <param name="q">The affine point.</param>
    /// <returns>True when it does.</returns>
    public static bool OnCurve((BigInteger X, BigInteger Y) q) =>
        Mod(-q.X * q.X + q.Y * q.Y - 1 - D * q.X * q.X % P * q.Y * q.Y, P).IsZero;

    /// <summary>The affine sum by the unified formula (complete: d is not a square modulo p).</summary>
    /// <param name="a">A point.</param>
    /// <param name="b">A point.</param>
    /// <returns>a + b.</returns>
    public static (BigInteger X, BigInteger Y) Add((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
    {
        BigInteger t = D * a.X % P * b.X % P * a.Y % P * b.Y % P;
        BigInteger x = Mod((a.X * b.Y + a.Y * b.X) * Inverse(1 + t, P), P);
        BigInteger y = Mod((a.Y * b.Y + a.X * b.X) * Inverse(1 - t, P), P);
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
    /// double-and-add from the top bit, with Hisil, Wong, Carter and Dawson's formulas for a = -1
    /// (dbl-2008-hwcd and add-2008-hwcd-3) and one inversion at the end: the per-entry check,
    /// written apart from both the table's affine route and the assembly's arrangements.
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
            BigInteger dd = Mod(-aa, P);
            BigInteger e = Mod((a.X + a.Y) * (a.X + a.Y) - aa - bb, P);
            BigInteger g = Mod(dd + bb, P), f = Mod(g - cc, P), h = Mod(dd - bb, P);
            return (e * f % P, g * h % P, f * g % P, e * h % P);
        }

        static (BigInteger, BigInteger, BigInteger, BigInteger) Sum((BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) a, (BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) b)
        {
            BigInteger aa = Mod((a.Y - a.X) * (b.Y - b.X), P), bb = Mod((a.Y + a.X) * (b.Y + b.X), P);
            BigInteger cc = 2 * D * a.T % P * b.T % P, dd = 2 * a.Z * b.Z % P;
            BigInteger e = Mod(bb - aa, P), f = Mod(dd - cc, P), g = Mod(dd + cc, P), h = Mod(bb + aa, P);
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
        Require(Mod(D * 121666 + 121665, P).IsZero, "d is not -121665/121666");
        Require(BigInteger.ModPow(D, (P - 1) / 2, P) == P - 1, "d is a square: the addition would not be complete");
        Require(Mod(SqrtM1() * SqrtM1() + 1, P).IsZero, "sqrt(-1)^2 is not -1");
        Require(OnCurve(B) && B.X.IsEven && B.Y == Mod(4 * Inverse(5, P), P), "B is not (even x, 4/5) on the curve");
        Require(Multiply(L, B) == (0, 1), "L B is not the neutral point");
        Require(Multiply(L - 1, B) == (P - B.X, B.Y), "(L - 1) B is not -B");

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

    /// <summary>
    /// Proves fe25519.inc's hand-written FE25519_INVERSE_RECORD line ("fe25519_mod_p: dq ..."):
    /// its first five values must be p's signed 62-bit limbs (each below 2^62, summing back to p)
    /// and the sixth p^-1 modulo 2^62. A wrong value would make ha_modinv256's divisions inexact
    /// and every Ed25519 and X25519 result wrong, which the tests would catch at once; this
    /// names the cause instead.
    /// </summary>
    /// <param name="path">include/crypto/fe25519.inc.</param>
    /// <exception cref="ProofException">The line is missing, has another count of values, or any
    /// value differs.</exception>
    public static void ProveInverseRecord(string path)
    {
        string? line = File.ReadLines(path).FirstOrDefault(l => l.StartsWith("fe25519_mod_p: dq ", StringComparison.Ordinal));
        Require(line is not null, "fe25519.inc has no fe25519_mod_p record");
        BigInteger[] values = line!["fe25519_mod_p: dq ".Length..].Split(',')
            .Select(v => BigInteger.Parse("0" + v.Trim()[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture))
            .ToArray();
        Require(values.Length == 6, $"fe25519_mod_p has {values.Length} values, not 6");
        BigInteger m62 = BigInteger.One << 62, rest = P;
        for (int i = 0; i < 5; i++)
        {
            BigInteger limb = i < 4 ? rest % m62 : rest;
            Require(values[i] == limb && limb < m62, $"fe25519_mod_p's limb {i} is not p's");
            rest /= m62;
        }

        Require(Mod(values[5] * P, m62).IsOne, "fe25519_mod_p's last value is not p^-1 mod 2^62");
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

/// <summary>Writes ed25519_table.inc from the proven constants and table.</summary>
static class Emitter
{
    /// <summary>Four little-endian qwords of a value below 2^256, as dq operands.</summary>
    /// <param name="x">The value.</param>
    /// <returns>"0x..., 0x..., 0x..., 0x...".</returns>
    /// <exception cref="ProofException">The value is negative or does not fit four qwords.</exception>
    static string Qwords(BigInteger x)
    {
        Curve.Require(x.Sign >= 0 && x < Curve.R, "a constant does not fit four qwords");
        var parts = new string[4];
        for (int i = 0; i < 4; i++)
        {
            parts[i] = "0x" + ((ulong)((x >> (64 * i)) & ulong.MaxValue)).ToString("X16", CultureInfo.InvariantCulture);
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
        BigInteger lr2 = r * r % l, lr3 = r * r * r % l;
        Curve.Require(lr2 * Curve.Inverse(r, l) % l == r % l && lr3 * Curve.Inverse(r * r, l) % l == r % l, "R^2 or R^3 mod L");
        BigInteger d = Curve.D, d2 = 2 * Curve.D % p;

        var s = new StringBuilder();
        s.Append("""
            ; =============================================================================
            ; ed25519_table.inc - GENERATED by specs/ed25519.cs (dotnet run specs/ed25519.cs): do not
            ; edit. The constants and the fixed-base table of crypto/ed25519.asm, each proven by the
            ; generator first (its header says how). Values are four little-endian qwords, plain (no
            ; Montgomery form), fully reduced.
            ; =============================================================================

            align 64
            """);
        s.Append('\n');
        s.Append($"ed25519_d:      dq {Qwords(d)}   ; d = -121665/121666 mod p\n");
        s.Append($"ed25519_2d:     dq {Qwords(d2)}   ; 2d mod p\n");
        s.Append($"ed25519_sqrtm1: dq {Qwords(Curve.SqrtM1())}   ; sqrt(-1) mod p\n");
        s.Append($"ed25519_one:    dq {Qwords(BigInteger.One)}   ; 1\n");
        s.Append($"ed25519_l:      dq {Qwords(l)}   ; L, the prime order of B\n");
        s.Append($"ed25519_l_r2:   dq {Qwords(lr2)}   ; R^2 mod L (R = 2^256)\n");
        s.Append($"ed25519_l_r3:   dq {Qwords(lr3)}   ; R^3 mod L\n");
        s.Append($"ed25519_l0:     dq 0x{(ulong)l0:X16}   ; -L^-1 mod 2^64\n");
        s.Append('\n');
        s.Append($"%define ED25519_W {Curve.W}                ; the fixed base's window: bits per signed digit\n");
        s.Append($"%define ED25519_WINDOWS {Curve.Windows}         ; windows: ceil(254 / ED25519_W)\n");
        s.Append('\n');
        s.Append($"; {Curve.Windows} windows of {Curve.Entries} points: window i holds m 2^({Curve.W}i) B for m = 1..{Curve.Entries} as (y + x, y - x,\n");
        s.Append("; 2d x y), 96 octets a point: a digit's point is at ed25519_base_table + 96 (32 i + m - 1).\n");
        s.Append("align 64\n");
        s.Append("ed25519_base_table:\n");
        for (int i = 0; i < Curve.Windows; i++)
        {
            for (int m = 1; m <= Curve.Entries; m++)
            {
                var (x, y) = Curve.Table[i][m - 1];
                s.Append($"    dq {Qwords((y + x) % p)}   ; {i}.{m} y + x\n");
                s.Append($"    dq {Qwords(Curve.Mod(y - x, p))}   ; {i}.{m} y - x\n");
                s.Append($"    dq {Qwords(d2 * x % p * y % p)}   ; {i}.{m} 2d x y\n");
            }
        }

        return s.ToString();
    }
}
