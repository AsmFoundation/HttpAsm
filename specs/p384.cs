// =============================================================================
// p384.cs - the constants and the fixed-base table of crypto/p384.asm (NIST P-384, the curve TLS
// calls secp384r1), each proven before anything is written. specs/p256.cs's twin: the same
// proofs, six limbs instead of four.
//
// Writes src/HttpAsm.Core/include/generated/p384_table.inc:
//   p384_p, p384_p0                      p (plain) and -p^-1 mod 2^64 (2^32 + 1): the field's
//                                        modulus as the generic six-limb products take it
//   p384_one, p384_r2, p384_r3, p384_b   R, R^2, R^3 and b R modulo p (R = 2^384): the field's
//                                        Montgomery form (1 in it, the way in, a plain inverse's way
//                                        back, the curve's b in it)
//   p384_int1                            the integer 1: a Montgomery product by it leaves the form
//   p384_n, p384_n_r2, p384_n0, p384_n_p n, R^2 mod n, -n^-1 mod 2^64, and p - n: ECDSA's scalars
//   p384_mod_p, p384_mod_n               the inversion's records: the modulus in seven signed 62-bit
//                                        limbs, then its inverse modulo 2^62
//   P384_W, P384_WINDOWS                 the fixed-base windows: 7 bits, 55 of them
//   p384_base_table                      55 windows of 64 points: window i holds m 2^(7i) G for
//                                        m = 1..64, affine, x then y in Montgomery form, six
//                                        little-endian qwords each (337,920 octets)
//
// The proofs, all in BigInteger arithmetic independent of the assembly:
//   - the curve: p and n pass Miller-Rabin to 32 prime bases; G satisfies y^2 = x^3 - 3x + b;
//     n G is the point at infinity (so G's order is n, a prime: every point but infinity has it);
//   - each constant against its definition (R R^-1 = 1 modulo p and n, n n0 = -1 modulo 2^64,
//     the records' limbs rebuild the modulus and their inverses multiply it to 1 modulo 2^62);
//   - the table twice: built by repeated affine addition (window i's entries are B_i, B_i + B_i,
//     ..., where B_i is G doubled 7i times), and every entry checked against its scalar multiple
//     computed by double-and-add from G alone (m 2^(7i) reduced modulo n, in Jacobian
//     coordinates with the textbook formulas: another route and other formulas than both the
//     table's and the assembly's); every entry on the curve, none at infinity.
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/p384.cs            write the file
//   dotnet run specs/p384.cs -- --check fail when the committed file differs (CI)
// Exit status: 0 success; 1 a proof or a check failed; 2 wrong usage.
// =============================================================================
using System.Globalization;
using System.Numerics;
using System.Text;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/p384.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
string target = Path.Combine(root, "src", "HttpAsm.Core", "include", "generated", "p384_table.inc");
if (!Directory.Exists(Path.GetDirectoryName(target)))
{
    Console.Error.WriteLine("p384: run this from the repository root (src/HttpAsm.Core/include/generated was not found)");
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
            Console.Error.WriteLine($"p384: {Path.GetRelativePath(root, target)} differs from what specs/p384.cs writes: run it and commit the result");
            return 1;
        }

        Console.WriteLine($"p384: p384_table.inc is current ({Curve.Windows} windows of {Curve.Entries} points, proven)");
        return 0;
    }

    File.WriteAllText(target, text);
    Console.WriteLine($"p384: wrote {Path.GetRelativePath(root, target)}: {Curve.Windows} windows of {Curve.Entries} points, proven");
    return 0;
}
catch (ProofException e)
{
    Console.Error.WriteLine("p384: " + e.Message);
    return 1;
}

/// <summary>A failed proof: a constant or a table entry is not what its definition gives.</summary>
/// <param name="message">What failed, for the console.</param>
sealed class ProofException(string message) : Exception(message);

/// <summary>
/// The curve (SP 800-186 3.2.1.4: y^2 = x^3 - 3x + b over GF(p)), its affine arithmetic with an
/// explicit point at infinity (null), and the proofs of everything the generated file holds.
/// </summary>
static class Curve
{
    /// <summary>The field's prime, 2^384 - 2^128 - 2^96 + 2^32 - 1.</summary>
    public static readonly BigInteger P = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");

    /// <summary>The order of G (the group's order: the cofactor is 1).</summary>
    public static readonly BigInteger N = Hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");

    /// <summary>The curve's b (a is -3).</summary>
    public static readonly BigInteger B = Hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");

    /// <summary>The base point G.</summary>
    public static readonly (BigInteger X, BigInteger Y) G = (
        Hex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
        Hex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));

    /// <summary>R = 2^384, the Montgomery radix of both moduli (six 64-bit limbs).</summary>
    public static readonly BigInteger R = BigInteger.One << 384;

    /// <summary>The fixed-base window: bits per Booth digit.</summary>
    public const int W = 7;

    /// <summary>Windows of 7 bits covering 384 bits and the Booth carry: ceil(385 / 7).</summary>
    public const int Windows = (384 + W) / W;

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

    /// <summary>k q by double-and-add from the low bit (an independent route to every entry).</summary>
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
    /// enough for all 3,520 entries.
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
        Require(P == (BigInteger.One << 384) - (BigInteger.One << 128) - (BigInteger.One << 96) + (BigInteger.One << 32) - 1, "p is not 2^384 - 2^128 - 2^96 + 2^32 - 1");
        Require(ProbablyPrime(P), "p is not prime");
        Require(ProbablyPrime(N), "n is not prime");
        Require(OnCurve(G), "G is not on the curve");
        Require(Multiply(N, G) is null, "n G is not the point at infinity");
        Require(Multiply(N - 1, G) is { } last && last.X == G.X && Mod(last.Y + G.Y, P).IsZero, "(n - 1) G is not -G");

        // The table: window i holds B_i, 2 B_i, ..., 64 B_i with B_i = 2^(7i) G.
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
        // The entries are independent: checked in parallel (3,520 multiplications of 384 bits).
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

/// <summary>Writes p384_table.inc from the proven constants and table.</summary>
static class Emitter
{
    /// <summary>Six little-endian qwords of a value below 2^384, as dq operands.</summary>
    /// <param name="x">The value.</param>
    /// <returns>"0x..., 0x..., ..." (six).</returns>
    /// <exception cref="ProofException">The value is negative or does not fit six qwords.</exception>
    static string Qwords(BigInteger x)
    {
        Curve.Require(x.Sign >= 0 && x < Curve.R, "a constant does not fit six qwords");
        var parts = new string[6];
        for (int i = 0; i < 6; i++)
        {
            parts[i] = "0x" + ((ulong)((x >> (64 * i)) & ulong.MaxValue)).ToString("X16", CultureInfo.InvariantCulture);
        }

        return string.Join(", ", parts);
    }

    /// <summary>
    /// An inversion record: the modulus in seven signed 62-bit limbs (six of 62 bits, the seventh
    /// the rest: 384 - 372 = 12 bits) and m^-1 mod 2^62, checked to rebuild m and to invert it.
    /// </summary>
    /// <param name="m">An odd modulus below 2^384.</param>
    /// <returns>Eight dq operands.</returns>
    /// <exception cref="ProofException">The limbs do not rebuild m, or the inverse is wrong.</exception>
    static string Record(BigInteger m)
    {
        BigInteger mask = (BigInteger.One << 62) - 1;
        var limbs = new BigInteger[7];
        for (int i = 0; i < 6; i++)
        {
            limbs[i] = (m >> (62 * i)) & mask;
        }

        limbs[6] = m >> 372;
        BigInteger rebuilt = 0;
        for (int i = 6; i >= 0; i--)
        {
            rebuilt = (rebuilt << 62) + limbs[i];
        }

        Curve.Require(rebuilt == m, "a record's limbs do not rebuild its modulus");
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
        BigInteger p0 = Curve.Mod(-BigInteger.ModPow(p, (BigInteger.One << 63) - 1, BigInteger.One << 64), BigInteger.One << 64);
        Curve.Require(((p * p0 + 1) & ulong.MaxValue).IsZero && p0 == (BigInteger.One << 32) + 1, "p0 is not -p^-1 mod 2^64 = 2^32 + 1");
        BigInteger one = r % p, r2 = r * r % p, r3 = r * r * r % p, b = Curve.B * r % p, nr2 = r * r % n;
        Curve.Require((one * Curve.Inverse(r, p) % p).IsOne && (r2 * Curve.Inverse(r, p) % p) == one, "R or R^2 mod p");
        Curve.Require(r3 * Curve.Inverse(r * r, p) % p == one, "R^3 mod p");
        Curve.Require(nr2 * Curve.Inverse(r, n) % n == r % n, "R^2 mod n");

        var s = new StringBuilder();
        s.Append("""
            ; =============================================================================
            ; p384_table.inc - GENERATED by specs/p384.cs (dotnet run specs/p384.cs): do not edit.
            ; The constants and the fixed-base table of crypto/p384.asm, each proven by the generator
            ; first (its header says how). Values are six little-endian qwords unless said; field
            ; values are in Montgomery form (a R mod p, R = 2^384) unless said.
            ; =============================================================================

            align 64
            """);
        s.Append('\n');
        s.Append($"p384_p:     dq {Qwords(p)}   ; p (plain): the field's modulus for the generic products\n");
        s.Append($"p384_p0:    dq 0x{(ulong)p0:X16}   ; -p^-1 mod 2^64 = 2^32 + 1\n");
        s.Append($"p384_one:   dq {Qwords(one)}   ; R mod p: 1 in Montgomery form\n");
        s.Append($"p384_r2:    dq {Qwords(r2)}   ; R^2 mod p: a product by it enters the form\n");
        s.Append($"p384_r3:    dq {Qwords(r3)}   ; R^3 mod p: a plain inverse of a value in the form, back into it\n");
        s.Append($"p384_b:     dq {Qwords(b)}   ; b R mod p\n");
        s.Append($"p384_int1:  dq {Qwords(BigInteger.One)}   ; the integer 1: a product by it leaves the form\n");
        s.Append($"p384_n:     dq {Qwords(n)}   ; the group order n (plain)\n");
        s.Append($"p384_n_r2:  dq {Qwords(nr2)}   ; R^2 mod n\n");
        s.Append($"p384_n_p:   dq {Qwords(p - n)}   ; p - n (plain): r + n < p when r < p - n\n");
        s.Append($"p384_n0:    dq 0x{(ulong)n0:X16}   ; -n^-1 mod 2^64\n");
        s.Append("align 16\n");
        s.Append($"p384_mod_p: dq {Record(p)}   ; p: seven signed 62-bit limbs, p^-1 mod 2^62\n");
        s.Append($"p384_mod_n: dq {Record(n)}   ; n: the same\n");
        s.Append('\n');
        s.Append($"%define P384_W {Curve.W}                  ; the fixed base's window: bits per Booth digit\n");
        s.Append($"%define P384_WINDOWS {Curve.Windows}           ; windows: ceil(385 / P384_W)\n");
        s.Append('\n');
        s.Append($"; {Curve.Windows} windows of {Curve.Entries} points: window i holds m 2^({Curve.W}i) G for m = 1..{Curve.Entries}, affine (x, then\n");
        s.Append("; y), 96 octets a point: a digit's point is at p384_base_table + 96 (64 i + m - 1).\n");
        s.Append("align 64\n");
        s.Append("p384_base_table:\n");
        for (int i = 0; i < Curve.Windows; i++)
        {
            for (int m = 1; m <= Curve.Entries; m++)
            {
                var (x, y) = Curve.Table[i][m - 1];
                s.Append($"    dq {Qwords(x * r % p)}   ; {i}.{m} x\n");
                s.Append($"    dq {Qwords(y * r % p)}   ; {i}.{m} y\n");
            }
        }

        return s.ToString();
    }
}
