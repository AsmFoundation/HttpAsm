// =============================================================================
// circuits.cs - code generated from the crypto circuits of specs/circuits/, each proven before
// anything is written. Today one circuit: the AES S-box (specs/circuits/aes_sbox.txt), written
// as an SSE2 macro for the constant-time AES of crypto/aes.asm (its v1, which looks nothing up
// in a table: a table lookup indexed by key or data leaks through the cache).
//
// Writes src/HttpAsm.Core/include/generated/aes_sbox.inc:
//   HA_AES_SBOX_SSE2 spill   the S-box on bitsliced state in xmm0-xmm7, in place: xmm i holds
//                            bit i of every octet slot (any number of slots: 128 per register),
//                            and afterwards bit i of every slot's S-box value. It uses
//                            xmm8-xmm15, the 16-octet slots at [rsp + spill + 16 k] for k below
//                            HA_AES_SBOX_SPILLS (spill 16-byte aligned with rsp), and the
//                            16-octet all-ones constant ha_aes_ones (for xnor). No flags, no
//                            branch, no address depends on the state.
//   HA_AES_SBOX_SPILLS       how many spill slots the macro uses.
//
// The register allocation. The program is straight-line and every value is assigned once, so
// every value's next use is known in advance. Values stay in the 16 XMM registers; when a
// register is needed and none is free, the one whose value is used farthest ahead is taken
// (Belady's choice), its value first written to a spill slot unless a slot already holds it (a
// value never changes, so one write serves every later eviction). A gate's second operand is read
// from its slot by the instruction itself when it is not in a register; a gate whose first
// operand dies there computes into that operand's register (the gates are commutative, so the
// operands swap when only the second one dies). At the end, the eight outputs move to xmm0-xmm7.
//
// The proof, twice before writing: the circuit itself on all 256 inputs against the S-box
// computed from FIPS 197's definition (5.1.1: the multiplicative inverse in GF(2^8) modulo
// x^8 + x^4 + x^3 + x + 1, 0 to 0, then the affine map with 0x63), and then the generated
// instructions, run by a model of the registers and slots that holds all 256 inputs at once as
// bit planes, against the same S-box.
//
// Usage (a .NET 10 file-based app; run from the repository root):
//   dotnet run specs/circuits.cs            write the file
//   dotnet run specs/circuits.cs -- --check fail when the committed file differs (CI)
// Exit status: 0 success; 1 a proof or a check failed; 2 wrong usage.
// =============================================================================
using System.Text;
using System.Text.RegularExpressions;

bool check = args.Contains("--check");
if (args.Any(a => a != "--check"))
{
    Console.Error.WriteLine("usage: dotnet run specs/circuits.cs [-- --check]");
    return 2;
}

string root = Directory.GetCurrentDirectory();
string circuitPath = Path.Combine(root, "specs", "circuits", "aes_sbox.txt");
if (!File.Exists(circuitPath))
{
    Console.Error.WriteLine("circuits: run this from the repository root (specs/circuits/aes_sbox.txt was not found)");
    return 2;
}

try
{
    Circuit circuit = Circuit.Parse(File.ReadAllLines(circuitPath));
    byte[] sbox = Fips197.Sbox();
    circuit.Prove(sbox);
    Allocation allocation = Allocator.Allocate(circuit);
    Model.Prove(allocation, sbox);
    string text = Emitter.Write(circuit, allocation);
    string target = Path.Combine(root, "src", "HttpAsm.Core", "include", "generated", "aes_sbox.inc");
    if (check)
    {
        string committed = File.Exists(target) ? File.ReadAllText(target).ReplaceLineEndings("\n") : "";
        if (committed != text)
        {
            Console.Error.WriteLine($"circuits: {Path.GetRelativePath(root, target)} differs from what specs/circuits.cs writes: run it and commit the result");
            return 1;
        }

        Console.WriteLine($"circuits: aes_sbox.inc is current ({allocation.Instructions.Count} instructions, {allocation.Slots} spill slots)");
        return 0;
    }

    File.WriteAllText(target, text);
    Console.WriteLine($"circuits: wrote {Path.GetRelativePath(root, target)}: {circuit.Gates.Count} gates as {allocation.Instructions.Count} instructions, {allocation.Slots} spill slots");
    return 0;
}
catch (ProofException e)
{
    Console.Error.WriteLine("circuits: " + e.Message);
    return 1;
}

/// <summary>A failed proof: the circuit or the generated code does not compute the S-box.</summary>
/// <param name="message">What failed, for the console.</param>
sealed class ProofException(string message) : Exception(message);

/// <summary>One gate: dst = a op b ("xor", "xnor", "and").</summary>
/// <param name="Dst">The value it assigns.</param>
/// <param name="Op">The operation.</param>
/// <param name="A">The first operand.</param>
/// <param name="B">The second operand.</param>
sealed record Gate(string Dst, string Op, string A, string B);

/// <summary>
/// The circuit as parsed: its inputs (a value per bit of the octet), its gates in order, and its
/// outputs (the value of each bit of the result).
/// </summary>
sealed partial class Circuit
{
    /// <summary>Bit i of the input octet is the value Inputs[i].</summary>
    public string[] Inputs { get; } = new string[8];

    /// <summary>Bit i of the S-box value is the value Outputs[i].</summary>
    public string[] Outputs { get; } = new string[8];

    /// <summary>The gates, in the order the file gives (an order every operand is ready in).</summary>
    public List<Gate> Gates { get; } = [];

    /// <summary>
    /// Reads the circuit file: comments (#) and blank lines skipped; every other line a gate, an
    /// input or an output. Refuses a name assigned twice, an operand used before it is assigned,
    /// a bit given twice or missing.
    /// </summary>
    /// <param name="lines">The file's lines.</param>
    /// <returns>The circuit.</returns>
    /// <exception cref="ProofException">A line does not parse, or the program is not well formed.</exception>
    public static Circuit Parse(IEnumerable<string> lines)
    {
        var c = new Circuit();
        var assigned = new HashSet<string>(StringComparer.Ordinal);
        int number = 0;
        foreach (string raw in lines)
        {
            number++;
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            Match m;
            if ((m = InputLine().Match(line)).Success)
            {
                int bit = int.Parse(m.Groups[2].Value);
                if (c.Inputs[bit] is not null || !assigned.Add(m.Groups[1].Value))
                {
                    throw new ProofException($"aes_sbox.txt:{number}: input bit {bit} or name {m.Groups[1].Value} given twice");
                }

                c.Inputs[bit] = m.Groups[1].Value;
            }
            else if ((m = OutputLine().Match(line)).Success)
            {
                int bit = int.Parse(m.Groups[1].Value);
                if (c.Outputs[bit] is not null || !assigned.Contains(m.Groups[2].Value))
                {
                    throw new ProofException($"aes_sbox.txt:{number}: output bit {bit} given twice, or {m.Groups[2].Value} not assigned yet");
                }

                c.Outputs[bit] = m.Groups[2].Value;
            }
            else if ((m = GateLine().Match(line)).Success)
            {
                var gate = new Gate(m.Groups[1].Value, m.Groups[3].Value, m.Groups[2].Value, m.Groups[4].Value);
                if (!assigned.Contains(gate.A) || !assigned.Contains(gate.B) || !assigned.Add(gate.Dst))
                {
                    throw new ProofException($"aes_sbox.txt:{number}: an operand is not assigned yet, or {gate.Dst} is assigned twice");
                }

                c.Gates.Add(gate);
            }
            else
            {
                throw new ProofException($"aes_sbox.txt:{number}: cannot read \"{line}\"");
            }
        }

        if (c.Inputs.Any(v => v is null) || c.Outputs.Any(v => v is null))
        {
            throw new ProofException("aes_sbox.txt: every input and output bit must be named once");
        }

        return c;
    }

    /// <summary>Runs the circuit on every octet and compares each result with the S-box.</summary>
    /// <param name="sbox">FIPS 197's S-box, computed.</param>
    /// <exception cref="ProofException">An octet's result differs.</exception>
    public void Prove(byte[] sbox)
    {
        for (int x = 0; x < 256; x++)
        {
            var v = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < 8; i++)
            {
                v[Inputs[i]] = (x >> i) & 1;
            }

            foreach (Gate g in Gates)
            {
                v[g.Dst] = g.Op switch
                {
                    "xor" => v[g.A] ^ v[g.B],
                    "xnor" => 1 ^ v[g.A] ^ v[g.B],
                    _ => v[g.A] & v[g.B],
                };
            }

            int y = 0;
            for (int i = 0; i < 8; i++)
            {
                y |= v[Outputs[i]] << i;
            }

            if (y != sbox[x])
            {
                throw new ProofException($"aes_sbox.txt: the circuit maps {x:x2} to {y:x2}, the S-box to {sbox[x]:x2}");
            }
        }
    }

    [GeneratedRegex(@"^(\w+) = in ([0-7])$")]
    private static partial Regex InputLine();

    [GeneratedRegex(@"^out ([0-7]) = (\w+)$")]
    private static partial Regex OutputLine();

    [GeneratedRegex(@"^(\w+) = (\w+) (xor|xnor|and) (\w+)$")]
    private static partial Regex GateLine();
}

/// <summary>FIPS 197's S-box, computed from its definition rather than typed in.</summary>
static class Fips197
{
    /// <summary>
    /// S(x) = A(x^-1) + 0x63 (FIPS 197 5.1.1): the inverse in GF(2^8) modulo
    /// x^8 + x^4 + x^3 + x + 1 (0 maps to 0), then bit i of the result is
    /// b_i + b_(i+4) + b_(i+5) + b_(i+6) + b_(i+7) + c_i, indices mod 8, c = 0x63.
    /// </summary>
    /// <returns>The 256 values; checked against FIPS 197's figure 7 at three points.</returns>
    /// <exception cref="ProofException">A spot check fails (the computation is wrong).</exception>
    public static byte[] Sbox()
    {
        var s = new byte[256];
        for (int x = 0; x < 256; x++)
        {
            int inverse = 0;
            for (int y = 1; x != 0 && y < 256; y++)
            {
                if (Multiply(x, y) == 1)
                {
                    inverse = y;
                    break;
                }
            }

            int value = 0;
            for (int i = 0; i < 8; i++)
            {
                int bit = (inverse >> i) ^ (inverse >> ((i + 4) & 7)) ^ (inverse >> ((i + 5) & 7)) ^ (inverse >> ((i + 6) & 7)) ^ (inverse >> ((i + 7) & 7)) ^ (0x63 >> i);
                value |= (bit & 1) << i;
            }

            s[x] = (byte)value;
        }

        if (s[0x00] != 0x63 || s[0x53] != 0xED || s[0xFF] != 0x16)
        {
            throw new ProofException("the computed S-box fails FIPS 197 figure 7's values at 00, 53, ff");
        }

        return s;
    }

    /// <summary>The product of two field elements, reduced modulo x^8 + x^4 + x^3 + x + 1.</summary>
    /// <param name="a">An element (0-255).</param>
    /// <param name="b">An element (0-255).</param>
    /// <returns>a * b in GF(2^8).</returns>
    private static int Multiply(int a, int b)
    {
        int r = 0;
        while (b != 0)
        {
            if ((b & 1) != 0)
            {
                r ^= a;
            }

            a <<= 1;
            if ((a & 0x100) != 0)
            {
                a ^= 0x11B;
            }

            b >>= 1;
        }

        return r;
    }
}

/// <summary>
/// One generated instruction: Op ("movdqa", "pxor", "pand"), its destination and source operands
/// as locations (a register "xmm3", a slot "slot 4", or "ones"), and the gate it belongs to (for
/// the comment).
/// </summary>
/// <param name="Op">The instruction.</param>
/// <param name="Dst">Where it writes.</param>
/// <param name="Src">What it reads besides its destination.</param>
/// <param name="Note">The gate or move it carries out.</param>
sealed record Instruction(string Op, string Dst, string Src, string Note);

/// <summary>The allocator's result: the instructions in order, and the spill slots they use.</summary>
/// <param name="Instructions">The program.</param>
/// <param name="Slots">How many 16-octet slots.</param>
sealed record Allocation(List<Instruction> Instructions, int Slots);

/// <summary>Belady's allocation of the circuit's values to the 16 XMM registers and spill slots.</summary>
static class Allocator
{
    /// <summary>
    /// Allocates the circuit: inputs start in xmm0-xmm7 (bit i in xmm i), outputs end there.
    /// </summary>
    /// <param name="c">The proven circuit.</param>
    /// <returns>The instructions and the slot count.</returns>
    public static Allocation Allocate(Circuit c)
    {
        // Every read of a value, by gate index; the outputs read at index Gates.Count.
        var uses = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        void Use(string v, int at)
        {
            if (!uses.TryGetValue(v, out List<int>? list))
            {
                uses[v] = list = [];
            }

            list.Add(at);
        }

        for (int i = 0; i < c.Gates.Count; i++)
        {
            Use(c.Gates[i].A, i);
            Use(c.Gates[i].B, i);
        }

        foreach (string v in c.Outputs)
        {
            Use(v, c.Gates.Count);
        }

        int NextUse(string v, int after)
        {
            if (!uses.TryGetValue(v, out List<int>? list))
            {
                return int.MaxValue;
            }

            foreach (int at in list)
            {
                if (at > after)
                {
                    return at;
                }
            }

            return int.MaxValue;
        }

        var program = new List<Instruction>();
        var registers = new string?[16];
        var slotOf = new Dictionary<string, int>(StringComparer.Ordinal);   // a value's slot, once written
        var freeSlots = new SortedSet<int>();
        int slots = 0;
        for (int i = 0; i < 8; i++)
        {
            registers[i] = c.Inputs[i];
        }

        int RegisterOf(string v) => Array.IndexOf(registers, v);
        string Location(string v) => RegisterOf(v) is int r and >= 0 ? $"xmm{r}" : $"slot {slotOf[v]}";

        // A register for a new value at gate `at`: a free one, else the one whose value is used
        // farthest ahead (spilled first unless its slot holds it). `keep` registers are in use by
        // the instruction being built.
        int Take(int at, params int[] keep)
        {
            for (int r = 0; r < 16; r++)
            {
                if (registers[r] is null && !keep.Contains(r))
                {
                    return r;
                }
            }

            int victim = -1, farthest = -1;
            for (int r = 0; r < 16; r++)
            {
                if (keep.Contains(r))
                {
                    continue;
                }

                int next = NextUse(registers[r]!, at - 1);
                if (next > farthest)
                {
                    farthest = next;
                    victim = r;
                }
            }

            string value = registers[victim]!;
            if (!slotOf.ContainsKey(value))
            {
                int slot;
                if (freeSlots.Count > 0)
                {
                    slot = freeSlots.Min;
                    freeSlots.Remove(slot);
                }
                else
                {
                    slot = slots++;
                }

                slotOf[value] = slot;
                program.Add(new Instruction("movdqa", $"slot {slot}", $"xmm{victim}", $"spill {value}"));
            }

            registers[victim] = null;
            return victim;
        }

        // Releases what is dead after gate `at`: registers and slots of values with no later use.
        void Release(int at)
        {
            for (int r = 0; r < 16; r++)
            {
                if (registers[r] is string v && NextUse(v, at) == int.MaxValue)
                {
                    registers[r] = null;
                }
            }

            foreach (string v in slotOf.Keys.ToList())
            {
                if (NextUse(v, at) == int.MaxValue && RegisterOf(v) < 0)
                {
                    freeSlots.Add(slotOf[v]);
                    slotOf.Remove(v);
                }
            }
        }

        for (int i = 0; i < c.Gates.Count; i++)
        {
            Gate g = c.Gates[i];
            string a = g.A, b = g.B;
            bool aDies = NextUse(a, i) == int.MaxValue;
            bool bDies = NextUse(b, i) == int.MaxValue;
            // Every gate is commutative: compute into the operand that dies, when one does.
            if (!aDies && bDies && RegisterOf(b) >= 0)
            {
                (a, b) = (b, a);
                (aDies, bDies) = (bDies, aDies);
            }

            if (RegisterOf(a) < 0)
            {
                int r = Take(i, RegisterOf(b) is int rb and >= 0 ? [rb] : []);
                program.Add(new Instruction("movdqa", $"xmm{r}", $"slot {slotOf[a]}", $"reload {a}"));
                registers[r] = a;
            }

            int ra = RegisterOf(a);
            string op = g.Op == "and" ? "pand" : "pxor";
            int rd;
            if (aDies && a != b)
            {
                rd = ra;
                program.Add(new Instruction(op, $"xmm{rd}", Location(b), $"{g.Dst} = {g.A} {g.Op} {g.B}"));
                if (slotOf.Remove(a, out int freed))
                {
                    freeSlots.Add(freed);   // the dying operand's slot copy is dead too
                }
            }
            else
            {
                rd = Take(i, RegisterOf(b) is int rb2 and >= 0 ? [ra, rb2] : [ra]);
                program.Add(new Instruction("movdqa", $"xmm{rd}", $"xmm{ra}", $"copy {a}"));
                program.Add(new Instruction(op, $"xmm{rd}", Location(b), $"{g.Dst} = {g.A} {g.Op} {g.B}"));
            }

            if (g.Op == "xnor")
            {
                program.Add(new Instruction("pxor", $"xmm{rd}", "ones", $"{g.Dst}: not"));
            }

            registers[rd] = g.Dst;
            Release(i);
        }

        // The outputs to xmm0-xmm7: first every output sitting in xmm0-xmm7 but not at its place
        // moves up to a free register of xmm8-xmm15, then each goes to its place, from a register
        // or its slot. There is always room for the first step: only the eight outputs are live
        // now, so if C of them sit in xmm8-xmm15, 8 - C registers there are free, and the outputs
        // to move up are at most 8 - C (the others are in place, up there, or in slots).
        int end = c.Gates.Count;
        for (int r = 0; r < 8; r++)
        {
            if (registers[r] is string v && Array.IndexOf(c.Outputs, v) != r)
            {
                int free = Enumerable.Range(8, 8).First(x => registers[x] is null);
                program.Add(new Instruction("movdqa", $"xmm{free}", $"xmm{r}", $"move {v} aside"));
                registers[free] = v;
                registers[r] = null;
            }
        }

        for (int bit = 0; bit < 8; bit++)
        {
            string v = c.Outputs[bit];
            if (RegisterOf(v) == bit)
            {
                continue;
            }

            program.Add(new Instruction("movdqa", $"xmm{bit}", Location(v), $"output bit {bit} = {v}"));
            int old = RegisterOf(v);
            if (old >= 0)
            {
                registers[old] = null;
            }

            registers[bit] = v;
        }

        _ = end;
        return new Allocation(program, slots);
    }
}

/// <summary>
/// Runs a generated program on all 256 inputs at once: each register and slot holds a 256-bit
/// bit plane (bit x is the value for the input octet x).
/// </summary>
static class Model
{
    /// <summary>Runs the program and compares xmm0-xmm7 with the S-box's bit planes.</summary>
    /// <param name="allocation">The generated program.</param>
    /// <param name="sbox">The S-box.</param>
    /// <exception cref="ProofException">An output plane differs.</exception>
    public static void Prove(Allocation allocation, byte[] sbox)
    {
        var state = new Dictionary<string, UInt128[]>(StringComparer.Ordinal);   // [low 128 inputs, high 128]
        for (int i = 0; i < 8; i++)
        {
            state[$"xmm{i}"] = Plane(x => (x >> i) & 1);
        }

        UInt128[] ones = [UInt128.MaxValue, UInt128.MaxValue];
        foreach (Instruction ins in allocation.Instructions)
        {
            UInt128[] src = ins.Src == "ones" ? ones : state[ins.Src];
            state[ins.Dst] = ins.Op switch
            {
                "movdqa" => [src[0], src[1]],
                "pxor" => [state[ins.Dst][0] ^ src[0], state[ins.Dst][1] ^ src[1]],
                _ => [state[ins.Dst][0] & src[0], state[ins.Dst][1] & src[1]],
            };
        }

        for (int i = 0; i < 8; i++)
        {
            UInt128[] want = Plane(x => (sbox[x] >> i) & 1);
            if (state[$"xmm{i}"][0] != want[0] || state[$"xmm{i}"][1] != want[1])
            {
                throw new ProofException($"the generated program leaves a wrong bit {i} in xmm{i}");
            }
        }
    }

    /// <summary>The bit plane of a function of the input octet.</summary>
    /// <param name="bit">The function, 0 or 1 for each octet.</param>
    /// <returns>Bits 0-127 and 128-255.</returns>
    private static UInt128[] Plane(Func<int, int> bit)
    {
        UInt128 low = 0, high = 0;
        for (int x = 0; x < 128; x++)
        {
            low |= (UInt128)(uint)bit(x) << x;
            high |= (UInt128)(uint)bit(x + 128) << x;
        }

        return [low, high];
    }
}

/// <summary>Writes the .inc file: a header, the slot count, and the macro.</summary>
static class Emitter
{
    /// <summary>The file's text, "\n" line ends.</summary>
    /// <param name="c">The circuit (for the gate counts in the header).</param>
    /// <param name="allocation">The proven program.</param>
    /// <returns>The text.</returns>
    public static string Write(Circuit c, Allocation allocation)
    {
        var s = new StringBuilder();
        int and = c.Gates.Count(g => g.Op == "and"), xor = c.Gates.Count(g => g.Op == "xor"), xnor = c.Gates.Count(g => g.Op == "xnor");
        s.Append("; =============================================================================\n");
        s.Append("; aes_sbox.inc - the AES S-box (FIPS 197 5.1.1) on bitsliced state in SSE2 registers (code).\n");
        s.Append("; GENERATED by specs/circuits.cs from specs/circuits/aes_sbox.txt: do not edit; regenerate.\n");
        s.Append($"; Boyar and Peralta's circuit ({xor} xor, {xnor} xnor, {and} and), proven on all 256 inputs,\n");
        s.Append($"; allocated to xmm0-xmm15 and {allocation.Slots} spill slots, and the result proven again.\n");
        s.Append(";\n");
        s.Append("; HA_AES_SBOX_SSE2 spill: in place on xmm0-xmm7 (xmm i = bit i of every octet slot). Uses\n");
        s.Append("; xmm8-xmm15, the HA_AES_SBOX_SPILLS 16-octet slots at [rsp + spill] (16-byte aligned), and\n");
        s.Append("; ha_aes_ones (16 octets of 0xFF). Constant time: no branch, no address, depends on the state.\n");
        s.Append("; =============================================================================\n");
        s.Append($"HA_AES_SBOX_SPILLS equ {allocation.Slots}\n\n");
        s.Append("%macro HA_AES_SBOX_SSE2 1\n");
        foreach (Instruction ins in allocation.Instructions)
        {
            string Operand(string loc) => loc switch
            {
                "ones" => "[rel ha_aes_ones]",
                _ when loc.StartsWith("slot ", StringComparison.Ordinal) => $"[rsp + %1 + {16 * int.Parse(loc[5..])}]",
                _ => loc,
            };

            string text = $"    {ins.Op,-8}{Operand(ins.Dst)}, {Operand(ins.Src)}";
            s.Append(text.PadRight(44)).Append("; ").Append(ins.Note).Append('\n');
        }

        s.Append("%endmacro\n");
        return s.ToString();
    }
}
