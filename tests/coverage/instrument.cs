// =============================================================================
// instrument.cs - the coverage build's assembler: NASM with every block and every branch edge
// of HttpAsm's own code marked, so the tests can be measured instruction-block by block
// (docs/DESIGN.md section 2: "every block of libhttpasm.so runs under the tests, or is listed
// with the reason it cannot").
//
// It stands in for NASM in AsmFoundation.Sdk's build (AsmToolchain=System, AsmNasmCommand; see
// tests/coverage/run.sh and tests/fuzz/run.sh). For each HttpAsm source it:
//   1. runs the real NASM with -E: macros expanded (each expansion is code of its own, with its
//      own markers), includes inlined, and %line directives that keep every line's origin;
//   2. inserts markers into the executable sections:
//        block   after each run of labels, before the first instruction that follows
//        fall    right after each conditional jump: its not-taken edge
//        taken   each conditional jump is sent through a trampoline that marks its taken edge
//                and jumps on to the real target
//        dead    after jmp, ret or ud2, before an instruction no label leads to: code nothing
//                can reach, which must stay unmarked
//      A marker is "mov byte [rel marks + id], 1": it changes no register and no flag, so it
//      can sit anywhere, even between a compare and the jump that reads its flags;
//   3. appends the trampolines, then a "ha_cov" data section: a 24-octet header ("HACOV001", a
//      hash of the source path, the marker count) and one octet per marker; the linker gathers
//      every object's region into one section, and tests/coverage/coverage_rt.asm writes it to
//      a file when the process exits. The Fuzz configuration names the section
//      "__libfuzzer_extra_counters" instead (--section): libFuzzer then reads the markers as
//      coverage counters of its own, so the fuzzers steer by the assembly's blocks and edges;
//   4. writes <object>.covmap beside the object: one line per marker (id, kind, the original
//      file and line, the scope label, and the label or jump it stands for);
//   5. assembles the instrumented text with the real NASM and the build's own arguments.
// A source NASM cannot preprocess alone (an %if over equ symbols) is assembled as it is, and its
// map records the octets of instructions left unmarked: report.cs fails the gate when there are
// any, so code never drops out of the gate's sight with only a note to show for it.
// Other sources the SDK assembles (its libc stubs) pass through untouched.
//
// Usage (as AsmNasmCommand): dotnet run --file tests/coverage/instrument.cs --
//   [--section <name>] --nasm <real nasm> <the SDK's NASM arguments: ... -o <object> <source>>
//   (--section defaults to ha_cov)
// Exit status: NASM's, or 2 for a usage error or an instruction this tool cannot instrument.
// =============================================================================
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

return Instrumenter.Run(args);

/// <summary>The coverage build's NASM stand-in: see this file's header.</summary>
internal static partial class Instrumenter
{
    /// <summary>The conditional jumps: each has a taken and a not-taken edge.</summary>
    private static readonly HashSet<string> ConditionalJumps = new(StringComparer.OrdinalIgnoreCase)
    {
        "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe",
        "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
        "js", "jz",
    };

    /// <summary>Jumps with only an 8-bit displacement, which a trampoline could be out of reach of.</summary>
    private static readonly HashSet<string> ShortOnlyJumps = new(StringComparer.OrdinalIgnoreCase)
    {
        "jrcxz", "jecxz", "loop", "loope", "loopne", "loopnz", "loopz",
    };

    /// <summary>Instructions after which the next one is reached only through a label.</summary>
    private static readonly HashSet<string> Terminators = new(StringComparer.OrdinalIgnoreCase) { "jmp", "ret", "ud2" };

    /// <summary>Directives that put data, not code, where they stand.</summary>
    private static readonly HashSet<string> DataDirectives = new(StringComparer.OrdinalIgnoreCase)
    {
        "db", "dw", "dd", "dq", "dt", "do", "dy", "dz", "incbin", "times",
    };

    /// <summary>The label of this object's region header (magic, hash, count), local to the object.</summary>
    private const string Base = "..@ha_cov_base";

    /// <summary>
    /// The label of the marker octets, right after the 24-octet header. Markers address this one,
    /// never <see cref="Base"/>: marker 0 at the header's start would overwrite its magic.
    /// </summary>
    private const string Marks = "..@ha_cov_marks";

    /// <summary>
    /// Runs the stand-in: parses the arguments, preprocesses, instruments, assembles.
    /// </summary>
    /// <param name="args">"--nasm", the real NASM, then the SDK's NASM arguments.</param>
    /// <returns>The process exit status: NASM's, or 2 for a usage or instrumentation error.</returns>
    public static int Run(string[] args)
    {
        // An optional "--section <name>" first: where the markers go (ha_cov, or libFuzzer's
        // __libfuzzer_extra_counters for the Fuzz configuration).
        string section = "ha_cov";
        if (args.Length >= 2 && args[0] == "--section")
        {
            section = args[1];
            args = args[2..];
        }

        if (args.Length < 4 || args[0] != "--nasm")
        {
            Console.Error.WriteLine("instrument.cs: usage: [--section <name>] --nasm <real nasm> <nasm arguments> -o <object> <source>");
            return 2;
        }

        string nasm = args[1];
        var nasmArgs = args[2..].ToList();
        int o = nasmArgs.LastIndexOf("-o");
        if (o < 0 || o + 2 != nasmArgs.Count - 1)
        {
            Console.Error.WriteLine($"instrument.cs: expected '... -o <object> <source>' at the end, got: {string.Join(' ', nasmArgs)}");
            return 2;
        }

        string obj = nasmArgs[o + 1], source = nasmArgs[^1];
        if (!IsHttpAsmSource(source))
        {
            return Nasm(nasm, nasmArgs);                    // the SDK's own stubs: as they are
        }

        string preprocessed = obj + ".pre.asm", instrumented = obj + ".cov.asm", map = obj + ".covmap";
        var preArgs = nasmArgs.Take(o).Append("-E").Append("-o").Append(preprocessed).Append(source).ToList();
        string normalizedSource = source.Replace('\\', '/');
        if (Nasm(nasm, preArgs, out string preprocessErrors) != 0)
        {
            // Some sources cannot be preprocessed alone: an %if over equ symbols (semantics/
            // tables.asm builds its character table with "%if (bits & (HA_CC_DIGIT | ...))",
            // and HA_CC_DIGIT is an equ) needs the assembler, which NASM's -E mode refuses with
            // "symbol references not supported in preprocess-only mode". Such a source is
            // assembled as it is, and its map says so, so the report lists it as not
            // instrumented rather than dropping it. The preprocessor's complaints are kept back
            // (MSBuild would count their "error" lines as the build's errors) and shown only if
            // assembling fails too.
            int plain = Nasm(nasm, nasmArgs);
            if (plain != 0)
            {
                Console.Error.Write(preprocessErrors);
                return plain;
            }

            // The map also says how many octets of instructions went unmarked, read from the
            // object just assembled. None (a source of tables only) is harmless; any is code the
            // gate cannot see, and report.cs fails the gate for it: client.asm was assembled so,
            // without a word but the report's note, while one "%if" over equ symbols kept it
            // from being preprocessed alone (b7b30d7).
            long code;
            try
            {
                code = ExecutableOctets(obj);
            }
            catch (Exception e) when (e is InvalidDataException or IOException)
            {
                Console.Error.WriteLine($"instrument.cs: {obj}: {e.Message}");
                return 2;
            }

            File.WriteAllLines(map, [$"# source\t{normalizedSource}\thash\t{Fnv1a(normalizedSource):X16}\tcount\t0", $"# uninstrumented\t{code}\t{FirstLine(preprocessErrors)}"]);
            return 0;
        }

        try
        {
            var result = Instrument(File.ReadAllLines(preprocessed), normalizedSource, section);
            File.WriteAllLines(instrumented, result.Lines);
            // The header names the region this map describes: the report matches it to the
            // dumps by the hash, which the region's own header carries too.
            File.WriteAllLines(map, result.Map.Prepend($"# source\t{normalizedSource}\thash\t{Fnv1a(normalizedSource):X16}\tcount\t{result.Map.Count}"));
        }
        catch (InstrumentationException e)
        {
            Console.Error.WriteLine($"instrument.cs: {source}: {e.Message}");
            return 2;
        }

        var asmArgs = nasmArgs.Take(o + 2).Append(instrumented).ToList();
        return Nasm(nasm, asmArgs);
    }

    /// <summary>
    /// Whether a source is HttpAsm's own (src/HttpAsm.Core, src/HttpAsm), as opposed to a stub
    /// the SDK generates. Only HttpAsm's are measured.
    /// </summary>
    /// <param name="source">The source path as the SDK passes it.</param>
    /// <returns>True for HttpAsm's sources.</returns>
    private static bool IsHttpAsmSource(string source)
    {
        string path = source.Replace('\\', '/');
        return path.Contains("/src/HttpAsm.Core/", StringComparison.Ordinal) || path.Contains("/src/HttpAsm/", StringComparison.Ordinal)
            ? !path.Contains("/obj/", StringComparison.Ordinal)
            : false;
    }

    /// <summary>Runs the real NASM, passing its output through.</summary>
    /// <param name="nasm">The real NASM.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <returns>Its exit status.</returns>
    /// <exception cref="InvalidOperationException">The process could not be started.</exception>
    private static int Nasm(string nasm, IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo(nasm) { UseShellExecute = false };
        foreach (string a in arguments)
        {
            start.ArgumentList.Add(a);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"could not start {nasm}");
        process.WaitForExit();
        return process.ExitCode;
    }

    /// <summary>Runs the real NASM, keeping its messages instead of passing them through.</summary>
    /// <param name="nasm">The real NASM.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="messages">What it wrote to stdout and stderr.</param>
    /// <returns>Its exit status.</returns>
    /// <exception cref="InvalidOperationException">The process could not be started.</exception>
    private static int Nasm(string nasm, IEnumerable<string> arguments, out string messages)
    {
        var start = new ProcessStartInfo(nasm) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string a in arguments)
        {
            start.ArgumentList.Add(a);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"could not start {nasm}");
        // Both streams are read to the end concurrently, so neither pipe can fill and stall NASM.
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        string stdout = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        messages = stdout + stderr.Result;
        return process.ExitCode;
    }

    /// <summary>
    /// The octets of instructions an ELF64 object holds: the sizes of its sections flagged
    /// SHF_EXECINSTR, summed. Zero for an object of data only (NASM may still emit an empty
    /// .text). Used on a source assembled without markers, to tell a harmless one from one whose
    /// code the coverage gate would not see.
    /// </summary>
    /// <param name="path">The object NASM wrote (the Coverage and Fuzz builds are linux-x64: -f elf64).</param>
    /// <returns>The octets of instructions.</returns>
    /// <exception cref="InvalidDataException">The file is not a little-endian ELF64 object, its section table lies outside it, or it uses extended section numbering (more than 65,279 sections, which NASM never writes for one source).</exception>
    /// <exception cref="IOException">The file could not be read.</exception>
    private static long ExecutableOctets(string path)
    {
        byte[] elf = File.ReadAllBytes(path);
        // e_ident: 0x7F "ELF", EI_CLASS 2 (ELFCLASS64), EI_DATA 1 (little-endian). Anything
        // else would make the offsets below read the wrong fields: refused, not guessed at.
        if (elf.Length < 64 || elf[0] != 0x7F || elf[1] != (byte)'E' || elf[2] != (byte)'L' || elf[3] != (byte)'F' || elf[4] != 2 || elf[5] != 1)
        {
            throw new InvalidDataException("not a little-endian ELF64 object");
        }

        long shoff = BinaryPrimitives.ReadInt64LittleEndian(elf.AsSpan(0x28));          // e_shoff
        int shentsize = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x3A));     // e_shentsize
        int shnum = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x3C));         // e_shnum
        if (shnum == 0 && shoff != 0)
        {
            // e_shnum 0 with a table present means the count is in section 0's sh_size
            // (extended numbering); one source never needs it, so it is refused, not read.
            throw new InvalidDataException("extended section numbering");
        }

        if (shentsize < 64 || shoff < 0 || shoff + (long)shentsize * shnum > elf.Length)
        {
            throw new InvalidDataException("the section header table lies outside the file");
        }

        long code = 0;
        for (int i = 0; i < shnum; i++)
        {
            ReadOnlySpan<byte> header = elf.AsSpan((int)(shoff + ((long)i * shentsize)), 64);
            ulong flags = BinaryPrimitives.ReadUInt64LittleEndian(header[8..]);          // sh_flags
            if ((flags & 0x4) != 0)                                                       // SHF_EXECINSTR
            {
                code += BinaryPrimitives.ReadInt64LittleEndian(header[32..]);            // sh_size
            }
        }

        return code;
    }

    /// <summary>The first line of a text, for a one-line note.</summary>
    /// <param name="text">The text.</param>
    /// <returns>Its first line, trimmed; empty for an empty text.</returns>
    private static string FirstLine(string text) => text.Split('\n', 2)[0].Trim();

    /// <summary>An instruction this tool cannot mark without changing the program's meaning.</summary>
    /// <param name="message">What and where.</param>
    private sealed class InstrumentationException(string message) : Exception(message);

    /// <summary>The instrumented text and its marker map.</summary>
    /// <param name="Lines">The source to assemble.</param>
    /// <param name="Map">The .covmap lines: id, kind, file, line, scope, text (tab-separated).</param>
    internal sealed record Result(List<string> Lines, List<string> Map);

    /// <summary>
    /// Inserts the markers into one preprocessed source (see the file header for the kinds).
    /// </summary>
    /// <param name="input">NASM -E output.</param>
    /// <param name="source">The source's path, hashed into the region header.</param>
    /// <param name="section">The section the markers go into (ha_cov, or libFuzzer's
    /// __libfuzzer_extra_counters).</param>
    /// <returns>The instrumented lines and the map.</returns>
    /// <exception cref="InstrumentationException">A short-only jump (jrcxz, loop), whose
    /// trampoline could be out of its 8-bit reach, or a conditional jump whose target is not a
    /// plain label.</exception>
    internal static Result Instrument(string[] input, string source, string section)
    {
        var output = new List<string>(input.Length * 2);
        var map = new List<string>();
        var trampolines = new List<string>();
        string file = source;
        int line = 0, increment = 1;
        string currentSection = ".text";
        bool code = true;                   // the current section is executable
        string scope = "";                  // the last non-local label: what ".x" means
        string? pendingLabel = null;        // labels seen, no instruction yet (a block start)
        bool afterTerminator = false;       // the previous instruction was jmp, ret or ud2
        string? pendingAt = null;           // where the pending block's first label stands

        int Marker(string kind, string at, string text)
        {
            int id = map.Count;
            map.Add($"{id}\t{kind}\t{at}\t{scope}\t{text}");
            return id;
        }

        string MarkerLine(int id) => $" mov byte [rel {Marks} + {id}], 1";

        foreach (string raw in input)
        {
            Match lineDirective = LineDirective().Match(raw);
            if (lineDirective.Success)
            {
                line = int.Parse(lineDirective.Groups[1].Value);
                increment = int.Parse(lineDirective.Groups[2].Value);
                file = lineDirective.Groups[3].Value.Trim();
                output.Add(raw);
                continue;
            }

            string here = $"{file}\t{line}";
            string text = raw.Trim();
            line += increment;              // the line after this one
            string resync = $"%line {line}+{increment} {file}";

            if (text.Length == 0)
            {
                output.Add(raw);
                continue;
            }

            Match sectionDirective = SectionDirective().Match(text);
            if (sectionDirective.Success)
            {
                currentSection = sectionDirective.Groups[2].Value;
                code = sectionDirective.Groups[1].Value.Equals("absolute", StringComparison.OrdinalIgnoreCase)
                    ? false
                    : currentSection.StartsWith(".text", StringComparison.Ordinal);
                pendingLabel = null;        // a label right before a section change is no block
                afterTerminator = false;
                output.Add(raw);
                continue;
            }

            if (!code || text.StartsWith('[') || text.StartsWith('%'))
            {
                output.Add(raw);
                continue;
            }

            // A label, maybe with an instruction after it on the same line.
            string rest = text;
            Match label = LabelDefinition().Match(rest);
            if (label.Success)
            {
                string name = label.Groups[1].Value;
                if (!name.StartsWith('.') || name.StartsWith("..@", StringComparison.Ordinal))
                {
                    scope = name.StartsWith("..@", StringComparison.Ordinal) ? scope : name;
                }

                if (pendingLabel is null)
                {
                    pendingAt = here;
                }

                pendingLabel = pendingLabel is null ? name : pendingLabel + " " + name;
                afterTerminator = false;
                rest = rest[label.Length..].Trim();
                if (rest.Length == 0)
                {
                    output.Add(raw);
                    continue;
                }

                // An instruction after the label: emit the label alone, then the rest as a line.
                output.Add(name + ":");
            }

            string mnemonic = FirstWord(rest);
            if (EquDefinition().IsMatch(rest))
            {
                // "NAME equ value" (or a label followed by "equ"): a constant, no code at all.
                output.Add(label.Success ? " " + rest : raw);
                continue;
            }

            if (DataDirectives.Contains(mnemonic))
            {
                pendingLabel = null;        // a data label (or alignment padding): no block
                output.Add(label.Success ? " " + rest : raw);
                continue;
            }

            // An instruction. Mark the block it starts, or the dead code it begins.
            if (pendingLabel is not null)
            {
                output.Add(MarkerLine(Marker("block", pendingAt!, pendingLabel)));
                output.Add($"%line {line - increment}+{increment} {file}");
                pendingLabel = null;
            }
            else if (afterTerminator)
            {
                output.Add(MarkerLine(Marker("dead", here, rest)));
                output.Add($"%line {line - increment}+{increment} {file}");
            }

            afterTerminator = Terminators.Contains(mnemonic);
            if (ShortOnlyJumps.Contains(mnemonic))
            {
                throw new InstrumentationException($"{here.Replace('\t', ':')}: {rest}: a short-only jump cannot be given a trampoline");
            }

            if (!ConditionalJumps.Contains(mnemonic))
            {
                output.Add(label.Success ? " " + rest : raw);
                continue;
            }

            // A conditional jump: send it through a trampoline that marks the taken edge, and
            // mark the not-taken edge right after it.
            string operand = rest[mnemonic.Length..].Trim();
            operand = StripPrefix(StripPrefix(StripPrefix(operand, "short"), "near"), "strict");
            if (!PlainLabel().IsMatch(operand))
            {
                throw new InstrumentationException($"{here.Replace('\t', ':')}: {rest}: the target is not a plain label");
            }

            string target = operand.StartsWith('.') && !operand.StartsWith("..@", StringComparison.Ordinal) ? scope + operand : operand;
            int taken = Marker("taken", here, rest);
            string trampoline = $"..@ha_cov_t{taken}";
            trampolines.Add($"{trampoline}:");
            trampolines.Add(MarkerLine(taken));
            trampolines.Add($" jmp {target}");
            output.Add($" {mnemonic} {trampoline}");
            output.Add(MarkerLine(Marker("fall", here, rest)));
            output.Add(resync);
        }

        // The trampolines, in the text section; then this object's region of markers.
        output.Add("[section .text]");
        output.AddRange(trampolines);
        output.Add($"[section {section} progbits alloc write noexec align=8]");
        output.Add($"{Base}:");
        output.Add(" db \"HACOV001\"");
        output.Add($" dq 0x{Fnv1a(source):X16}");
        output.Add($" dq {map.Count}");
        output.Add($"{Marks}:");
        output.Add($" times {map.Count} db 0");
        return new Result(output, map);
    }

    /// <summary>The first word of a statement (its mnemonic or directive), without prefixes like lock or rep.</summary>
    /// <param name="statement">The statement.</param>
    /// <returns>The word that decides what the statement is.</returns>
    private static string FirstWord(string statement)
    {
        string[] words = statement.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        foreach (string word in words)
        {
            if (!word.Equals("lock", StringComparison.OrdinalIgnoreCase) && !word.StartsWith("rep", StringComparison.OrdinalIgnoreCase)
                && !word.Equals("o16", StringComparison.OrdinalIgnoreCase) && !word.Equals("a32", StringComparison.OrdinalIgnoreCase))
            {
                return word;
            }
        }

        return words.Length > 0 ? words[0] : "";
    }

    /// <summary>Removes a leading keyword (and the space after it) from an operand.</summary>
    /// <param name="operand">The operand.</param>
    /// <param name="keyword">The keyword, such as "short".</param>
    /// <returns>The operand without it.</returns>
    private static string StripPrefix(string operand, string keyword) =>
        operand.StartsWith(keyword + " ", StringComparison.OrdinalIgnoreCase) ? operand[(keyword.Length + 1)..].Trim() : operand;

    /// <summary>FNV-1a over a source path: the region header's object id.</summary>
    /// <param name="text">The path.</param>
    /// <returns>The 64-bit hash.</returns>
    internal static ulong Fnv1a(string text)
    {
        ulong hash = 14695981039346656037;
        foreach (byte b in Encoding.UTF8.GetBytes(text))
        {
            hash ^= b;
            hash *= 1099511628211;
        }

        return hash;
    }

    /// <summary>NASM -E's line directive: "%line 47+1 src/file.asm".</summary>
    [GeneratedRegex(@"^\s*%line\s+(\d+)\+(\d+)\s+(.*)$")]
    private static partial Regex LineDirective();

    /// <summary>A section directive in -E's bracket form: "[section .text ...]", "[absolute 0]".</summary>
    [GeneratedRegex(@"^\[\s*(section|segment|absolute)\s+([^\s\]]+)", RegexOptions.IgnoreCase)]
    private static partial Regex SectionDirective();

    /// <summary>A label definition at a statement's start: "name:".</summary>
    [GeneratedRegex(@"^([A-Za-z._?$@][\w.$@#~?]*):")]
    private static partial Regex LabelDefinition();

    /// <summary>A constant definition: "NAME equ value", or "equ value" after a label.</summary>
    [GeneratedRegex(@"^(?:[A-Za-z._?$@][\w.$@#~?]*\s+)?equ\b", RegexOptions.IgnoreCase)]
    private static partial Regex EquDefinition();

    /// <summary>A jump target this tool can retarget: one label, nothing else.</summary>
    [GeneratedRegex(@"^[A-Za-z._?$@][\w.$@#~?]*$")]
    private static partial Regex PlainLabel();
}
