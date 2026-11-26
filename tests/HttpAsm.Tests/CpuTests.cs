using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>
/// The CPU tiers (httpasm.h, "CPU tiers"; docs/DESIGN.md sections 2 and 3): what the library
/// finds, what it uses under HTTPASM_CPU and httpasm_cpu_limit, and that every version of a
/// multi-version routine computes the same results.
/// </summary>
/// <remarks>
/// In <see cref="SerialCollection"/>: these tests change process-wide state (the library's cap,
/// the C library's environment) and read it back, so nothing may run beside them. Each restores
/// what it found.
/// </remarks>
[Collection(nameof(SerialCollection))]
public sealed unsafe class CpuTests
{
    /// <summary>The cap this test process was started with (HTTPASM_CPU), restored after each change.</summary>
    private static ulong StartCap => Cpu.CapFromText(Environment.GetEnvironmentVariable("HTTPASM_CPU"));

    /// <summary>
    /// httpasm_cpu_found reports what the kernel lists in /proc/cpuinfo: a level only when every
    /// feature of it and of the levels below is there (the kernel lists AVX and AVX-512 only when
    /// it saves their registers, as the library's XGETBV check demands), and the groups that need
    /// YMM or ZMM registers only with those.
    /// </summary>
    [Fact]
    public void FindsWhatTheKernelLists()
    {
        Platform.RequireLinuxX64();
        HashSet<string> flags = ProcCpuinfoFlags();
        bool Has(params string[] names) => names.All(flags.Contains);

        ulong expected = 0;
        expected |= Has("aes") ? Cpu.Aesni : 0;
        expected |= Has("pclmulqdq") ? Cpu.Clmul : 0;
        expected |= Has("sha_ni") ? Cpu.Sha : 0;
        expected |= Has("gfni") ? Cpu.Gfni : 0;
        expected |= Has("bmi2") ? Cpu.Bmi2 : 0;
        expected |= Has("adx") ? Cpu.Adx : 0;
        bool v2 = Has("pni", "ssse3", "sse4_1", "sse4_2", "popcnt", "cx16", "lahf_lm");
        bool ymm = v2 && Has("avx");
        bool v3 = ymm && Has("avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe");
        bool v4 = v3 && Has("avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl");
        expected |= v2 ? Cpu.V2 : 0;
        expected |= v3 ? Cpu.V3 : 0;
        expected |= v4 ? Cpu.V4 : 0;
        expected |= ymm && Has("vaes") ? Cpu.Vaes : 0;
        expected |= ymm && Has("vpclmulqdq") ? Cpu.Vclmul : 0;
        expected |= ymm && Has("sha512") ? Cpu.Sha512 : 0;
        expected |= v4 && Has("avx512ifma") ? Cpu.Ifma : 0;
        expected |= v4 && Has("avx512vbmi") ? Cpu.Vbmi : 0;
        expected |= v4 && Has("avx512_vbmi2") ? Cpu.Vbmi2 : 0;

        Assert.Equal($"{expected:x}", $"{Native.CpuFound():x}");
    }

    /// <summary>
    /// httpasm_cpu_features is what was found, narrowed by the HTTPASM_CPU this process started
    /// with (tests/run-linux.sh runs the suite once per tier) and closed over the levels.
    /// </summary>
    [Fact]
    public void UsesWhatTheEnvironmentAllows()
    {
        Platform.RequireLinuxX64();
        ulong expected = Cpu.Effective(Native.CpuFound(), StartCap);
        Assert.Equal($"{expected:x}", $"{Native.CpuFeatures():x}");
    }

    /// <summary>
    /// httpasm_cpu_limit replaces the cap and returns the features: found AND cap, with no level
    /// above a missing one and no group without the level its encodings need, for the levels'
    /// own caps, for caps that skip a level, and for random caps. The start cap is restored.
    /// </summary>
    [Fact]
    public void LimitNarrowsAndClosesOverLevels()
    {
        Platform.RequireLinuxX64();
        ulong found = Native.CpuFound();
        var caps = new List<ulong>
        {
            Cpu.All, Cpu.CapV1, Cpu.CapV2, Cpu.CapV3, Cpu.CapV4,
            Cpu.V4, Cpu.V3 | Cpu.V4, Cpu.V2 | Cpu.V4, Cpu.Vaes, Cpu.V2 | Cpu.Vaes, Cpu.CapV3 & ~Cpu.V2,
            Cpu.Ifma | Cpu.V2 | Cpu.V3, Cpu.All & ~Cpu.V3, ulong.MaxValue, 1UL << 40,
        };
        var random = new Random(20261126);
        for (int i = 0; i < 300; i++)
        {
            caps.Add((ulong)random.NextInt64() & Cpu.All);
        }

        try
        {
            foreach (ulong cap in caps)
            {
                ulong expected = Cpu.Effective(found, cap);
                Assert.True(expected == Native.CpuLimit(cap), $"cap {cap:x}");
                Assert.True(expected == Native.CpuFeatures(), $"cap {cap:x}, read back");
            }
        }
        finally
        {
            _ = Native.CpuLimit(StartCap);
        }
    }

    /// <summary>
    /// HTTPASM_CPU is read by the library's constructor when it loads, with the documented
    /// grammar: levels, "-group" items, and the baseline for anything invalid (unknown words,
    /// case or spacing differences, empty items, a missing "-"). Each case loads a fresh copy of
    /// libhttpasm.so (a new file, so the loader runs its constructor again) with the variable
    /// set in the C library's environment, and reads that copy's features.
    /// </summary>
    /// <remarks>
    /// setenv is not safe while another thread reads the environment; this class runs alone
    /// (<see cref="SerialCollection"/>), and the original value is put back.
    /// </remarks>
    [Fact]
    public void ReadsHttpasmCpuWhenItLoads()
    {
        Platform.RequireLinuxX64();
        string[] texts =
        [
            "", "native", "v1", "v2", "v3", "v4", "v3,-vaes,-sha", "-vaes", "-vaes,-vclmul",
            "native,-ifma", "v4,-vbmi2,-vbmi,-ifma", "v2,-aesni,-clmul,-sha,-gfni", "v3,-bmi2,-adx",
            "-aesni,-clmul,-sha,-gfni,-bmi2,-adx,-vaes,-vclmul,-sha512,-ifma,-vbmi,-vbmi2",
            "V3", "Native", "v3,", ",", ",v3", "v3,vaes", "nonsense", "v3,-vaes,-", "v3,-", "-", "v5",
            "v0", "v3 ", " v3", "v3,,-vaes", "v3,-VAES", "v3;-vaes", "verylongword", "v3,-sha512x",
            "native,native", "v3,v4",
        ];
        string library = Directory.GetFiles(AppContext.BaseDirectory, "libhttpasm.so", SearchOption.AllDirectories).First();
        string scratch = Directory.CreateTempSubdirectory("httpasm-cpu-").FullName;
        string? original = Environment.GetEnvironmentVariable("HTTPASM_CPU");
        ulong found = Native.CpuFound();
        try
        {
            for (int i = 0; i < texts.Length + 1; i++)
            {
                string? text = i < texts.Length ? texts[i] : null; // the last case: unset
                if (text is null)
                {
                    Assert.Equal(0, Native.UnsetEnv("HTTPASM_CPU"));
                }
                else
                {
                    Assert.Equal(0, Native.SetEnv("HTTPASM_CPU", text, 1));
                }

                string copy = Path.Combine(scratch, $"libhttpasm-{i}.so");
                File.Copy(library, copy);
                nint handle = NativeLibrary.Load(copy);
                try
                {
                    var features = (delegate* unmanaged<ulong>)NativeLibrary.GetExport(handle, "httpasm_cpu_features");
                    ulong expected = Cpu.Effective(found, Cpu.CapFromText(text));
                    Assert.True(expected == features(), $"HTTPASM_CPU=\"{text ?? "(unset)"}\": expected {expected:x}, got {features():x}");
                }
                finally
                {
                    NativeLibrary.Free(handle);
                }
            }
        }
        finally
        {
            // Put the variable back as this process found it, then the scratch copies.
            _ = original is null ? Native.UnsetEnv("HTTPASM_CPU") : Native.SetEnv("HTTPASM_CPU", original, 1);
            Directory.Delete(scratch, recursive: true);
        }
    }

    /// <summary>
    /// httpasm_field_value_scan returns the same index at every tier (v1 SSE2, v3 AVX2, v4
    /// AVX-512 where the CPU has them; v2 runs the v1 version) as an oracle written from RFC 9110
    /// section 5.5, for every length up to 200, with a forbidden octet at each position, for all
    /// 256 octet values, and for random values, each placed against a guard page so that any
    /// read past the value kills the test process.
    /// </summary>
    /// <remarks>
    /// Tiers the CPU lacks collapse to the best one it has (the closure), so on a CPU without
    /// AVX-512 the v4 pass re-runs v3; the suite's run under Intel SDE covers v4 itself.
    /// </remarks>
    [Fact]
    public void EveryTierScansFieldValuesAlike()
    {
        Platform.RequireLinuxX64();
        ulong[] tiers = [Cpu.CapV1, Cpu.CapV2, Cpu.CapV3, Cpu.CapV4];
        using var guard = new GuardedBuffer();
        var random = new Random(5_5_2);
        var inputs = new List<byte[]>();
        for (int length = 0; length <= 200; length++)
        {
            inputs.Add(Valid(random, length));
            for (int at = 0; at < length; at++)
            {
                byte[] value = Valid(random, length);
                value[at] = Forbidden[(at + length) % Forbidden.Length];
                inputs.Add(value);
            }
        }

        for (int octet = 0; octet < 256; octet++)
        {
            for (int length = 1; length <= 130; length += 43)
            {
                byte[] value = Valid(random, length);
                value[length - 1] = (byte)octet;
                inputs.Add(value);
            }
        }

        for (int i = 0; i < 2000; i++)
        {
            byte[] value = new byte[random.Next(0, 300)];
            random.NextBytes(value);
            inputs.Add(value);
        }

        try
        {
            foreach (ulong tier in tiers)
            {
                ulong features = Native.CpuLimit(tier);
                foreach (byte[] value in inputs)
                {
                    byte* p = guard.AtPageEnd(value);
                    nuint actual = Native.FieldValueScan(p, (nuint)value.Length);
                    nuint expected = (nuint)Oracle(value);
                    if (actual != expected)
                    {
                        Assert.Fail($"features {features:x}: length {value.Length}, expected {expected}, got {actual}: {Convert.ToHexString(value)}");
                    }
                }
            }
        }
        finally
        {
            _ = Native.CpuLimit(StartCap);
        }
    }

    /// <summary>The octets a field value may not hold: the CTLs other than HTAB (RFC 9110 5.5).</summary>
    private static readonly byte[] Forbidden = [.. Enumerable.Range(0, 32).Where(b => b != 9).Select(b => (byte)b), 0x7F];

    /// <summary>A value of field-vchar, SP and HTAB only, from the whole allowed range.</summary>
    /// <param name="random">The generator.</param>
    /// <param name="length">The value's length.</param>
    /// <returns>The value.</returns>
    private static byte[] Valid(Random random, int length)
    {
        byte[] value = new byte[length];
        for (int i = 0; i < length; i++)
        {
            int pick = random.Next(0, 256 - 32 - 1 + 1);       // 0x20-0x7E, 0x80-0xFF, HTAB
            value[i] = pick == 0 ? (byte)0x09 : (byte)(pick < 96 ? 0x1F + pick : pick + 32);
        }

        return value;
    }

    /// <summary>The oracle: the first octet a field value may not hold, or the length.</summary>
    /// <param name="value">The value.</param>
    /// <returns>Its index.</returns>
    private static int Oracle(byte[] value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            byte b = value[i];
            if ((b < 0x20 && b != 0x09) || b == 0x7F)
            {
                return i;
            }
        }

        return value.Length;
    }

    /// <summary>The CPU flags the kernel lists for the first CPU.</summary>
    /// <returns>The flag names.</returns>
    private static HashSet<string> ProcCpuinfoFlags()
    {
        string line = File.ReadLines("/proc/cpuinfo").First(l => l.StartsWith("flags", StringComparison.Ordinal));
        return [.. line[(line.IndexOf(':') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries)];
    }
}
