using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>Where the native tests can run.</summary>
internal static class Platform
{
    /// <summary>
    /// Skips the calling test unless the process is Linux x64, where libhttpasm.so loads.
    /// With HTTPASM_REQUIRE_LINUX=1 (CI and tests/run-linux.sh) the test fails instead, so a
    /// run that was meant to cover the native code can never pass by skipping it.
    /// </summary>
    /// <exception cref="Xunit.Sdk.SkipException">Not Linux x64, and skipping is allowed.</exception>
    /// <exception cref="Xunit.Sdk.FailException">Not Linux x64, and HTTPASM_REQUIRE_LINUX=1.</exception>
    public static void RequireLinuxX64()
    {
        if (OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64)
        {
            return;
        }

        string reason = $"libhttpasm.so is a Linux x64 library; this is {RuntimeInformation.OSDescription} "
            + $"{RuntimeInformation.ProcessArchitecture}. tests/run-linux.sh runs the tests in a Linux container.";
        if (Environment.GetEnvironmentVariable("HTTPASM_REQUIRE_LINUX") == "1")
        {
            Assert.Fail(reason);
        }

        Assert.Skip(reason);
    }

    /// <summary>
    /// Whether the running Linux kernel is at least <paramref name="major"/>.<paramref name="minor"/>,
    /// read from /proc/sys/kernel/osrelease ("7.0.0-1017-azure", "5.15.153.1-microsoft-standard-WSL2").
    /// </summary>
    /// <param name="major">The least major version.</param>
    /// <param name="minor">The least minor version within it.</param>
    /// <returns>True when the release is that one or later; false when it is older, or unreadable.</returns>
    /// <remarks>
    /// The upstream version only: a distribution's kernel may carry a later change backported, so
    /// a test that keys on this must only depend on behavior upstream had by that version.
    /// </remarks>
    public static bool KernelAtLeast(int major, int minor)
    {
        string[] parts;
        try
        {
            parts = File.ReadAllText("/proc/sys/kernel/osrelease").Trim().Split('.', '-');
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;                               // no /proc (not Linux), or not readable
        }

        return parts.Length >= 2
            && int.TryParse(parts[0], out int haveMajor)
            && int.TryParse(parts[1], out int haveMinor)
            && (haveMajor > major || (haveMajor == major && haveMinor >= minor));
    }

    /// <summary>
    /// Whether this process holds a capability in its effective set, read from
    /// /proc/self/status's CapEff line (a hexadecimal mask, bit n = capability n).
    /// </summary>
    /// <param name="capability">The capability's number (CAP_IPC_LOCK = 14).</param>
    /// <returns>True when held; false when not, or when the line cannot be read.</returns>
    /// <remarks>
    /// What the kernel checks may be narrower: io_uring asks for CAP_IPC_LOCK in the initial user
    /// namespace, so a process holding it only inside its own user namespace is still charged,
    /// and a test that skips on true merely skips more often than it must.
    /// </remarks>
    public static bool HasEffectiveCapability(int capability)
    {
        try
        {
            foreach (string line in File.ReadLines("/proc/self/status"))
            {
                if (line.StartsWith("CapEff:", StringComparison.Ordinal))
                {
                    ulong mask = Convert.ToUInt64(line["CapEff:".Length..].Trim(), 16);
                    return (mask >> capability & 1) != 0;
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
        {
            // No /proc, or a line this parser does not know: treat the capability as absent.
        }

        return false;
    }

    /// <summary>
    /// The kernel release and this process's RLIMIT_MEMLOCK, for a failure message about
    /// io_uring: Linux 6.14 and later charge every ring to that limit (httpasm.h, HTTPASM_SERVER_URING),
    /// so a worker past it runs on epoll.
    /// </summary>
    /// <returns>For example "kernel 7.0.0-1017-azure, RLIMIT_MEMLOCK 8192 KiB (hard 8192 KiB)".</returns>
    public static string IoUringBudget()
    {
        string release = File.Exists("/proc/sys/kernel/osrelease")
            ? File.ReadAllText("/proc/sys/kernel/osrelease").Trim()
            : "unknown";
        if (Native.GetRlimit(Native.RlimitMemlock, out Rlimit limit) != 0)
        {
            return $"kernel {release}, RLIMIT_MEMLOCK unreadable (errno {Marshal.GetLastPInvokeError()})";
        }

        return $"kernel {release}, RLIMIT_MEMLOCK {Kib(limit.Current)} (hard {Kib(limit.Max)})";

        // RLIM_INFINITY is ~0: "unlimited", not 16 EiB.
        static string Kib(ulong bytes) => bytes == ulong.MaxValue ? "unlimited" : $"{bytes / 1024} KiB";
    }
}
