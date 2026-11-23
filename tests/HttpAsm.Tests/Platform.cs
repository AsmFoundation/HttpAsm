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
}
