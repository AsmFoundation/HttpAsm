using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>
/// The tests that change process-wide state (a resource limit, the C library's environment, the
/// library's CPU cap), and so must not run beside any other test: xunit runs this collection
/// alone, after every parallel collection has finished.
/// </summary>
[CollectionDefinition(nameof(SerialCollection), DisableParallelization = true)]
public sealed class SerialCollection;

/// <summary>
/// io_uring's memory budget. Some kernels charge every page of a ring to the user's
/// RLIMIT_MEMLOCK: Linux 6.14 to 7.2, unless they carry upstream commit b59cabf9b4ac (2026-10-06,
/// "io_uring: do not charge the SQ/CQ rings to RLIMIT_MEMLOCK"), which calls the charge a 6.14
/// regression and is backported to stable kernels. Whatever the kernel decides, a worker that
/// asked for io_uring and is refused a ring opens epoll instead and serves all the same.
/// </summary>
[Collection(nameof(SerialCollection))]
public sealed unsafe class RingBudgetTests
{
    /// <summary>CAP_IPC_LOCK's bit in /proc/self/status's CapEff: a process holding it is never charged.</summary>
    private const int CapIpcLock = 14;

    /// <summary>The SQ size the library asks for (uring.asm, HA_RING_ENTRIES).</summary>
    private const long RingEntries = 256;

    /// <summary>
    /// With RLIMIT_MEMLOCK at 0, the library follows the kernel's own verdict, which this test
    /// takes independently with a raw io_uring_setup of the library's ring size:
    /// <list type="bullet">
    /// <item>a kernel that charges rings refuses it (ENOMEM), and then every worker of a server
    /// asking for io_uring falls back to epoll and serves;</item>
    /// <item>a kernel that does not (before 6.14, or with the fix) grants it, and then the
    /// server keeps io_uring.</item>
    /// </list>
    /// With the limit back, the next start gets its rings again in either case.
    /// </summary>
    /// <remarks>
    /// Kernel versions cannot decide this: CI's runners have shown both behaviors on kernels of
    /// the same series (2026-11-26), since the fix reaches each distribution's kernel at its own
    /// time. The deterministic test of the fallback itself, on every kernel, is
    /// tests/native/fallback.c (a seccomp filter refuses io_uring_setup, as Docker's does).
    /// Skips only where the question does not arise: with CAP_IPC_LOCK (never charged), or where
    /// io_uring is unavailable to begin with (which HTTPASM_REQUIRE_URING=1 turns into a
    /// failure). The limit is process-wide, hence <see cref="SerialCollection"/>, and it is put
    /// back even when an assertion fails.
    /// </remarks>
    [Fact]
    public void FollowsTheKernelUnderAZeroMemlockLimit()
    {
        Platform.RequireLinuxX64();
        if (Platform.HasEffectiveCapability(CapIpcLock))
        {
            Assert.Skip("this process holds CAP_IPC_LOCK, so its rings are never charged to RLIMIT_MEMLOCK");
        }

        Assert.Equal(0, Native.GetRlimit(Native.RlimitMemlock, out Rlimit saved));
        using var server = new TestServer(x => x.Respond(200, "served"), flags: ServerIo.AskUring);
        if (server.Io != ServerIo.Uring)
        {
            string why = $"io_uring is not available to begin with: {server.Io} ({Platform.IoUringBudget()})";
            if (TestServer.RequireUring)
            {
                Assert.Fail(why);
            }

            Assert.Skip(why);
        }

        server.Stop();
        int restored;
        try
        {
            Assert.Equal(0, Native.SetRlimit(Native.RlimitMemlock, new Rlimit { Current = 0, Max = saved.Max }));
            (bool refused, int errno) = KernelRefusesARing();
            Assert.True(!refused || errno == 12, $"io_uring_setup refused with errno {errno}, not ENOMEM ({Platform.IoUringBudget()})");
            Assert.Equal(0, server.Start());
            uint expected = refused ? ServerIo.Epoll : ServerIo.Uring;
            Assert.True(expected == server.Io,
                $"the kernel {(refused ? "refused" : "granted")} a ring under a zero memlock limit, so every worker should be on {expected}; httpasm_server_io says {server.Io} ({Platform.IoUringBudget()})");
            for (int i = 0; i < 4; i++)
            {
                // Several connections, spread over the workers by SO_REUSEPORT: each is
                // served, whichever backend the worker that takes it runs on.
                using var c = new RawConnection(server.Port);
                c.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
                Assert.Equal("served", c.ReadResponse().Text);
            }

            server.Stop();
        }
        finally
        {
            // Put the limit back first, whatever failed: every later test needs it. Asserted
            // only after the finally, so a failure above is not hidden by this one.
            restored = Native.SetRlimit(Native.RlimitMemlock, saved);
        }

        Assert.Equal(0, restored);
        Assert.Equal(0, server.Start());
        Assert.True(server.Io == ServerIo.Uring, $"the rings came back: {server.Io} ({Platform.IoUringBudget()})");
        using var again = new RawConnection(server.Port);
        again.Send("GET / HTTP/1.1\r\nHost: t\r\n\r\n");
        Assert.Equal("served", again.ReadResponse().Text);
    }

    /// <summary>
    /// Asks the kernel for a ring of the library's size with a raw io_uring_setup, and closes it
    /// at once if granted: the kernel's verdict under the current limits, taken apart from the
    /// library.
    /// </summary>
    /// <returns>Whether it refused, and the errno when it did (0 otherwise).</returns>
    private static (bool Refused, int Errno) KernelRefusesARing()
    {
        byte* parameters = stackalloc byte[120];
        new Span<byte>(parameters, 120).Clear();
        long fd = Native.SyscallIoUringSetup(Native.SysIoUringSetup, RingEntries, parameters);
        if (fd < 0)
        {
            return (true, Marshal.GetLastPInvokeError());
        }

        _ = Native.Close((int)fd);
        return (false, 0);
    }
}
