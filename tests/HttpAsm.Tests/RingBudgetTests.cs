namespace HttpAsm.Tests;

/// <summary>
/// The tests that change process-wide state (a resource limit), and so must not run beside any
/// other test: xunit runs this collection alone, after every parallel collection has finished.
/// </summary>
[CollectionDefinition(nameof(SerialCollection), DisableParallelization = true)]
public sealed class SerialCollection;

/// <summary>
/// io_uring's memory budget. Linux 6.14 and later charge every page of a worker's ring to the
/// user's RLIMIT_MEMLOCK (uring.asm, HA_RING_ENTRIES), and a worker that asked for io_uring and
/// whose ring the kernel refuses opens epoll instead and serves all the same.
/// </summary>
[Collection(nameof(SerialCollection))]
public sealed class RingBudgetTests
{
    /// <summary>CAP_IPC_LOCK's bit in /proc/self/status's CapEff: a process holding it is never charged.</summary>
    private const int CapIpcLock = 14;

    /// <summary>
    /// With RLIMIT_MEMLOCK at 0 every ring is refused (io_uring_setup answers ENOMEM), so every
    /// worker of a server asking for io_uring falls back to epoll and the server serves; with
    /// the limit back, the next start gets its rings again. This is the path a server takes
    /// past the budget, and the only test in which the kernel itself refuses io_uring.
    /// </summary>
    /// <remarks>
    /// Runs where the kernel would charge this process: Linux 6.14 or later (WSL2's 5.15 skips
    /// it; the CI runner's 7.0 runs it), io_uring allowed (Docker's seccomp refuses it, and with
    /// HTTPASM_REQUIRE_URING=1 that fails instead), and no CAP_IPC_LOCK. It runs the same in
    /// both test runs: its server asks for io_uring itself. A limit of 0 refuses any charge
    /// whatever the user's other rings hold, which keeps the test deterministic; the limit is
    /// process-wide, hence <see cref="SerialCollection"/>, and it is put back even when an
    /// assertion fails.
    /// </remarks>
    [Fact]
    public void ServesOnEpollWhenTheKernelRefusesTheRings()
    {
        Platform.RequireLinuxX64();
        if (!Platform.KernelAtLeast(6, 14))
        {
            Assert.Skip($"needs Linux 6.14 or later, which charges rings to RLIMIT_MEMLOCK ({Platform.IoUringBudget()})");
        }

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
            Assert.Equal(0, server.Start());
            Assert.Equal(ServerIo.Epoll, server.Io);    // every worker: Io counts them all
            for (int i = 0; i < 4; i++)
            {
                // Several connections, spread over the workers by SO_REUSEPORT: each is
                // served on epoll, whichever worker takes it.
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
}
