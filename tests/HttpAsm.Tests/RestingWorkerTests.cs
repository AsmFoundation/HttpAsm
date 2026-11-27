using System.Diagnostics;
using System.Text;

namespace HttpAsm.Tests;

/// <summary>
/// A worker that can do nothing for a connection rests: its wait returns only for something it
/// can act on. Measured as this test process's CPU time over a quiet second, so these tests run
/// alone (<see cref="SerialCollection"/>): any other test's work would be counted too.
/// </summary>
[Collection(nameof(SerialCollection))]
public sealed class RestingWorkerTests
{
    /// <summary>
    /// The most CPU time the process may use over the quiet second. A worker that spins uses all
    /// of it (0.98 s was measured); the test host's own threads use a few milliseconds.
    /// </summary>
    private static readonly TimeSpan QuietCpu = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// A client asks for an 8 MiB answer, more than loopback's socket buffers and
    /// HA_OUTPUT_HIGH together take, so the server's processing stops for the back-pressure;
    /// pipelines small requests behind it; half-closes; and reads nothing for a second. Two
    /// spins were found here (2026-11-26, the coverage gate's walk) and both are gone:
    /// <list type="bullet">
    /// <item>epoll: EPOLLRDHUP was asked for while output waited. With 20 KiB of requests
    /// behind the large one, the 16 KiB input is full and the FIN sits behind input the worker
    /// cannot take yet, so the level-triggered hang-up returned every wait at once. Now a
    /// connection whose output waits asks for EPOLLOUT alone.</item>
    /// <item>io_uring: kernels before upstream commit 74c1f1048e44 (2026-10-29) add POLLRDHUP to
    /// every poll, a poll for room included, so once the peer half-closed, the one-shot poll
    /// for room completed at once each time it was armed, whatever the input held (2,000
    /// octets of requests spun too). Now a writer's poll is multishot.</item>
    /// </list>
    /// Either way the worker had used a whole core until the idle timeout. Now the process uses
    /// almost no CPU over the quiet second; then the client reads, and every answer arrives
    /// whole and in order before the server closes the connection.
    /// </summary>
    /// <param name="pipelined">The octets of small requests behind the large one: past the
    /// 16 KiB input (20 KiB), or within it (2,000: the FIN can be read; only io_uring spun).</param>
    [Theory]
    [InlineData(20 << 10)]
    [InlineData(2000)]
    [Requirement("RFC9112-9.5-4", "RFC9112-9.5-2#2", "RFC9112-9.3.2-1#3")]
    public void RestsWhileAHalfClosedClientReadsNothingUnderBackPressure(int pipelined)
    {
        Platform.RequireLinuxX64();
        byte[] big = new byte[8 << 20];
        new Random(8).NextBytes(big);
        using var server = new TestServer(x => x.Respond(200, x.Target == "/big" ? big : Encoding.ASCII.GetBytes("small")), workers: 1);
        using var c = new RawConnection(server.Port, timeoutMs: 20000, receiveBuffer: 16 << 10);
        var requests = new StringBuilder("GET /big HTTP/1.1\r\nHost: t\r\n\r\n");
        int smalls = 0;
        while (requests.Length < pipelined)
        {
            requests.Append("GET /s HTTP/1.1\r\nHost: t\r\n\r\n");
            smalls++;
        }

        c.Send(requests.ToString());
        Pause.AtLeast(100);                      // the server takes what it can, then the back-pressure
        c.ShutdownSend();
        Pause.AtLeast(100);                      // the FIN arrives; a worker that spins starts now

        // The whole process's CPU: the server's worker is a thread of this process.
        TimeSpan before = Process.GetCurrentProcess().TotalProcessorTime;
        Pause.AtLeast(1000);
        TimeSpan used = Process.GetCurrentProcess().TotalProcessorTime - before;
        Assert.True(used < QuietCpu, $"{used.TotalMilliseconds:F0} ms of CPU over a second in which nothing could be done");

        RawResponse first = c.ReadResponse();
        Assert.True(big.AsSpan().SequenceEqual(first.Body), "the large answer");
        for (int i = 0; i < smalls; i++)
        {
            Assert.Equal("small", c.ReadResponse().Text);
        }

        Assert.True(c.ServerClosed(), "the server closes once everything was answered");
    }
}
