namespace HttpAsm.Tests;

/// <summary>
/// Sleeps that last at least their length on the server's own clock. Every pause in the tests
/// goes through here instead of Thread.Sleep, which can come back early: on Linux, .NET's
/// Thread.Sleep is an alertable wait in the runtime's PAL, and under load it returned after
/// 1,259 ms of a requested 3,000 (2026-11-27, a full suite run on io_uring; CLOCK_MONOTONIC and
/// CLOCK_MONOTONIC_COARSE both said 1.26 s, and the server's glitch budget, refilled by the time
/// that really passed, then cut a client that the test expected to pass:
/// Http2FrameTests.RefillsTheGlitchBudgetWithTime failed about once in ten suite runs).
/// </summary>
/// <remarks>
/// The measure is <see cref="Environment.TickCount64"/>, which .NET reads from
/// CLOCK_MONOTONIC_COARSE on Linux: the same clock the server's workers read for deadlines and
/// budgets (monotonic_ms in server.asm). So a pause of N milliseconds here is at least N of the
/// server's milliseconds, whatever the sleep itself does. Task.Delay needs no such care: its
/// timers fire by that same clock, late rather than early.
/// </remarks>
internal static class Pause
{
    /// <summary>
    /// Sleeps until <see cref="Environment.TickCount64"/> has advanced by at least
    /// <paramref name="milliseconds"/>, sleeping again for what is left whenever a sleep comes back
    /// early.
    /// </summary>
    /// <param name="milliseconds">The least pause, in milliseconds (0 or less returns at once).</param>
    public static void AtLeast(int milliseconds)
    {
        long end = Environment.TickCount64 + milliseconds;
        for (long left = milliseconds; left > 0; left = end - Environment.TickCount64)
        {
            Thread.Sleep((int)left);
        }
    }
}
