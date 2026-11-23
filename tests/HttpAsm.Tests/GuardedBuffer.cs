using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>
/// One readable page followed by an inaccessible one: a value placed at the end of the first
/// page lets a test prove that a function never reads past the value. A read past the end
/// faults and kills the test process, instead of passing silently.
/// </summary>
/// <remarks>Linux only (mmap and mprotect). Dispose unmaps both pages.</remarks>
internal sealed unsafe class GuardedBuffer : IDisposable
{
    /// <summary>The page size these tests assume (x86-64 Linux's base page).</summary>
    public const int PageSize = 4096;

    /// <summary>The first page's address; the guard page follows it.</summary>
    private readonly nint mapping;

    /// <summary>Maps the two pages and makes the second one inaccessible.</summary>
    /// <exception cref="InvalidOperationException">mmap or mprotect failed (the errno is in the message).</exception>
    public GuardedBuffer()
    {
        mapping = Native.Mmap(0, 2 * PageSize, Native.ProtReadWrite, Native.MapPrivateAnonymous, -1, 0);
        if (mapping == -1)
        {
            throw new InvalidOperationException($"mmap failed: errno {Marshal.GetLastPInvokeError()}");
        }

        if (Native.Mprotect(mapping + PageSize, PageSize, Native.ProtNone) != 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            _ = Native.Munmap(mapping, 2 * PageSize); // best effort: the failure below is what matters
            throw new InvalidOperationException($"mprotect failed: errno {errno}");
        }
    }

    /// <summary>Copies a value so that its last octet is the readable page's last octet.</summary>
    /// <param name="value">At most a page of octets.</param>
    /// <returns>The value's first octet: the guard page starts right after its last one.</returns>
    /// <exception cref="ArgumentException">The value is longer than a page.</exception>
    public byte* AtPageEnd(ReadOnlySpan<byte> value)
    {
        if (value.Length > PageSize)
        {
            throw new ArgumentException("at most one page", nameof(value));
        }

        byte* start = (byte*)(mapping + PageSize - value.Length);
        value.CopyTo(new Span<byte>(start, value.Length));
        return start;
    }

    /// <summary>Unmaps both pages.</summary>
    public void Dispose() => _ = Native.Munmap(mapping, 2 * PageSize);
}
