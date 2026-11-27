namespace HttpAsm.Tests;

/// <summary>
/// httpasm_random (src/HttpAsm/random.asm), the octets TLS's randoms, ephemeral keys and ticket
/// keys come from: every length filled and nothing past it, outputs that differ from call to
/// call, and a histogram that looks uniform. The kernel's refusals (seccomp's EPERM, ENOSYS, a
/// filter answering no octets) and signals in the middle of a call are proven by
/// tests/native/random, which can install filters in children of its own.
/// </summary>
public sealed unsafe class RandomTests
{
    /// <summary>
    /// Every length from 0 to 300 octets, and some up to 1 MiB: filled (no 32-octet stretch keeps
    /// the pattern it was given, which random octets do with probability 2^-256), with nothing
    /// written past the end.
    /// </summary>
    [Fact]
    public void FillsEveryLengthAndNothingPast()
    {
        Platform.RequireLinuxX64();
        foreach (int length in Enumerable.Range(0, 301).Concat([4096, 65536, 1 << 20]))
        {
            byte[] buffer = new byte[length + 32];
            buffer.AsSpan().Fill(0xA5);
            fixed (byte* b = buffer)
            {
                Assert.Equal(0, Native.Random(b, (nuint)length));
            }

            for (int at = 0; at + 32 <= length; at += 32)
            {
                Assert.True(buffer.AsSpan(at, 32).IndexOfAnyExcept((byte)0xA5) >= 0, $"{length} octets: 32 at {at} never filled");
            }

            Assert.True(buffer.AsSpan(length).IndexOfAnyExcept((byte)0xA5) < 0, $"{length} octets: written past the end");
        }
    }

    /// <summary>
    /// 1,000 calls of 32 octets (a TLS random's length) are 1,000 different values, and 1 MiB's
    /// octet histogram stays below the chi-square bound that 99.99% of uniform draws meet (360 for
    /// 255 degrees of freedom).
    /// </summary>
    [Fact]
    public void LooksUniform()
    {
        Platform.RequireLinuxX64();
        var seen = new HashSet<string>();
        byte[] random = new byte[32];
        for (int i = 0; i < 1000; i++)
        {
            fixed (byte* r = random)
            {
                Assert.Equal(0, Native.Random(r, 32));
            }

            Assert.True(seen.Add(Convert.ToHexString(random)), "a 32-octet value came twice");
        }

        byte[] big = new byte[1 << 20];
        fixed (byte* b = big)
        {
            Assert.Equal(0, Native.Random(b, (nuint)big.Length));
        }

        long[] counts = new long[256];
        foreach (byte octet in big)
        {
            counts[octet]++;
        }

        double expected = big.Length / 256.0;
        double chi = counts.Sum(c => (c - expected) * (c - expected) / expected);
        Assert.True(chi < 360, $"chi-square {chi:F1} over 1 MiB");
    }
}
