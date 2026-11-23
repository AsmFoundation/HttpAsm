using System.Runtime.InteropServices;

namespace HttpAsm.Tests;

/// <summary>
/// libhttpasm.so's C ABI (src/HttpAsm/include/httpasm.h), and the few C library calls the tests
/// need to build guarded buffers.
/// </summary>
/// <remarks>
/// The bare name "httpasm" makes .NET probe libhttpasm.so, which AsmFoundation.Sdk puts under
/// runtimes/linux-x64/native/ and lists in the test app's deps.json. Every entry point here is
/// a leaf that neither blocks nor calls back, so the GC transition could be suppressed. It is
/// not suppressed: these tests measure nothing, and the default is the safe one.
/// </remarks>
internal static unsafe partial class Native
{
    /// <summary>The library's name, as [LibraryImport] probes it.</summary>
    private const string Library = "httpasm";

    /// <summary>glibc by its soname: plain "libc" would make .NET probe libc.so, a linker script.</summary>
    private const string Libc = "libc.so.6";

    /// <summary>mmap's PROT_NONE: the page cannot be touched.</summary>
    internal const int ProtNone = 0;

    /// <summary>mmap's PROT_READ | PROT_WRITE.</summary>
    internal const int ProtReadWrite = 0x1 | 0x2;

    /// <summary>mmap's MAP_PRIVATE | MAP_ANONYMOUS on Linux x64.</summary>
    internal const int MapPrivateAnonymous = 0x02 | 0x20;

    /// <summary>uint32_t httpasm_abi_version(void).</summary>
    /// <returns>The loaded library's ABI version; 0 before the first release.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_abi_version")]
    internal static partial uint AbiVersion();

    /// <summary>size_t httpasm_token_length(const uint8_t *p, size_t n).</summary>
    /// <param name="p">The octets.</param>
    /// <param name="n">How many there are.</param>
    /// <returns>The number of leading octets that are tchar; n when all are.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_token_length")]
    internal static partial nuint TokenLength(byte* p, nuint n);

    /// <summary>size_t httpasm_field_value_scan(const uint8_t *p, size_t n).</summary>
    /// <param name="p">The octets.</param>
    /// <param name="n">How many there are.</param>
    /// <returns>The index of the first octet a field value may not hold; n when none.</returns>
    [LibraryImport(Library, EntryPoint = "httpasm_field_value_scan")]
    internal static partial nuint FieldValueScan(byte* p, nuint n);

    /// <summary>void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset).</summary>
    /// <param name="addr">A placement hint; zero lets the kernel choose.</param>
    /// <param name="length">The mapping's size in bytes.</param>
    /// <param name="prot">PROT_* bits.</param>
    /// <param name="flags">MAP_* bits.</param>
    /// <param name="fd">-1 for an anonymous mapping.</param>
    /// <param name="offset">0 for an anonymous mapping.</param>
    /// <returns>The mapping's address, or -1 (MAP_FAILED) with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "mmap", SetLastError = true)]
    internal static partial nint Mmap(nint addr, nuint length, int prot, int flags, int fd, nint offset);

    /// <summary>int mprotect(void *addr, size_t len, int prot).</summary>
    /// <param name="addr">A page-aligned address.</param>
    /// <param name="length">The range's size in bytes.</param>
    /// <param name="prot">PROT_* bits.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "mprotect", SetLastError = true)]
    internal static partial int Mprotect(nint addr, nuint length, int prot);

    /// <summary>int munmap(void *addr, size_t length).</summary>
    /// <param name="addr">The mapping's address.</param>
    /// <param name="length">Its size in bytes.</param>
    /// <returns>0, or -1 with errno set.</returns>
    [LibraryImport(Libc, EntryPoint = "munmap", SetLastError = true)]
    internal static partial int Munmap(nint addr, nuint length);
}
