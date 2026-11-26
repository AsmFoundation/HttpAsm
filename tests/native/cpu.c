/*
 * cpu.c - HttpAsm's CPU detection (cpu/cpu.asm, ha_cpu_detect) checked against an independent
 * reading of the same CPUID leaves and XGETBV, on this CPU and, under Intel SDE, on the CPU
 * models SDE emulates (tests/run-linux.sh runs it under several), so every branch of the
 * detection meets a CPU that takes it.
 *
 * The oracle below applies the rules docs/DESIGN.md section 3 and cpu.inc document, written apart
 * from the assembly: a level counts when every feature of it and of the levels below is present
 * and the OS saves the registers it needs (XCR0: YMM for v3, ZMM and the opmasks for v4);
 * AES-NI, PCLMULQDQ, SHA, GFNI, BMI2 and ADX count at any level; VAES, VPCLMULQDQ and SHA512 need
 * v2 and the YMM state; IFMA, VBMI and VBMI2 need v4.
 *
 * Usage: cpu [level]   level (v1-v4) is the x86-64 level the CPU (or SDE's model) must reach,
 *                      exactly: an anchor beyond the oracle's agreement.
 * Exit status: 0 when the library's bits equal the oracle's (and the level is the one named);
 * 1 otherwise, with both printed; 2 for a bad argument.
 */
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "httpasm.h"

/* xcr0: XGETBV(0)'s low half (the state the OS saves). Only callable with OSXSAVE set. */
static uint32_t xcr0(void)
{
    uint32_t eax, edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return eax;
}

/* has: whether every bit of mask is set in value. */
static int has(uint32_t value, uint32_t mask)
{
    return (value & mask) == mask;
}

/* expected: the HTTPASM_CPU_* bits this CPU and OS offer, by the documented rules. */
static uint64_t expected(void)
{
    unsigned a, b, c, d;
    uint32_t l1c = 0, l7b = 0, l7c = 0, l71a = 0, lxc = 0, x = 0;
    unsigned max = __get_cpuid_max(0, NULL);
    __cpuid(1, a, b, c, d);
    l1c = c;
    if (max >= 7) {
        __cpuid_count(7, 0, a, b, c, d);
        l7b = b;
        l7c = c;
        if (a >= 1) {
            __cpuid_count(7, 1, a, b, c, d);
            l71a = a;
        }
    }
    if (__get_cpuid_max(0x80000000, NULL) >= 0x80000001) {
        __cpuid(0x80000001, a, b, c, d);
        lxc = c;
    }
    if (l1c & bit_OSXSAVE)
        x = xcr0();

    uint64_t f = 0;
    if (l1c & bit_AES)
        f |= HTTPASM_CPU_AESNI;
    if (l1c & bit_PCLMUL)
        f |= HTTPASM_CPU_CLMUL;
    if (l7b & bit_SHA)
        f |= HTTPASM_CPU_SHA;
    if (l7c & bit_GFNI)
        f |= HTTPASM_CPU_GFNI;
    if (l7b & bit_BMI2)
        f |= HTTPASM_CPU_BMI2;
    if (l7b & bit_ADX)
        f |= HTTPASM_CPU_ADX;

    /* v2: SSE3, SSSE3, CX16, SSE4.1, SSE4.2, POPCNT, LAHF/SAHF (the psABI's list). */
    if (!has(l1c, bit_SSE3 | bit_SSSE3 | bit_CMPXCHG16B | bit_SSE4_1 | bit_SSE4_2 | bit_POPCNT) || !(lxc & bit_LAHF_LM))
        return f;
    f |= HTTPASM_CPU_V2;
    if (!has(x, (1u << 1) | (1u << 2)))
        return f;                            /* no YMM state: nothing wider than SSE */
    if (l7c & bit_VAES)
        f |= HTTPASM_CPU_VAES;
    if (l7c & bit_VPCLMULQDQ)
        f |= HTTPASM_CPU_VCLMUL;
    if (l71a & 1u)                           /* CPUID.(7,1):EAX[0]: SHA512 */
        f |= HTTPASM_CPU_SHA512;
    /* v3: AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, OSXSAVE. */
    if (!has(l1c, bit_FMA | bit_MOVBE | bit_AVX | bit_F16C | bit_OSXSAVE) || !has(l7b, bit_BMI | bit_AVX2 | bit_BMI2) || !(lxc & bit_LZCNT))
        return f;
    f |= HTTPASM_CPU_V3;
    /* v4: AVX-512 F, DQ, CD, BW, VL, and the opmask and ZMM state. */
    if (!has(x, (1u << 5) | (1u << 6) | (1u << 7)) || !has(l7b, bit_AVX512F | bit_AVX512DQ | bit_AVX512CD | bit_AVX512BW | bit_AVX512VL))
        return f;
    f |= HTTPASM_CPU_V4;
    if (l7b & bit_AVX512IFMA)
        f |= HTTPASM_CPU_IFMA;
    if (l7c & bit_AVX512VBMI)
        f |= HTTPASM_CPU_VBMI;
    if (l7c & bit_AVX512VBMI2)
        f |= HTTPASM_CPU_VBMI2;
    return f;
}

/* level: the highest x86-64 level among the bits: 1 to 4. */
static int level(uint64_t bits)
{
    return bits & HTTPASM_CPU_V4 ? 4 : bits & HTTPASM_CPU_V3 ? 3 : bits & HTTPASM_CPU_V2 ? 2 : 1;
}

/* main: compares, and checks the level named. */
int main(int argc, char **argv)
{
    int want = 0;
    if (argc > 1) {
        if (strlen(argv[1]) != 2 || argv[1][0] != 'v' || argv[1][1] < '1' || argv[1][1] > '4') {
            fprintf(stderr, "usage: cpu [v1|v2|v3|v4]\n");
            return 2;
        }
        want = argv[1][1] - '0';
    }
    uint64_t found = httpasm_cpu_found(), oracle = expected();
    printf("cpu: the library found %#llx, CPUID and XGETBV say %#llx (v%d)\n", (unsigned long long)found, (unsigned long long)oracle,
           level(oracle));
    if (found != oracle) {
        fprintf(stderr, "cpu: the detection differs from the oracle by %#llx\n", (unsigned long long)(found ^ oracle));
        return 1;
    }
    if (want != 0 && level(found) != want) {
        fprintf(stderr, "cpu: the CPU should reach v%d exactly, the detection says v%d\n", want, level(found));
        return 1;
    }
    return 0;
}
