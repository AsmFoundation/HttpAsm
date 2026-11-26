/*
 * fuzz.h - what HttpAsm's fuzzers share (tests/fuzz/<name>.c; docs/DESIGN.md section 2, "Tested from
 * every angle": coverage-guided fuzzing of every parser).
 *
 * Each fuzzer is a libFuzzer target linked with the Fuzz configuration's objects: the core's,
 * and libhttpasm.so's where it needs them. Their markers (tests/coverage/instrument.cs) sit in
 * libFuzzer's __libfuzzer_extra_counters section, so the fuzzer steers by the assembly's own
 * blocks and branch edges, not only by the harness's C code.
 *
 * Every input runs at every CPU tier (httpasm_cpu_limit), and every tier must produce the same
 * results: the fuzzers are tier-differential tests as well. Inputs sit against an inaccessible
 * page, so a read past an input is a crash, not a silent success.
 */
#ifndef HTTPASM_FUZZ_H
#define HTTPASM_FUZZ_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "httpasm.h"

/* The tiers every input runs at: each x86-64 level's cap. One the CPU lacks collapses to the best
 * one below it (the library's closure), which only repeats that tier. */
static const uint64_t fuzz_caps[] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_CAP_V2, HTTPASM_CPU_CAP_V3, HTTPASM_CPU_CAP_V4 };
#define FUZZ_TIERS (sizeof fuzz_caps / sizeof fuzz_caps[0])

/* The largest input a fuzzer takes (run.sh passes -max_len of this size); a larger one is skipped. */
enum { FUZZ_MAX = 64 * 1024, FUZZ_PAGE = 4096 };

/* fuzz_place: copies an input so that its last octet is the last readable octet before an
 * inaccessible page, and returns where it starts. The mapping is made once and reused.
 *   data, n  the input; n <= FUZZ_MAX. Aborts if the pages cannot be mapped (no fuzzing then). */
static inline uint8_t *fuzz_place(const uint8_t *data, size_t n)
{
    static uint8_t *end;
    if (end == NULL) {
        size_t pages = FUZZ_MAX / FUZZ_PAGE + 1;
        uint8_t *map = mmap(NULL, (pages + 1) * FUZZ_PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map == MAP_FAILED || mprotect(map + pages * FUZZ_PAGE, FUZZ_PAGE, PROT_NONE) != 0)
            abort();
        end = map + pages * FUZZ_PAGE;
    }
    uint8_t *p = end - n;
    if (n != 0)
        memcpy(p, data, n);
    return p;
}

/* FUZZ_CHECK: an invariant every input must keep. When it does not, the message goes to stderr
 * and the process aborts, which libFuzzer records as a crash with the input that caused it. */
#define FUZZ_CHECK(condition, ...)                                                                \
    do {                                                                                          \
        if (!(condition)) {                                                                       \
            fprintf(stderr, "fuzz: %s:%d: check failed: %s: ", __FILE__, __LINE__, #condition);  \
            fprintf(stderr, __VA_ARGS__);                                                         \
            fputc('\n', stderr);                                                                  \
            abort();                                                                              \
        }                                                                                         \
    } while (0)

/* fuzz_within: whether [p, p + n) lies inside [base, base + size): a pointer a parser returned
 * into its input must never point outside it. A NULL p with n == 0 is within (an absent part). */
static inline int fuzz_within(const uint8_t *p, size_t n, const uint8_t *base, size_t size)
{
    if (p == NULL)
        return n == 0;
    return p >= base && n <= size && (size_t)(p - base) <= size - n;
}

#endif
