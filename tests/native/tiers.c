/*
 * tiers.c - proves that every version of each multi-version routine in libhttpasm.so computes
 * the same results (docs/DESIGN.md section 2, "Fastest tier, every tier proven"; cpu.inc).
 *
 * Each input runs at every tier, switched with httpasm_cpu_limit, and the results must match
 * each other and an oracle written here from the RFC. Inputs sit against an inaccessible page,
 * so a version that reads past its input dies with SIGSEGV instead of passing.
 *
 * Why a C program as well as the .NET suite: the suite runs natively at every tier the CPU has
 * (tests/run-linux.sh), but Intel SDE, which emulates AVX-512 on CPUs without it, cannot run
 * the .NET runtime (it hangs). This program runs under SDE in seconds, so the AVX-512 versions
 * are proven equal to the baseline the suite proves, on any machine.
 *
 * Usage: tiers [random-inputs-per-routine]     (default 200000)
 * Exit status: 0 when every result matched; 1 on the first mismatch (printed with its input);
 * 2 on a usage or setup error. The tiers a run covers are the ones the CPU (or SDE) offers: the
 * output lists them, and tests/run-linux.sh checks the list says v4 under SDE.
 *
 * Build (tests/native/build.sh): cc -O2 -Wall -Wextra -Werror, against libhttpasm.so.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "httpasm.h"

/* The caps compared: each level's own. A level the CPU lacks collapses to the best one below
 * (the library's closure), which simply repeats that tier. */
static const uint64_t caps[] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_CAP_V2, HTTPASM_CPU_CAP_V3, HTTPASM_CPU_CAP_V4 };
static const char *const cap_names[] = { "v1", "v2", "v3", "v4" };
#define TIERS (sizeof caps / sizeof caps[0])

enum { PAGE = 4096 };

/* One readable page, then an inaccessible one: page_end - n is where an n-octet input starts. */
static uint8_t *page_end;

/* The state of a small deterministic generator (xorshift64*), seeded fixed, so a failure
 * reproduces run after run. */
static uint64_t rng_state = 0x9E3779B97F4A7C15u;
/* rng: the generator's next 64 pseudo-random bits. */
static uint64_t rng(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Du;
}

/* dump: prints an input as hex on stderr, for a failure report.
 *   what  a label for the line; p, n  the input. */
static void dump(const char *what, const uint8_t *p, size_t n)
{
    fprintf(stderr, "%s (%zu octets): ", what, n);
    for (size_t i = 0; i < n; i++)
        fprintf(stderr, "%02X", p[i]);
    fputc('\n', stderr);
}

/* ---- httpasm_field_value_scan ---------------------------------------------------------- */

/* field_value_oracle: the oracle, from RFC 9110 section 5.5.
 *   p, n  the value. Returns the index of its first CTL other than HTAB (0x00-0x08,
 *   0x0A-0x1F, 0x7F), or n when it has none. */
static size_t field_value_oracle(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if ((p[i] < 0x20 && p[i] != 0x09) || p[i] == 0x7F)
            return i;
    return n;
}

/* field_value_check: runs one value at every tier, copied against the guard page first.
 *   value, n  the value. Returns 0 when every tier agrees with the oracle; 1, after
 *   reporting the tier, both results and the value, otherwise. Leaves the last tier set. */
static int field_value_check(const uint8_t *value, size_t n)
{
    uint8_t *p = page_end - n;
    memcpy(p, value, n);
    size_t expected = field_value_oracle(p, n);
    for (size_t t = 0; t < TIERS; t++) {
        uint64_t features = httpasm_cpu_limit(caps[t]);
        size_t actual = httpasm_field_value_scan(p, n);
        if (actual != expected) {
            fprintf(stderr, "httpasm_field_value_scan at %s (features %#llx): expected %zu, got %zu\n",
                    cap_names[t], (unsigned long long)features, expected, actual);
            dump("value", p, n);
            return 1;
        }
    }
    return 0;
}

/* field_value_valid: fills v[0..n) with octets a field value may hold (field-vchar, SP,
 * HTAB), drawn from the whole allowed range. */
static void field_value_valid(uint8_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned pick = (unsigned)(rng() % 224);        /* HTAB, 0x20-0x7E, 0x80-0xFF */
        v[i] = pick == 0 ? 0x09 : (uint8_t)(pick < 96 ? 0x1F + pick : pick + 32);
    }
}

/* field_value_scan_tiers: httpasm_field_value_scan's inputs: every length up to 300 valid and
 * with a forbidden octet at every position, every octet value at the end of a few lengths,
 * then `randoms` random values up to 1023 octets. Returns 0 when every one agreed at every
 * tier, 1 at the first that did not. */
static int field_value_scan_tiers(long randoms)
{
    static uint8_t v[PAGE];
    static const uint8_t forbidden[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x7F };
    long checked = 0;

    /* Every length up to 300 (past four 64-octet vectors), valid, and with one forbidden octet
     * at every position; then every octet value as the last of a few lengths. */
    for (size_t n = 0; n <= 300; n++) {
        field_value_valid(v, n);
        if (field_value_check(v, n))
            return 1;
        checked++;
        for (size_t at = 0; at < n; at++) {
            field_value_valid(v, n);
            v[at] = forbidden[(at + n) % sizeof forbidden];
            if (field_value_check(v, n))
                return 1;
            checked++;
        }
    }
    for (unsigned octet = 0; octet < 256; octet++) {
        for (size_t n = 1; n <= 200; n += 33) {
            field_value_valid(v, n);
            v[n - 1] = (uint8_t)octet;
            if (field_value_check(v, n))
                return 1;
            checked++;
        }
    }
    /* Random values: mostly valid, with forbidden octets sprinkled at random rates. */
    for (long i = 0; i < randoms; i++) {
        size_t n = (size_t)(rng() % 1024);
        field_value_valid(v, n);
        unsigned rate = (unsigned)(rng() % 5);
        for (size_t k = 0; k < n; k++)
            if (rate && rng() % (rate * 97) == 0)
                v[k] = forbidden[rng() % sizeof forbidden];
        if (field_value_check(v, n))
            return 1;
        checked++;
    }
    printf("httpasm_field_value_scan: %ld inputs, every tier agrees with the oracle\n", checked);
    return 0;
}

/* main: sets up the guard page, prints the tiers this CPU (or SDE) gives, and runs every
 * routine's comparison. Returns 0, 1 on a mismatch, or 2 on a usage or setup error. */
int main(int argc, char **argv)
{
    long randoms = argc > 1 ? strtol(argv[1], NULL, 10) : 200000;
    if (randoms < 0) {
        fprintf(stderr, "usage: tiers [random-inputs-per-routine]\n");
        return 2;
    }

    uint8_t *map = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED || mprotect(map + PAGE, PAGE, PROT_NONE) != 0) {
        perror("tiers: guard page");
        return 2;
    }
    page_end = map + PAGE;

    uint64_t start_features = httpasm_cpu_features();
    printf("found %#llx; tiers:", (unsigned long long)httpasm_cpu_found());
    for (size_t t = 0; t < TIERS; t++)
        printf(" %s=%#llx", cap_names[t], (unsigned long long)httpasm_cpu_limit(caps[t]));
    printf("\n");

    int failed = field_value_scan_tiers(randoms);

    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    (void)start_features;
    return failed;
}
