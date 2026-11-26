/*
 * micro.c - single-thread measurements of libhttpasm.so's routines, at every CPU tier, with an
 * A/A control (docs/DESIGN.md section 2: a faster version stays only when a single-thread
 * measurement shows it pays).
 *
 * For each routine and input size, the tiers (and the baseline once more, as the A/A control)
 * are measured in turn, round after round, so drift hits all of them alike. A sample times a
 * batch of calls long enough (about 0.5 ms) for the clock to be exact.
 *
 * Which statistic: interference (other work on the host, a virtual CPU moved to a slower core,
 * which WSL2 on a hybrid Intel CPU does) only ever adds time, so the fastest of many short
 * samples is the stable estimate of a routine's own cost; medians on such a host swing by 2x
 * between two runs of the same code (2026-11-26, this harness's first run). The report gives
 * each tier's fastest sample per call (the ranking), its median (how noisy the run was), its
 * speed in octets per nanosecond at the fastest sample, and the baseline's fastest over its
 * own. A difference counts only when it is larger than the gap between the baseline and its
 * A/A twin.
 *
 * The process pins itself to one CPU (sched_setaffinity) and takes the library's tiers through
 * httpasm_cpu_limit, so every tier runs in the same process on the same core and inputs.
 *
 * Usage: micro [rounds, default 41]
 * Output: Markdown tables on stdout (benchmarks/README.md explains how to read them).
 * Build: tests/native/build.sh builds it too (cc -O2, against libhttpasm.so).
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "httpasm.h"

/* The tiers measured, the baseline first and again last as its A/A control. */
static const uint64_t caps[] = { HTTPASM_CPU_CAP_V1, HTTPASM_CPU_CAP_V2, HTTPASM_CPU_CAP_V3, HTTPASM_CPU_CAP_V4, HTTPASM_CPU_CAP_V1 };
static const char *const cap_names[] = { "v1", "v2", "v3", "v4", "v1 (A/A)" };
#define TIERS (sizeof caps / sizeof caps[0])
#define MAX_ROUNDS 101

/* A sink the compiler cannot see through, so no call is optimized away. */
static volatile size_t sink;

/* now_ns: CLOCK_MONOTONIC_RAW in nanoseconds (no NTP slewing inside a sample). */
static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* compare_doubles: qsort's comparison for ascending doubles: negative, 0 or positive as *a
 * is below, equal to or above *b. */
static int compare_doubles(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* A routine under measurement: runs it `calls` times on one input. */
typedef void (*batch_fn)(const uint8_t *input, size_t length, long calls);

/* field_value_scan_batch: httpasm_field_value_scan on input[0..length), `calls` times, its
 * results summed into the sink. */
static void field_value_scan_batch(const uint8_t *input, size_t length, long calls)
{
    size_t total = 0;
    for (long i = 0; i < calls; i++)
        total += httpasm_field_value_scan(input, length);
    sink = total;
}

/* measure: one routine on one input at every tier, `rounds` interleaved rounds; prints one
 * table row per tier. name labels the rows; run is the routine's batch; input, length is the
 * input. Leaves the last tier set. */
static void measure(const char *name, batch_fn run, const uint8_t *input, size_t length, int rounds)
{
    double samples[TIERS][MAX_ROUNDS];
    /* Size the batch: about 0.5 ms at the baseline, short enough that many samples run
     * undisturbed, long enough that the clock's resolution is a rounding error. */
    httpasm_cpu_limit(HTTPASM_CPU_CAP_V1);
    long calls = 256;
    for (;;) {
        double t0 = now_ns();
        run(input, length, calls);
        double dt = now_ns() - t0;
        if (dt > 5e5 || calls > (1L << 30))
            break;
        calls *= 2;
    }
    for (int r = 0; r < rounds; r++) {
        for (size_t t = 0; t < TIERS; t++) {
            httpasm_cpu_limit(caps[t]);
            run(input, length, calls / 16);         /* warm the version's code and branches */
            double t0 = now_ns();
            run(input, length, calls);
            samples[t][r] = (now_ns() - t0) / (double)calls;
        }
    }
    double base_best = 0;
    for (size_t t = 0; t < TIERS; t++) {
        qsort(samples[t], (size_t)rounds, sizeof(double), compare_doubles);
        double best = samples[t][0], median = samples[t][rounds / 2];
        if (t == 0)
            base_best = best;
        uint64_t features = httpasm_cpu_limit(caps[t]);
        printf("| %s | %zu | %s (%#llx) | %.2f | %.2f | %.2f | %.2fx |\n", name, length, cap_names[t],
               (unsigned long long)features, best, median, best > 0 ? (double)length / best : 0.0,
               best > 0 ? base_best / best : 0.0);
    }
}

/* main: pins the process to its current CPU, prints the table head and measures every
 * routine. Returns 0, or 2 on a usage error. */
int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 41;
    if (rounds < 1 || rounds > MAX_ROUNDS) {
        fprintf(stderr, "usage: micro [rounds 1-%d]\n", MAX_ROUNDS);
        return 2;
    }
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(sched_getcpu(), &one);
    if (sched_setaffinity(0, sizeof one, &one) != 0)
        perror("micro: sched_setaffinity (continuing unpinned)");

    printf("found %#llx; %d rounds; ns per call (fastest, median), octets per ns (fastest), and the\n"
           "baseline's fastest over this tier's\n\n", (unsigned long long)httpasm_cpu_found(), rounds);
    printf("| routine | octets | tier (features) | fastest ns | median ns | octets/ns | vs v1 |\n");
    printf("|---|---:|---|---:|---:|---:|---:|\n");

    /* Field values: every octet valid, so each call scans the whole value (the parsers' common
     * case). Lengths around the vector widths (16, 32, 64) and typical header sizes. */
    static uint8_t value[8192];
    for (size_t i = 0; i < sizeof value; i++)
        value[i] = (uint8_t)(0x20 + (i * 37) % 95);
    static const size_t lengths[] = { 8, 15, 16, 31, 32, 63, 64, 100, 256, 1024, 4096 };
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++)
        measure("field_value_scan", field_value_scan_batch, value, lengths[i], rounds);

    httpasm_cpu_limit(HTTPASM_CPU_ALL);
    return 0;
}
