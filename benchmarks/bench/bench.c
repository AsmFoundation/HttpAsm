/*
 * bench.c - the runner of HttpAsm's benchmark framework (bench.h describes the pieces;
 * benchmarks/README.md the method and how to read a report).
 *
 * Usage: bench [options]
 *   --suite NAME        tiers, parsers, rivals, or all (default all)
 *   --filter GLOB       only the cases whose "suite/name/input" matches (fnmatch), e.g.
 *                       'tiers/field_value_scan/64*' or '*browser*'
 *   --rounds N          rounds per case (default 41; --quick: 11)
 *   --sample-us N       the batch length a sample aims at, in microseconds (default 500;
 *                       --quick: 200)
 *   --quick             the development loop's settings: fewer, shorter samples
 *   --build NAME=PATH   one more libhttpasm.so to measure beside the tree's ("current"), in
 *                       this process, interleaved: an A/B of a change (repeatable)
 *   --only-builds       with --build: no default "current" build
 *   --seed N            the order shuffle's seed (default: from the clock; recorded)
 *   --cpu N             the CPU to pin to (default: the one this process starts on)
 *   --json PATH         the whole record (every sample, the host, the builds) as JSON
 *   --meta KEY=VALUE    a fact to record with the run (the commit, the configuration)
 *   --list              the cases that would run, one per line, and nothing measured
 *   --icount SDE64      instead of timing: every selected case's contenders' instructions per
 *                       call, exact, counted by Intel SDE (the path to its sde64), one SDE
 *                       process per contender running --once
 *   --sde-cpu MODEL     the CPU SDE presents with --icount (an sde64 chip option without its
 *                       dash: adl, spr, ...); default: spr when this CPU has AVX-512, else adl,
 *                       so no tier runs that this machine could not (AVX-512 is neither timed
 *                       nor counted where it is absent: the owner's rule, 2026-11-26)
 *   --once CONTENDER    the child's side of --icount: runs CONTENDER's batch of --calls calls
 *                       once, on every selected case, between SSC marks 0x111 (start) and
 *                       0x222 (stop), untimed
 *   --calls N           the batch --once runs (default 10000)
 * Exit status: 0, 1 when a build cannot be loaded or a case cannot run, 2 on a usage error.
 *
 * The method, briefly (README.md says why): every contender of a case runs once per round, in
 * a fresh random order, its sample a batch of `calls` calls timed with CLOCK_MONOTONIC_RAW
 * after a short warm-up (a sixteenth of the batch) at its tier; the first contender runs twice,
 * the second time as the A/A control. The verdict on each contender is paired: the median of
 * its per-round ratios to the first contender, with a bootstrap 95% interval, judged against
 * the A/A twin's interval (print_case). The record (--json) keeps every raw sample.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fnmatch.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bench.h"

volatile size_t bench_sink;

/* The limits of the tables below: enough for every suite with two builds; bench_add and the
 * option parser refuse past them. */
#define BENCH_MAX_CASES 512
#define BENCH_MAX_BUILDS 4
#define BENCH_MAX_CONTENDERS 24
#define BENCH_MAX_ROUNDS 401
#define BENCH_MAX_META 16

static bench_case cases[BENCH_MAX_CASES];
static size_t case_count;
static bench_build builds[BENCH_MAX_BUILDS];
static size_t build_count;

/* The run's settings, from the command line. */
static struct {
    const char *suite;
    const char *filter;
    int rounds;
    long sample_ns;
    int quick;
    int only_builds;
    uint64_t seed;
    int cpu;
    const char *json;
    const char *meta_key[BENCH_MAX_META];
    const char *meta_value[BENCH_MAX_META];
    int meta_count;
    int list;
    const char *once;
    long once_calls;
    const char *icount;
    const char *sde_cpu;
    const char *build_args[2 * BENCH_MAX_BUILDS + 1];   /* --build NAME=PATH pairs and --only-builds, for --icount's children */
    int build_arg_count;
} opt = { "all", "*", 0, 0, 0, 0, 0, -1, NULL, { 0 }, { 0 }, 0, 0, NULL, 10000, NULL, NULL, { 0 }, 0 };

/* A tier: the row's name and httpasm_cpu_limit's argument. "best" is everything the CPU has. */
typedef struct tier {
    const char *name;
    uint64_t cap;
} tier;

static const tier all_tiers[] = {
    { "v1", HTTPASM_CPU_CAP_V1 },
    { "v2", HTTPASM_CPU_CAP_V2 },
    { "v3", HTTPASM_CPU_CAP_V3 },
    { "v4", HTTPASM_CPU_CAP_V4 },
};
static const tier best_v1_tiers[] = {
    { "best", HTTPASM_CPU_ALL },
    { "v1", HTTPASM_CPU_CAP_V1 },
};

/* contender: one row of a case: its label, its build (NULL for a rival) and tier, its batch,
 * the features in effect at its tier (httpasm_cpu_limit's answer, recorded so a report can show
 * that "v4" ran v3's code on a CPU without AVX-512), and whose A/A control it is (-1: none). */
typedef struct contender {
    char name[64];
    const bench_build *build;
    const char *tier_name;
    uint64_t cap;
    uint64_t features;
    bench_batch run;
    int control_of;
} contender;

/* now_ns: CLOCK_MONOTONIC_RAW in nanoseconds (the raw clock: no NTP slewing inside a sample). */
static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* next_random: xorshift64*, the order shuffle's generator; state must not be 0. Returns the
 * next value. Statistical quality is plenty for shuffling a dozen rows. */
static uint64_t next_random(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* compare_doubles: qsort's ascending comparison: negative, 0 or positive as *a is below, equal
 * to or above *b. */
static int compare_doubles(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* bench_add: see bench.h. */
void bench_add(const bench_case *c)
{
    if (case_count == BENCH_MAX_CASES) {
        fprintf(stderr, "bench: more than %d cases: raise BENCH_MAX_CASES\n", BENCH_MAX_CASES);
        exit(2);
    }
    cases[case_count++] = *c;
}

/* bench_first_build: see bench.h. */
const bench_build *bench_first_build(void)
{
    return build_count > 0 ? &builds[0] : NULL;
}

/* The per-build states bench_state hands out: (build, key) pairs and their memory, never freed
 * (they live as long as the run). */
static struct {
    const bench_build *build;
    const void *key;
    void *memory;
} states[64];
static size_t state_count;

/* bench_state: see bench.h. */
void *bench_state(const bench_build *build, const void *key, size_t size, bench_state_init init)
{
    for (size_t i = 0; i < state_count; i++) {
        if (states[i].build == build && states[i].key == key)
            return states[i].memory;
    }
    if (state_count == sizeof states / sizeof states[0])
        return NULL;
    void *memory = calloc(1, size);
    if (memory == NULL)
        return NULL;
    if (init(build, memory, size) != 0) {
        free(memory);
        return NULL;
    }
    states[state_count].build = build;
    states[state_count].key = key;
    states[state_count++].memory = memory;
    return memory;
}

/* load_build: loads one libhttpasm.so as a build and resolves its API table.
 *   name  the build's name ("current", or --build's NAME); path  the file (see bench_build).
 * Returns 0, or -1 with the reason on stderr (the file cannot be loaded, or lacks a function
 * the cases call: an older build without a routine cannot run its cases). RTLD_LOCAL keeps each
 * build's symbols to itself, so two builds with the same exported names never cross-bind;
 * RTLD_NOW resolves everything at once, so a missing symbol fails here and not mid-run. */
static int load_build(const char *name, const char *path)
{
    if (build_count == BENCH_MAX_BUILDS) {
        fprintf(stderr, "bench: more than %d builds\n", BENCH_MAX_BUILDS);
        return -1;
    }
    bench_build *b = &builds[build_count];
    memset(b, 0, sizeof *b);
    b->name = name;
    b->path = path;
    b->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (b->handle == NULL) {
        fprintf(stderr, "bench: build %s: %s\n", name, dlerror());
        return -1;
    }
#define BENCH_API_LOOKUP(fn)                                                         \
    b->api.fn = (__typeof__(b->api.fn))dlsym(b->handle, #fn);                        \
    if (b->api.fn == NULL) {                                                         \
        fprintf(stderr, "bench: build %s (%s) has no %s\n", name, path, #fn);       \
        return -1;                                                                   \
    }
    BENCH_API(BENCH_API_LOOKUP)
#undef BENCH_API_LOOKUP
    b->found = b->api.httpasm_cpu_found();
    build_count++;
    return 0;
}

/* make_contenders: the rows of case c: every build at each of the case's tiers (named
 * "TIER", or "BUILD TIER" when there are several builds), then the rivals, then the first row
 * again as its A/A control.
 *   c    the case; out  the rows, BENCH_MAX_CONTENDERS of room (filled from the start).
 * Each build's tier is set and read back while the rows are made (the features in effect at
 * it), then restored to everything. Returns how many rows, at most BENCH_MAX_CONTENDERS (no
 * suite comes near; past it the rest are dropped). */
static int make_contenders(const bench_case *c, contender *out)
{
    int n = 0;
    const tier *tiers = c->tiers == BENCH_TIERS_ALL ? all_tiers : best_v1_tiers;
    size_t tier_count = c->tiers == BENCH_TIERS_ALL ? sizeof all_tiers / sizeof all_tiers[0] : sizeof best_v1_tiers / sizeof best_v1_tiers[0];
    if (c->ours != NULL) {
        for (size_t b = 0; b < build_count; b++) {
            for (size_t t = 0; t < tier_count && n < BENCH_MAX_CONTENDERS - 1; t++) {
                contender *k = &out[n++];
                memset(k, 0, sizeof *k);
                if (build_count > 1)
                    snprintf(k->name, sizeof k->name, "%s %s", builds[b].name, tiers[t].name);
                else
                    snprintf(k->name, sizeof k->name, "%s", tiers[t].name);
                k->build = &builds[b];
                k->tier_name = tiers[t].name;
                k->cap = tiers[t].cap;
                k->features = builds[b].api.httpasm_cpu_limit(tiers[t].cap);
                k->run = c->ours;
                k->control_of = -1;
            }
            builds[b].api.httpasm_cpu_limit(HTTPASM_CPU_ALL);
        }
    }
    for (size_t r = 0; r < c->rival_count && n < BENCH_MAX_CONTENDERS - 1; r++) {
        contender *k = &out[n++];
        memset(k, 0, sizeof *k);
        snprintf(k->name, sizeof k->name, "%s", c->rivals[r].name);
        k->run = c->rivals[r].run;
        k->control_of = -1;
    }
    if (n == 0)
        return 0;
    /* The A/A control: the first row again, under its own name (built from a copy: the source
     * and the destination are elements of one array, which snprintf may not overlap). */
    char first[sizeof out[0].name];
    memcpy(first, out[0].name, sizeof first);
    out[n] = out[0];
    snprintf(out[n].name, sizeof out[n].name, "%.56s (A/A)", first);
    out[n].control_of = 0;
    return n + 1;
}

/* run_one: one sample of contender k on case c: its tier set (a build's), a warm-up of a
 * sixteenth of the batch (its code and branch history in place), then `calls` calls timed.
 *   c  the case; k  the contender; calls  the batch (at least 1).
 * Returns the batch's time over its calls, in ns per call. */
static double run_one(const bench_case *c, const contender *k, long calls)
{
    if (k->build != NULL)
        k->build->api.httpasm_cpu_limit(k->cap);
    k->run(k->build, c, calls / 16 > 0 ? calls / 16 : 1);
    double t0 = now_ns();
    k->run(k->build, c, calls);
    return (now_ns() - t0) / (double)calls;
}

/* json_string: writes s as a JSON string (quotes and backslashes escaped, control octets as
 * \u00XX) to f. */
static void json_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p != 0; p++) {
        if (*p == '"' || *p == '\\')
            fprintf(f, "\\%c", *p);
        else if (*p < 0x20)
            fprintf(f, "\\u%04x", *p);
        else
            fputc(*p, f);
    }
    fputc('"', f);
}

/* read_cpu_model: the CPU's model name from /proc/cpuinfo into out (size octets), or "unknown".
 * Also sets *hypervisor when the CPU flags say the kernel runs under one. */
static void read_cpu_model(char *out, size_t size, int *hypervisor)
{
    snprintf(out, size, "unknown");
    *hypervisor = 0;
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f == NULL)
        return;
    char line[4096];
    int have_model = 0, have_flags = 0;
    while (fgets(line, sizeof line, f) != NULL && !(have_model && have_flags)) {
        if (!have_model && strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon != NULL) {
                colon += colon[1] == ' ' ? 2 : 1;
                colon[strcspn(colon, "\n")] = 0;
                snprintf(out, size, "%s", colon);
                have_model = 1;
            }
        } else if (!have_flags && strncmp(line, "flags", 5) == 0) {
            *hypervisor = strstr(line, " hypervisor") != NULL;
            have_flags = 1;
        }
    }
    fclose(f);
}

/* is_wsl: whether this kernel is WSL2's (its version string names Microsoft). */
static int is_wsl(void)
{
    FILE *f = fopen("/proc/version", "r");
    if (f == NULL)
        return 0;
    char line[512];
    int wsl = fgets(line, sizeof line, f) != NULL && (strstr(line, "microsoft") != NULL || strstr(line, "Microsoft") != NULL);
    fclose(f);
    return wsl;
}

/* write_header: the record's opening: the schema, the time, the host, the builds, the settings
 * and the --meta facts; the cases follow (write_case), then main closes the record.
 *   f       the record's file (--json's);
 *   pinned  the CPU the run is pinned to, or -1 when pinning failed. */
static void write_header(FILE *f, int pinned)
{
    char model[256], when[32];
    int hypervisor = 0;
    read_cpu_model(model, sizeof model, &hypervisor);
    struct utsname u;
    if (uname(&u) != 0)
        snprintf(u.release, sizeof u.release, "unknown");
    time_t t = time(NULL);
    strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    fprintf(f, "{\n  \"schema\": \"httpasm-bench/1\",\n  \"started\": \"%s\",\n  \"host\": {\n    \"cpu\": ", when);
    json_string(f, model);
    fprintf(f, ",\n    \"kernel\": ");
    json_string(f, u.release);
    fprintf(f, ",\n    \"virtual\": \"%s\",\n    \"cpus\": %ld,\n    \"pinned\": %d,\n    \"compiler\": ",
            is_wsl() ? "wsl2" : hypervisor ? "hypervisor" : "none", sysconf(_SC_NPROCESSORS_ONLN), pinned);
    json_string(f, __VERSION__);
    fprintf(f, "\n  },\n  \"builds\": [");
    for (size_t b = 0; b < build_count; b++) {
        fprintf(f, "%s\n    { \"name\": ", b == 0 ? "" : ",");
        json_string(f, builds[b].name);
        fprintf(f, ", \"path\": ");
        json_string(f, builds[b].path);
        fprintf(f, ", \"found\": \"0x%llx\" }", (unsigned long long)builds[b].found);
    }
    fprintf(f, "\n  ],\n  \"settings\": { \"suite\": ");
    json_string(f, opt.suite);
    fprintf(f, ", \"filter\": ");
    json_string(f, opt.filter);
    fprintf(f, ", \"rounds\": %d, \"sample_us\": %ld, \"quick\": %s, \"seed\": %llu },\n  \"meta\": {", opt.rounds,
            opt.sample_ns / 1000, opt.quick ? "true" : "false", (unsigned long long)opt.seed);
    for (int m = 0; m < opt.meta_count; m++) {
        fprintf(f, "%s ", m == 0 ? "" : ",");
        json_string(f, opt.meta_key[m]);
        fprintf(f, ": ");
        json_string(f, opt.meta_value[m]);
    }
    fprintf(f, " },\n  \"cases\": [");
}

/* write_case: one case's record: its identity, the batch size, and every contender with its
 * build, tier, features in effect and raw samples (ns per call, in round order).
 *   f        the record's file;  first  whether it is the first case written (no comma before);
 *   c        the case;           k, n   its contenders and how many;
 *   calls    the batch size;     samples  each contender's samples, opt.rounds of them. */
static void write_case(FILE *f, int first, const bench_case *c, const contender *k, int n, long calls, double *const *samples)
{
    fprintf(f, "%s\n    {\n      \"suite\": ", first ? "" : ",");
    json_string(f, c->suite);
    fprintf(f, ", \"name\": ");
    json_string(f, c->name);
    fprintf(f, ", \"input\": ");
    json_string(f, c->input);
    fprintf(f, ", \"octets\": %zu, \"calls\": %ld,\n      \"contenders\": [", c->octets, calls);
    for (int i = 0; i < n; i++) {
        fprintf(f, "%s\n        { \"name\": ", i == 0 ? "" : ",");
        json_string(f, k[i].name);
        fprintf(f, ", \"build\": ");
        if (k[i].build != NULL)
            json_string(f, k[i].build->name);
        else
            fprintf(f, "null");
        fprintf(f, ", \"tier\": ");
        if (k[i].tier_name != NULL)
            json_string(f, k[i].tier_name);
        else
            fprintf(f, "null");
        fprintf(f, ", \"features\": \"0x%llx\", \"control_of\": %d,\n          \"ns\": [", (unsigned long long)k[i].features,
                k[i].control_of);
        for (int r = 0; r < opt.rounds; r++)
            fprintf(f, "%s%.4f", r == 0 ? "" : ", ", samples[i][r]);
        fprintf(f, "] }");
    }
    fprintf(f, "\n      ]\n    }");
}

/* BOOTSTRAP: the resamples behind a paired interval: 2000 put the 2.5th and 97.5th percentiles
 * at the 50th and 1950th (a few milliseconds a contender). */
#define BOOTSTRAP 2000

/* paired: one contender against another over a case's rounds: the median of the per-round
 * ratios (the other's time over this one's in the same round: above 1, this one is faster) and
 * its 95% bootstrap interval [low, high]. Pairing each round cancels the host's drift, which
 * hits both sides of a round alike (measured 2026-11-26: the A/A interval was 0.99-1.03 paired
 * against 0.91-1.10 for unpaired medians on the same samples). */
typedef struct paired {
    double median;
    double low;
    double high;
} paired;

/* median_of: the median of v[0..n), which it sorts in place. n >= 1. */
static double median_of(double *v, int n)
{
    qsort(v, (size_t)n, sizeof(double), compare_doubles);
    return n % 2 != 0 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

/* paired_ratio: the paired comparison of x against base over the rounds (see paired).
 *   base, x  each contender's samples in round order (ns per call, all above 0);
 *   seed     the resampling's seed: the same data and seed give the same interval, so a
 *            printed verdict can be reproduced from the record.
 * Returns the median and its percentile-bootstrap 95% interval. */
static paired paired_ratio(const double *base, const double *x, uint64_t seed)
{
    static double ratios[BENCH_MAX_ROUNDS], resample[BENCH_MAX_ROUNDS], medians[BOOTSTRAP];
    int n = opt.rounds;
    for (int r = 0; r < n; r++)
        ratios[r] = x[r] > 0 ? base[r] / x[r] : 0;
    uint64_t state = seed | 1;
    for (int b = 0; b < BOOTSTRAP; b++) {
        for (int r = 0; r < n; r++)
            resample[r] = ratios[next_random(&state) % (uint64_t)n];
        medians[b] = median_of(resample, n);
    }
    paired p;
    p.median = median_of(ratios, n);
    qsort(medians, BOOTSTRAP, sizeof(double), compare_doubles);
    p.low = medians[BOOTSTRAP / 40];
    p.high = medians[BOOTSTRAP - BOOTSTRAP / 40 - 1];
    return p;
}

/* verdict: what a paired comparison says, judged against the case's noise (the baseline against
 * its A/A twin, the same code): "faster" when the whole interval lies above both 1 and the
 * noise's interval, "slower" when below both, else "noise". Two runs of identical code (v2,
 * which runs v1's code where a routine has no SSE4.2 version) must come out "noise": that is
 * the rule's check, and today's rule passed it where the fastest sample's did not (2026-11-26).
 * Returns a static string. */
static const char *verdict(paired p, paired noise)
{
    if (p.low > 1.0 && p.low > noise.high)
        return "faster";
    if (p.high < 1.0 && p.high < noise.low)
        return "slower";
    return "noise";
}

/* print_case: the development loop's summary of one case on stdout: per contender the fastest
 * and the median ns per call (its speed; octets per ns at the fastest), and its paired
 * comparison with the first contender (median ratio, 95% interval) with the verdict against the
 * A/A twin's interval. With several builds, each build's tiers against the first build's
 * ("speedup of current over NAME": above 1, the tree is faster). The record has the raw
 * samples for more.
 *   c, k, n, calls, samples  as write_case's;
 *   case_index  the case's index in the table: it seeds the resampling, so the same record
 *               gives the same intervals again. */
static void print_case(const bench_case *c, const contender *k, int n, long calls, double *const *samples, size_t case_index)
{
    printf("\n%s/%s/%s  (%ld calls a sample, %d rounds)\n", c->suite, c->name, c->input, calls, opt.rounds);
    printf("  %-24s %10s %10s %9s  %-26s %s\n", "contender", "fastest ns", "median ns", "octets/ns", "paired vs first [95% CI]", "verdict");
    int twin = -1;
    for (int i = 0; i < n; i++) {
        if (k[i].control_of == 0)
            twin = i;
    }
    paired noise = twin >= 0 ? paired_ratio(samples[0], samples[twin], case_index * 1000 + (uint64_t)twin) : (paired){ 1, 1, 1 };
    double *sorted = malloc(sizeof(double) * (size_t)opt.rounds);
    if (sorted == NULL)
        return;
    for (int i = 0; i < n; i++) {
        memcpy(sorted, samples[i], sizeof(double) * (size_t)opt.rounds);
        qsort(sorted, (size_t)opt.rounds, sizeof(double), compare_doubles);
        double fastest = sorted[0], median = sorted[opt.rounds / 2];
        char throughput[16] = "-";
        if (c->octets > 0 && fastest > 0)
            snprintf(throughput, sizeof throughput, "%.2f", (double)c->octets / fastest);
        char interval[40] = "baseline";
        const char *says = "";
        if (i > 0) {
            paired p = i == twin ? noise : paired_ratio(samples[0], samples[i], case_index * 1000 + (uint64_t)i);
            snprintf(interval, sizeof interval, "%.3fx [%.3f-%.3f]", p.median, p.low, p.high);
            says = i == twin ? "(the noise)" : verdict(p, noise);
        }
        printf("  %-24s %10.2f %10.2f %9s  %-26s %s\n", k[i].name, fastest, median, throughput, interval, says);
    }
    free(sorted);
    /* A/B: each other build's rows against the first build's at the same tier. */
    for (size_t b = 1; b < build_count; b++) {
        for (int i = 0; i < n; i++) {
            if (k[i].build != &builds[0] || k[i].control_of >= 0)
                continue;
            for (int j = 0; j < n; j++) {
                if (k[j].build != &builds[b] || strcmp(k[j].tier_name, k[i].tier_name) != 0)
                    continue;
                paired p = paired_ratio(samples[j], samples[i], case_index * 1000 + 500 + (uint64_t)j);
                printf("  speedup of %s over %s at %s: %.3fx [%.3f-%.3f] %s\n", builds[0].name, builds[b].name, k[i].tier_name, p.median,
                       p.low, p.high, verdict(p, noise));
            }
        }
    }
}

/* run_case: measures case c: its contenders, the batch size (the first contender's calls for
 * about sample_us), then the rounds in shuffled order. Writes it to json (when not NULL) and
 * summarizes it on stdout. first: whether it is the first case of the record; case_index: its
 * index in the case table (it seeds the summary's resampling); random_state: the order
 * shuffle's generator, carried from case to case. Returns 0, or -1 when memory runs out. */
static int run_case(FILE *json, int first, const bench_case *c, size_t case_index, uint64_t *random_state)
{
    contender k[BENCH_MAX_CONTENDERS];
    int n = make_contenders(c, k);
    if (n == 0)
        return 0;
    double *samples[BENCH_MAX_CONTENDERS];
    for (int i = 0; i < n; i++) {
        samples[i] = calloc((size_t)opt.rounds, sizeof(double));
        if (samples[i] == NULL) {
            while (i-- > 0)
                free(samples[i]);
            return -1;
        }
    }
    /* The batch: doubled until the first contender's takes sample_us, so the clock's resolution
     * and the timing call's own cost are rounding errors, and many samples fit between the
     * host's interruptions. Every contender then runs the same number of calls. */
    long calls = 16;
    for (;;) {
        double ns = run_one(c, &k[0], calls) * (double)calls;
        if (ns >= (double)opt.sample_ns || calls > (1L << 30))
            break;
        calls *= 2;
    }
    int order[BENCH_MAX_CONTENDERS];
    for (int r = 0; r < opt.rounds; r++) {
        /* A new order each round (Fisher-Yates): no contender always runs right after another,
         * whose caches, branch history or frequency it would inherit. */
        for (int i = 0; i < n; i++)
            order[i] = i;
        for (int i = n - 1; i > 0; i--) {
            int j = (int)(next_random(random_state) % (uint64_t)(i + 1));
            int t = order[i];
            order[i] = order[j];
            order[j] = t;
        }
        for (int i = 0; i < n; i++)
            samples[order[i]][r] = run_one(c, &k[order[i]], calls);
    }
    for (size_t b = 0; b < build_count; b++)
        builds[b].api.httpasm_cpu_limit(HTTPASM_CPU_ALL);
    if (json != NULL)
        write_case(json, first, c, k, n, calls, samples);
    print_case(c, k, n, calls, samples, case_index);
    for (int i = 0; i < n; i++)
        free(samples[i]);
    return 0;
}

/* SSC_MARK: Intel SDE's marker (mov ebx, imm32; then the fs- and address-size-prefixed nop SDE
 * watches for), which -start_ssc_mark / -stop_ssc_mark turn into the start and the end of the
 * region its tools count; a plain nop to a real CPU. The id must be an immediate in that mov:
 * SDE reads it from the instruction itself (a register move left every count at 0, measured). */
#define SSC_MARK(id) __asm__ volatile("movl $" #id ", %%ebx\n\t.byte 0x64, 0x67, 0x90" : : : "ebx", "memory")

/* run_once: --once's work for case c: finds the contender named opt.once, sets its tier, and
 * runs one batch of opt.once_calls calls between SSC marks 0x111 and 0x222, so SDE counts that
 * batch's instructions and nothing else (the loop around each call included, as in a timed
 * sample). Prints the case's id when the contender exists. Returns 0, or -1 when the case has
 * no contender of that name. */
static int run_once(const bench_case *c)
{
    contender k[BENCH_MAX_CONTENDERS];
    int n = make_contenders(c, k);
    for (int i = 0; i < n; i++) {
        if (strcmp(k[i].name, opt.once) != 0)
            continue;
        if (k[i].build != NULL)
            k[i].build->api.httpasm_cpu_limit(k[i].cap);
        /* One call before the mark: one-off work (a per-build table bench_state makes, with
         * glibc's own memset) stays out of the count, which is then the steady state's. */
        k[i].run(k[i].build, c, 1);
        SSC_MARK(0x111);
        k[i].run(k[i].build, c, opt.once_calls);
        SSC_MARK(0x222);
        printf("%s/%s/%s %s %ld calls\n", c->suite, c->name, c->input, k[i].name, opt.once_calls);
        return 0;
    }
    return -1;
}

/* glob_escape: id with fnmatch's special characters (* ? [ \) escaped into out (size octets), so
 * a --filter of it selects exactly that case. Returns out. */
static char *glob_escape(const char *id, char *out, size_t size)
{
    size_t n = 0;
    for (const char *p = id; *p != 0 && n + 2 < size; p++) {
        if (*p == '*' || *p == '?' || *p == '[' || *p == '\\')
            out[n++] = '\\';
        out[n++] = *p;
    }
    out[n] = 0;
    return out;
}

/* read_mix: an SDE mix file's first dynamic block (the marked region, TID 0): its "*total" into
 * *total, and its "*isa-ext-NAME count" lines into isa (the names with their counts, as text,
 * the largest first, at most isa_size octets). Returns 0, or -1 when the file has no total. */
static int read_mix(const char *path, unsigned long long *total, char *isa, size_t isa_size)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    char line[512];
    struct {
        char name[48];
        unsigned long long count;
    } ext[64];
    int exts = 0, have_total = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, "# END_DYNAMIC_STATS", 19) == 0)
            break;
        if (!have_total && strncmp(line, "*total", 6) == 0) {
            *total = strtoull(line + 6, NULL, 10);
            have_total = 1;
        } else if (strncmp(line, "*isa-ext-", 9) == 0 && exts < 64) {
            char *space = strpbrk(line + 9, " \t");
            if (space == NULL)
                continue;
            size_t len = (size_t)(space - (line + 9));
            if (len >= sizeof ext[0].name)
                len = sizeof ext[0].name - 1;
            memcpy(ext[exts].name, line + 9, len);
            ext[exts].name[len] = 0;
            ext[exts].count = strtoull(space, NULL, 10);
            if (ext[exts].count > 0)
                exts++;
        }
    }
    fclose(f);
    /* The classes by count, largest first (a handful: insertion sort). */
    for (int i = 1; i < exts; i++) {
        for (int j = i; j > 0 && ext[j].count > ext[j - 1].count; j--) {
            __typeof__(ext[0]) t = ext[j];
            ext[j] = ext[j - 1];
            ext[j - 1] = t;
        }
    }
    size_t n = 0;
    isa[0] = 0;
    for (int i = 0; i < exts && n + 1 < isa_size; i++)
        n += (size_t)snprintf(isa + n, isa_size - n, "%s%s", i == 0 ? "" : " ", ext[i].name);
    return have_total ? 0 : -1;
}

/* icount_case: --icount's work for case c: for each contender but the A/A twin (the same code
 * again), one SDE process runs this program's --once on that contender and case, counting only
 * between the SSC marks; prints instructions per call, per octet (when the case has a size),
 * and the instruction classes executed (SDE's ISA extensions, the most frequent first, so a
 * tier's version can be seen to run its own instructions). Returns 0, or -1 when a child or
 * its mix file fails (said on stderr). */
static int icount_case(const bench_case *c)
{
    contender k[BENCH_MAX_CONTENDERS];
    int n = make_contenders(c, k);
    char id[256], escaped[512], self[4096], calls[32], model[40], mix[64];
    snprintf(id, sizeof id, "%s/%s/%s", c->suite, c->name, c->input);
    glob_escape(id, escaped, sizeof escaped);
    ssize_t self_length = readlink("/proc/self/exe", self, sizeof self - 1);
    if (self_length <= 0)
        return -1;
    self[self_length] = 0;
    snprintf(calls, sizeof calls, "%ld", opt.once_calls);
    snprintf(model, sizeof model, "-%s", opt.sde_cpu);
    printf("\n%s  (SDE %s, %ld calls, instructions counted between the marks)\n", id, model, opt.once_calls);
    printf("  %-24s %14s %12s  %s\n", "contender", "instr/call", "instr/octet", "instruction classes, most frequent first");
    for (int i = 0; i < n; i++) {
        if (k[i].control_of >= 0)
            continue;
        snprintf(mix, sizeof mix, "/tmp/bench-icount-%d.txt", (int)getpid());
        const char *argv[32];
        int a = 0;
        argv[a++] = opt.icount;
        argv[a++] = model;
        argv[a++] = "-mix";
        argv[a++] = "-omix";
        argv[a++] = mix;
        argv[a++] = "-start_ssc_mark";
        argv[a++] = "111";
        argv[a++] = "-stop_ssc_mark";
        argv[a++] = "222";
        argv[a++] = "--";
        argv[a++] = self;
        for (int b = 0; b < opt.build_arg_count; b++)
            argv[a++] = opt.build_args[b];
        argv[a++] = "--once";
        argv[a++] = k[i].name;
        argv[a++] = "--calls";
        argv[a++] = calls;
        argv[a++] = "--filter";
        argv[a++] = escaped;
        argv[a] = NULL;
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            /* The child's own line ("... N calls") is not the report: quiet it. */
            if (freopen("/dev/null", "w", stdout) == NULL)
                _exit(127);
            execv(opt.icount, (char *const *)argv);
            _exit(127);
        }
        int status = 0;
        if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "bench: SDE on %s / %s failed (status %d)\n", id, k[i].name, status);
            return -1;
        }
        unsigned long long total = 0;
        char isa[256];
        if (read_mix(mix, &total, isa, sizeof isa) != 0) {
            fprintf(stderr, "bench: %s: no count for %s / %s\n", mix, id, k[i].name);
            return -1;
        }
        unlink(mix);
        double per_call = (double)total / (double)opt.once_calls;
        char per_octet[24] = "-";
        if (c->octets > 0)
            snprintf(per_octet, sizeof per_octet, "%.3f", per_call / (double)c->octets);
        printf("  %-24s %14.1f %12s  %s\n", k[i].name, per_call, per_octet, isa);
    }
    return 0;
}

/* selected: whether case c is in the run: its suite (or "all") and the --filter glob over
 * "suite/name/input". */
static int selected(const bench_case *c)
{
    if (strcmp(opt.suite, "all") != 0 && strcmp(opt.suite, c->suite) != 0)
        return 0;
    char id[256];
    snprintf(id, sizeof id, "%s/%s/%s", c->suite, c->name, c->input);
    return fnmatch(opt.filter, id, 0) == 0;
}

/* usage: the usage line on stderr; returns 2 (the usage error's exit status). */
static int usage(void)
{
    fprintf(stderr, "usage: bench [--suite tiers|parsers|rivals|all] [--filter GLOB] [--rounds N] [--sample-us N] [--quick]\n"
                    "             [--build NAME=PATH]... [--only-builds] [--seed N] [--cpu N] [--json PATH]\n"
                    "             [--meta KEY=VALUE]... [--list] [--icount SDE64 [--sde-cpu MODEL] [--calls N]]\n"
                    "       (--once CONTENDER --calls N: --icount's child, between SDE's marks)\n");
    return 2;
}

/* main: parses the options, loads the builds, registers the suites, pins the process, and
 * measures every selected case. Returns the exit status bench.c's header lists. */
int main(int argc, char **argv)
{
    const char *build_name[BENCH_MAX_BUILDS], *build_path[BENCH_MAX_BUILDS];
    int extra_builds = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(a, "--quick") == 0) {
            opt.quick = 1;
        } else if (strcmp(a, "--list") == 0) {
            opt.list = 1;
        } else if (strcmp(a, "--only-builds") == 0) {
            opt.only_builds = 1;
            opt.build_args[opt.build_arg_count++] = a;
        } else if (v == NULL) {
            return usage();
        } else if (strcmp(a, "--suite") == 0) {
            opt.suite = v, i++;
        } else if (strcmp(a, "--filter") == 0) {
            opt.filter = v, i++;
        } else if (strcmp(a, "--rounds") == 0) {
            opt.rounds = atoi(v), i++;
        } else if (strcmp(a, "--sample-us") == 0) {
            opt.sample_ns = atol(v) * 1000, i++;
        } else if (strcmp(a, "--seed") == 0) {
            opt.seed = strtoull(v, NULL, 0), i++;
        } else if (strcmp(a, "--cpu") == 0) {
            opt.cpu = atoi(v), i++;
        } else if (strcmp(a, "--json") == 0) {
            opt.json = v, i++;
        } else if (strcmp(a, "--once") == 0) {
            opt.once = v, i++;
        } else if (strcmp(a, "--calls") == 0) {
            opt.once_calls = atol(v), i++;
        } else if (strcmp(a, "--icount") == 0) {
            opt.icount = v, i++;
        } else if (strcmp(a, "--sde-cpu") == 0) {
            opt.sde_cpu = v, i++;
        } else if (strcmp(a, "--build") == 0 || strcmp(a, "--meta") == 0) {
            const char *eq = strchr(v, '=');
            if (eq == NULL || eq == v)
                return usage();
            char *key = strndup(v, (size_t)(eq - v));
            if (key == NULL)
                return 1;
            if (a[2] == 'b') {
                if (extra_builds == BENCH_MAX_BUILDS - 1)
                    return usage();
                build_name[extra_builds] = key;
                build_path[extra_builds++] = eq + 1;
                opt.build_args[opt.build_arg_count++] = a;     /* --icount's children load the same builds */
                opt.build_args[opt.build_arg_count++] = v;
            } else {
                if (opt.meta_count == BENCH_MAX_META)
                    return usage();
                opt.meta_key[opt.meta_count] = key;
                opt.meta_value[opt.meta_count++] = eq + 1;
            }
            i++;
        } else {
            return usage();
        }
    }
    if (opt.rounds == 0)
        opt.rounds = opt.quick ? 11 : 41;
    if (opt.sample_ns == 0)
        opt.sample_ns = opt.quick ? 200000 : 500000;
    if (opt.rounds < 3 || opt.rounds > BENCH_MAX_ROUNDS || opt.sample_ns < 1000 || (opt.only_builds && extra_builds == 0))
        return usage();
    if (opt.seed == 0)
        opt.seed = (uint64_t)now_ns() | 1;

    /* The builds first: a suite may prepare its inputs with the library (bench_first_build). The
     * tree's own build comes first (found through this binary's RUNPATH), then --build's. */
    if (!opt.only_builds && load_build("current", "libhttpasm.so") != 0)
        return 1;
    for (int b = 0; b < extra_builds; b++) {
        if (load_build(build_name[b], build_path[b]) != 0)
            return 1;
    }
    bench_suite_tiers();
    bench_suite_parsers();
    bench_suite_rivals();
    if (opt.list) {
        for (size_t i = 0; i < case_count; i++) {
            if (selected(&cases[i]))
                printf("%s/%s/%s\n", cases[i].suite, cases[i].name, cases[i].input);
        }
        return 0;
    }
    if (opt.once != NULL) {
        /* Instruction counting: one batch per selected case, between SDE's marks; no pinning,
         * timing or record (an emulator's clock means nothing). */
        if (opt.once_calls < 1)
            return usage();
        int ran = 0;
        for (size_t i = 0; i < case_count; i++) {
            if (selected(&cases[i]) && run_once(&cases[i]) == 0)
                ran++;
        }
        if (ran == 0) {
            fprintf(stderr, "bench: no selected case has a contender named %s\n", opt.once);
            return 1;
        }
        return 0;
    }
    if (opt.icount != NULL) {
        /* Exact instruction counts instead of times. The CPU SDE presents follows this one's:
         * a tier this machine cannot run is not counted either (spr only when it has AVX-512). */
        if (opt.sde_cpu == NULL)
            opt.sde_cpu = (builds[0].found & HTTPASM_CPU_V4) != 0 ? "spr" : "adl";
        if (opt.once_calls < 1)
            return usage();
        int status = 0;
        for (size_t i = 0; i < case_count && status == 0; i++) {
            if (selected(&cases[i]) && icount_case(&cases[i]) != 0)
                status = 1;
        }
        return status;
    }

    /* One CPU for the whole run, so every contender meets the same core, caches and clock. */
    int cpu = opt.cpu >= 0 ? opt.cpu : sched_getcpu();
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(cpu, &one);
    if (sched_setaffinity(0, sizeof one, &one) != 0) {
        fprintf(stderr, "bench: cannot pin to CPU %d: %s (continuing unpinned)\n", cpu, strerror(errno));
        cpu = -1;
    }

    FILE *json = NULL;
    if (opt.json != NULL) {
        json = fopen(opt.json, "w");
        if (json == NULL) {
            fprintf(stderr, "bench: %s: %s\n", opt.json, strerror(errno));
            return 1;
        }
        write_header(json, cpu);
    }
    printf("bench: %d rounds, samples of %ld us, seed %llu, pinned to CPU %d; builds:", opt.rounds, opt.sample_ns / 1000,
           (unsigned long long)opt.seed, cpu);
    for (size_t b = 0; b < build_count; b++)
        printf(" %s (found %#llx)", builds[b].name, (unsigned long long)builds[b].found);
    printf("\n");

    uint64_t random_state = opt.seed;
    int written = 0, status = 0;
    for (size_t i = 0; i < case_count && status == 0; i++) {
        if (!selected(&cases[i]))
            continue;
        if (run_case(json, written == 0, &cases[i], i, &random_state) != 0) {
            fprintf(stderr, "bench: out of memory\n");
            status = 1;
        }
        written++;
    }
    if (json != NULL) {
        fprintf(json, "\n  ]\n}\n");
        if (fclose(json) != 0) {
            fprintf(stderr, "bench: %s: %s\n", opt.json, strerror(errno));
            status = 1;
        }
    }
    return status;
}
