/*
 * suite_tiers.c - the tiers suite: every multi-version routine of libhttpasm.so at every CPU
 * tier (v1 to v4), on inputs sized around the vector widths (docs/DESIGN.md section 3, "CPU
 * tiers": a tier's version is kept only where it measures faster than the baseline, beyond the
 * A/A control's gap). A routine joins this suite when it gets a version above v1.
 *
 * Inputs are built once, deterministically, so two runs (or two machines) measure the same
 * octets.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

/* field_value: 8 KiB of valid field-value octets (visible ASCII and space, no CR, LF or NUL), so
 * every call scans its whole length: the parsers' common case. */
static uint8_t field_value[8192];

/* field_value_scan: httpasm_field_value_scan on the case's octets, `calls` times. */
static void field_value_scan(const bench_build *b, const bench_case *c, long calls)
{
    size_t total = 0;
    for (long i = 0; i < calls; i++)
        total += b->api.httpasm_field_value_scan(c->data, c->length);
    bench_sink = total;
}

/* The lengths: each side of the 16-, 32- and 64-octet vector widths (where a version's head and
 * tail handling show), a typical value (100), and long ones where the loop dominates. */
static const size_t field_lengths[] = { 8, 15, 16, 31, 32, 63, 64, 100, 256, 1024, 4096 };
static char field_labels[sizeof field_lengths / sizeof field_lengths[0]][24];

/* bench_suite_tiers: registers the suite's cases (bench.h). */
void bench_suite_tiers(void)
{
    for (size_t i = 0; i < sizeof field_value; i++)
        field_value[i] = (uint8_t)(0x20 + (i * 37) % 95);
    for (size_t i = 0; i < sizeof field_lengths / sizeof field_lengths[0]; i++) {
        snprintf(field_labels[i], sizeof field_labels[i], "%zu octets", field_lengths[i]);
        bench_case c;
        memset(&c, 0, sizeof c);
        c.suite = "tiers";
        c.name = "field_value_scan";
        c.input = field_labels[i];
        c.data = field_value;
        c.length = field_lengths[i];
        c.octets = field_lengths[i];
        c.ours = field_value_scan;
        c.tiers = BENCH_TIERS_ALL;
        bench_add(&c);
    }
}
