/*
 * bench.h - HttpAsm's benchmark framework: the measurement core every suite shares
 * (benchmarks/README.md has the method; docs/DESIGN.md section 2: a faster version stays only
 * when a single-thread measurement shows it pays).
 *
 * The pieces:
 *   - a build: one libhttpasm.so loaded into this process with dlopen (RTLD_LOCAL), its API
 *     looked up into a table (bench_api), so that two builds - the tree's and another one, the
 *     commit before a change, say - run in one process, on one core, interleaved round by
 *     round: the fairest A/B a change can get, with no second process or machine state between
 *     its two sides;
 *   - a case: one routine on one input (a suite registers its cases with bench_add);
 *   - a contender: what one row of a case measures: a build at a CPU tier (httpasm_cpu_limit),
 *     or a rival's code (picohttpparser, llhttp, nghttp2), and the first contender once more as
 *     the A/A control: whatever separates the two is noise;
 *   - the runner (bench.c): per case, sizes a batch to about sample_us, then runs rounds, each
 *     round every contender once, in a new random order each time (the seed is recorded), so
 *     drift and order effects reach all of them alike;
 *   - the record: every sample, raw, in JSON, with the host, the builds and the settings
 *     (benchmarks/report.cs turns it into statistics, verdicts and tables), and a summary on
 *     stdout for the development loop.
 *
 * Footgun: a case's batch must feed its results to bench_sink (or another volatile), or the
 * compiler may drop the calls it measures: libhttpasm.so's functions are opaque to it, but a
 * rival compiled into this binary is not.
 */
#ifndef HTTPASM_BENCH_H
#define HTTPASM_BENCH_H

#include <stddef.h>
#include <stdint.h>

#include "httpasm.h"

/* BENCH_API: the library functions the cases call, each looked up by name in every build
 * (dlsym), so a case calls a build's own code through that build's table. Add a function here
 * when a case needs one. Only the declarations of httpasm.h are used (through __typeof__): this
 * program never links libhttpasm.so, it loads it. */
#define BENCH_API(X)                \
    X(httpasm_cpu_found)            \
    X(httpasm_cpu_features)         \
    X(httpasm_cpu_limit)            \
    X(httpasm_token_length)         \
    X(httpasm_field_value_scan)     \
    X(httpasm_field_id)             \
    X(httpasm_h1_parse_request)     \
    X(httpasm_h1_parse_response)    \
    X(httpasm_h1_chunked_decode)    \
    X(httpasm_h1_parse_trailers)    \
    X(httpasm_h1_write_response)    \
    X(httpasm_h1_write_request)     \
    X(httpasm_hpack_size)           \
    X(httpasm_hpack_init)           \
    X(httpasm_hpack_decode)         \
    X(httpasm_hpack_encode_bound)   \
    X(httpasm_hpack_encode)         \
    X(httpasm_h2_request)           \
    X(httpasm_sha256)

#define BENCH_API_FIELD(name) __typeof__(&name) name;

/* bench_api: one build's functions, resolved by name; every field is set once the build is
 * loaded (a build missing one of them is refused: an older build that lacks a routine cannot
 * run the cases that measure it). */
typedef struct bench_api {
    BENCH_API(BENCH_API_FIELD)
} bench_api;

/* bench_build: one libhttpasm.so in this process.
 *   name    "current" for the default build, or NAME of --build NAME=PATH;
 *   path    the file loaded (resolved through this binary's RUNPATH when it has no '/');
 *   handle  dlopen's handle; every build is RTLD_LOCAL, so each one's calls stay inside it;
 *   found   the CPU features the build detected (httpasm_cpu_found), recorded per build. */
typedef struct bench_build {
    const char *name;
    const char *path;
    void *handle;
    uint64_t found;
    bench_api api;
} bench_build;

struct bench_case;

/* bench_batch: runs the routine under measurement `calls` times on the case's input.
 *   build  the build whose code runs (its api table), NULL for a rival's batch;
 *   c      the case: its input (data, length) and the state its suite prepared;
 *   calls  how many calls this batch makes (at least 1).
 * It must feed every call's result to bench_sink, or the calls may be optimized away. */
typedef void (*bench_batch)(const bench_build *build, const struct bench_case *c, long calls);

/* bench_rival: another project's code on the same input: its row's name and its batch. */
typedef struct bench_rival {
    const char *name;
    bench_batch run;
} bench_rival;

/* Which tiers a case's HttpAsm contenders run at, per build:
 *   BENCH_TIERS_ALL       v1, v2, v3 and v4 (a tier the CPU lacks runs the best one it has,
 *                         and the record says which features were in effect): the tiers suite,
 *                         where each multi-version routine proves its versions;
 *   BENCH_TIERS_BEST_V1   the best tier the CPU has, then v1: whole routines (parsers,
 *                         rivals), where the question is the library's own speed and what its
 *                         vector code adds. */
enum bench_tiers {
    BENCH_TIERS_ALL,
    BENCH_TIERS_BEST_V1,
};

/* bench_case: one routine on one input.
 *   suite, name   where it belongs ("tiers", "parsers", "rivals") and the routine's name;
 *   input         the input's label for the reports ("64 octets", "browser request");
 *   data, length  the input; length also gives the throughput column (octets per ns), and a
 *                 case without a meaningful size passes 0 octets in `octets` below;
 *   octets        the octets one call processes, for octets per ns (0: no throughput);
 *   state         what the suite prepared for the case (a decoder, a field array), its own;
 *   ours          HttpAsm's batch, run per build and tier (NULL: the rivals only);
 *   tiers         which tiers `ours` runs at;
 *   rivals        the rivals' batches on the same input (rival_count of them). */
typedef struct bench_case {
    const char *suite;
    const char *name;
    const char *input;
    const uint8_t *data;
    size_t length;
    size_t octets;
    void *state;
    bench_batch ours;
    enum bench_tiers tiers;
    const bench_rival *rivals;
    size_t rival_count;
} bench_case;

/* bench_add: registers a case (copied); a suite calls it from its registration function.
 * Exits the program with status 2 when the case table is full (raise BENCH_MAX_CASES). */
void bench_add(const bench_case *c);

/* bench_state_init: makes a build's state in memory (size octets, zeroed) for a case, through
 * that build's own functions. Returns 0, or nonzero when the build refuses (the state is then
 * not kept, and the batch must not run). */
typedef int (*bench_state_init)(const bench_build *build, void *memory, size_t size);

/* bench_state: the state a batch keeps per build and per key (an HPACK table: its layout is the
 * build's own, so two builds of different commits never share one). The first call for a
 * (build, key) pair allocates size octets and runs init; later calls return the same memory.
 * Meant to be called once per batch, outside the calls it times. Returns the memory, or NULL
 * when memory runs out, init fails, or the table of states is full (64 pairs). */
void *bench_state(const bench_build *build, const void *key, size_t size, bench_state_init init);

/* bench_sink: where batches put their results, so no call is optimized away. */
extern volatile size_t bench_sink;

/* bench_first_build: the first build loaded (the tree's, "current", unless --only-builds), for a
 * suite that prepares inputs with the library itself (an HPACK block to decode): the builds are
 * loaded before the suites register. NULL when there is none (--list without builds). */
const bench_build *bench_first_build(void);

/* The request heads the rivals suite parses (suite_rivals.c: a minimal request, a browser's
 * navigation request, an API call with a bearer token), NUL-terminated. The tiers suite times
 * httpasm_h1_parse_request on the same octets at every tier, where a version above v2 must prove
 * itself against v2, which the rivals suite's best-and-v1 rows cannot show. */
extern const char bench_small_request[];
extern const char bench_browser_request[];
extern const char bench_api_request[];

/* bench_h1_request: httpasm_h1_parse_request on the case's head, `calls` times, each a
 * message's first call (scan_from 0), into a 64-record field array (suite_rivals.c). A batch for
 * either suite: bench_case.ours. */
void bench_h1_request(const bench_build *b, const bench_case *c, long calls);

/* bench_response: the response head every suite parses (suite_rivals.c: a typical 200 for a
 * page, twelve fields), as a writable copy made on the first call: httpasm_h1_parse_response may
 * write its buffer (an obs-fold is blanked in place; this head has none, so every call parses the
 * same octets). The rivals suite times it beside picohttpparser and llhttp, the parsers suite at
 * the best tier and v1, the tiers suite at every tier.
 *   length  out: the head's length. Returns the copy. */
uint8_t *bench_response(size_t *length);

/* bench_h1_response: httpasm_h1_parse_response on the case's head, `calls` times, each a
 * response's first call (scan_from 0) to a GET, into a 64-record field array (suite_rivals.c).
 * A batch for any suite: bench_case.ours. */
void bench_h1_response(const bench_build *b, const bench_case *c, long calls);

/* bench_sha_input: 16 KiB of fixed pseudo-random octets (made on the first call) that the hash
 * cases take their messages from: 64 octets (one block and its padding block), 1 KiB, 16 KiB. */
const uint8_t *bench_sha_input(void);

/* bench_sha256: httpasm_sha256 of the case's message, `calls` times (suite_rivals.c). A batch for
 * any suite: the tiers suite times it at every tier, the rivals suite beside OpenSSL. */
void bench_sha256(const bench_build *b, const bench_case *c, long calls);

/* bench_hpack_block: the HPACK block of a browser request's 18 fields, Huffman-coded and indexing
 * nothing, built by the first build's encoder on the first call and shared by every suite
 * (suite_rivals.c), so the tiers suite times the decoder's versions on the rivals' octets.
 *   data, length  out: the block. Returns 0, or -1 when there is no build or encoding fails. */
int bench_hpack_block(const uint8_t **data, size_t *length);

/* bench_hpack_decode: httpasm_hpack_decode of the case's block, `calls` times, with the build's
 * own decoder table (suite_rivals.c). A batch for either suite. */
void bench_hpack_decode(const bench_build *b, const bench_case *c, long calls);

/* The suites' registration functions, called by bench.c's main in this order. A suite whose
 * setup fails registers nothing and says why on stderr. */
void bench_suite_tiers(void);
void bench_suite_parsers(void);
void bench_suite_rivals(void);

#endif
