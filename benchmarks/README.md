# HttpAsm benchmarks

Two kinds of measurement, both local: benchmarks never run in CI (the owner's rule, 2026-11-26).
A change is measured on the developer's machine, against the commit before it, before it is
kept.

- **The framework, `bench.sh`:** single routines on one thread. It times every CPU tier of each
  multi-version routine, the parsers' whole routines, and the parsers beside picohttpparser,
  llhttp and nghttp2. This is where a change to the code is proven faster, or not.
- **Whole servers, `run.sh` and `ab.sh`:** HttpAsm against nginx and h2o, its HTTP/1.1-only
  build and its two backends; and what a change costs per request.

## The framework: `bench.sh`

### What it measures

A case is one routine on one input. Every contender of a case runs once per round, round after
round, in one process pinned to one CPU, in a new random order each round. Three suites:

- **`tiers`:** each multi-version routine at v1, v2, v3 and v4, on inputs around the vector
  widths. A routine joins when it gets a version above v1; today that is
  `httpasm_field_value_scan`.
- **`parsers`:** the library's whole routines on realistic inputs, at the best tier the CPU has
  and at v1. The routines: response heads, chunked bodies (small and large chunks), field-name
  lookup, token validation, response writing, HPACK encoding, and HTTP/2's request rules. These
  are the hot paths of phase H step 4.
- **`rivals`:** the HTTP/1.1 request parser beside picohttpparser (h2o) and llhttp (Node.js) on
  three request heads, and the HPACK decoder beside nghttp2. The rivals are the sources
  `tests/tools.sh` pins, compiled with `-O3 -march=native`, their best (picohttpparser's and
  llhttp's SSE4.2 paths need it). Mind what each one does: picohttpparser splits a head into
  lines and checks almost nothing else; llhttp checks the grammar; HttpAsm also applies RFC
  9112's semantics (target and Host grammar, field names and values, every framing rule,
  known-field ids).

A contender is a build of the library at a tier, or a rival. The first contender runs a second
time as the A/A control: whatever separates the two is the run's noise. The library is loaded,
not linked (`dlopen`), so another build can run beside it: see `ab` below.

### How to run

```bash
dotnet build HttpAsm.slnx -c Release                # libhttpasm.so, which the runner loads
benchmarks/bench.sh                                 # every suite: 41 rounds of ~0.5 ms samples
benchmarks/bench.sh --quick --filter 'tiers/*'     # the development loop: 11 shorter rounds
benchmarks/bench.sh --list                          # the cases, as "suite/name/input"
benchmarks/bench.sh ab HEAD~1 --suite parsers       # a change against the commit before it
benchmarks/bench.sh icount --filter 'parsers/*'    # exact instructions per call (Intel SDE)
benchmarks/bench.sh mca field_value_scan            # llvm-mca on each version's loops
```

The options: `--suite`, `--filter` (a glob over "suite/name/input"), `--rounds`, `--sample-us`,
`--quick`, `--json PATH` (the whole record: every raw sample, the host, the builds and the
settings) and `--meta KEY=VALUE` (a fact to record with it). From Windows it runs in WSL. The
runner's sources are `bench/`: `bench.c` (the runner) and one `suite_*.c` per suite.

### How to read a verdict

Each row gives the contender's speed, then its comparison with the first row:
- **fastest and median ns per call**, and octets per ns at the fastest: what the routine costs;
- **the paired ratio:** each round gives the first row's time over this row's, both measured
  within milliseconds of each other. The row shows the median of those ratios with its
  bootstrap 95% interval. Above 1, this row is faster;
- **the verdict:** `faster` when the whole interval lies above both 1 and the A/A twin's
  interval, `slower` when it lies below both, and `noise` otherwise.

Why paired rounds decide (measured 2026-11-26, the same 41-round run judged three ways):
- **The fastest sample**, the rule the earlier harness used, called identical code faster four
  times and slower once. When the two fastest samples tie, the A/A gap reads 0, and any ratio
  counts.
- **Unpaired medians** gave the right verdicts, but the A/A interval spanned ±10% (0.91-1.10 at
  1024 octets). A real 8% gain would read as noise.
- **Paired rounds** gave the right verdicts with an A/A interval of about ±2% (0.99-1.03). The
  host's drift hits both sides of a round alike, so pairing cancels it.

### The instruments

- **A/B of two builds: `ab COMMIT`.** COMMIT's libhttpasm.so is built once, in a git worktree
  under `.ab/`, and loaded beside the tree's own (`dlopen`, `RTLD_LOCAL`, so neither build's
  calls reach the other). Both run interleaved at every tier, and each case ends with "speedup
  of current over COMMIT at TIER". The A/B runs in 3 processes (`--repeat N`), and a change is
  proven only when every process gives the same verdict. The reason: identical code at another
  address can run up to 12% faster or slower in one process, through branch-predictor and
  cache-set aliasing, and every process loads the builds at new random addresses.
- **Instruction counts: `icount`.** Each contender's batch runs once under Intel SDE (the
  version `tests/tools.sh` pins), between two marker instructions. SDE counts exactly the
  instructions executed per call, and the instruction classes that ran (SSE2, AVX2...), which
  shows that a tier runs its own version. The count is the same on every run. SDE presents
  this machine's CPU family: Alder Lake here, without AVX-512.
- **Loop analysis: `mca ROUTINE`.** Each version's loops, cut from the built library, go
  through llvm-mca (Alder Lake model by default). It gives the simulated cycles per iteration,
  the throughput bound, the IPC and the busiest execution ports. It models the core alone (no
  caches, frequency or memory), so it guides a loop's design and never proves anything.

### Why trust it: the validation of 2026-11-26

Each instrument had to be consistently and empirically valid before it was used (the owner's
condition). On the i9-13900K under WSL2:

| Check | Result |
|---|---|
| Paired verdicts with known answers: 5 runs of the tiers suite (41 rounds). Identical code must say noise: v2 everywhere, and every tier below 32 octets. The AVX2 version must say faster from 32 octets up | 165 of 165 right |
| One-process A/B against an identical copy of the build (5 runs, 220 comparisons) | 6 wrong (2.7%), in random directions, 5 of them at 63 octets |
| The same comparisons, requiring 3 processes to agree | 0 wrong |
| A/B against a build slowed by one extra uop per iteration of the AVX2 loop (about 11%), 3 processes | Proven slower at 256 and 4096 octets (3 of 3 processes). Not proven at 1024 (2 of 3). Not detectable at 100 octets and below (3 iterations or fewer: under 4%). Unchanged code was never proven different |
| SDE counts, repeated, and at 10,000 against 20,000 calls | Identical. The slowed build counted exactly one more instruction per iteration (1941 against 1813 at 4096 octets) |
| llvm-mca's simulated cycles against measurements | v3 over v1 per octet: 2.00x predicted, 1.99-2.10x measured. The extra uop: +11.0% predicted, +10.7-12.6% measured |

Two agreements are a start for llvm-mca, not a proof. Each loop of step 4 gets the same check
(prediction against measurement), recorded here, and llvm-mca is dropped if it stops agreeing.

**AVX-512** is not timed, counted or analyzed where the CPU lacks it (the owner's rule,
2026-11-26): the default SDE and llvm-mca models are this machine's. `tests/native/tiers` still
proves every AVX-512 version equal to v1 under SDE: a test, not a measurement.

## Whole servers: `run.sh` and `ab.sh`

`run.sh` measures HttpAsm against nginx and h2o, against its own HTTP/1.1-only build, and its
two backends against each other. The second comparison is the isolation measurement of
[docs/DESIGN.md](../docs/DESIGN.md) section 4: it checks whether building HTTP/1.1 from shared
source, next to HTTP/2, costs it anything. The third decides which backend is the default:
`httpasm` runs on epoll, the default, and `httpasm-uring` is the same build asking for
io_uring.

Every report it writes is kept in [results/](results/), named by date and time, with the machine,
the versions and the settings it ran with.

### What is measured


Every server answers `GET /` with `200 Hello, World!` (`text/plain`), the TechEmpower plaintext
shape, from code:
- HttpAsm: `samples/Hello`'s handler;
- nginx 1.24: `return 200`;
- h2o 2.2.5: an mruby handler.

Each server runs 4 workers pinned to CPUs 0-3. The load generators run on CPUs 8-15, twice as
many, so the servers should be the limit.

| Scenario | Load generator | What it shows |
|---|---|---|
| `h1` | `wrk -t8 -c256` | HTTP/1.1 keep-alive, one request at a time per connection |
| `h1-pipelined` | `h2load --h1 -c256 -m16` | HTTP/1.1, 16 requests in flight per connection |
| `h2` | `h2load -c64 -m32` | HTTP/2 over cleartext (h2c, prior knowledge), 32 streams per connection |

Each run records two numbers:
- **requests per second**;
- **the server's CPU time per request:** utime + stime of all its processes, read from `/proc`
  before and after the run.

The second number still means something when a run is limited by the load generator or by the
machine, which throughput alone would hide. It is the measure the isolation question is decided
on.

Each round runs every server once per scenario, interleaved, so drift (heat, the host's other
work) hits all of them alike. The table gives each pair's median over the rounds, the lowest
and highest CPU time per request any round measured, and every round's numbers below it.

**The noise floor.** `httpasm-control` is a second process of the very same full build (an A/A
control), run in the HTTP/1.1 scenarios. Whatever separates it from `httpasm` is noise, so the
isolation result (the full build against the HTTP/1.1-only build) counts only where it is
larger than that gap.

### How to run

On Linux x64 (WSL2 works), with nginx, h2o (with mruby), wrk and h2load (`nghttp2-client`)
installed:

```bash
dotnet build HttpAsm.slnx -c Release                 # samples/Hello and libhttpasm.so
dotnet build src/HttpAsm/HttpAsm.asmproj -c H1Only   # the isolation control
ROUNDS=5 benchmarks/run.sh 10                        # 5 rounds of 10 s per server and scenario
```

`SERVER_CPUS`, `CLIENT_CPUS` and `WORKERS` move the pinning. Nothing else may run on the machine
meanwhile: not even a build, which here once replaced `libhttpasm.so` under the running servers.

`ab.sh` answers a narrower question, whether a change made HttpAsm cheaper or dearer: two
builds of the Hello sample, interleaved, and the second one twice (its A/A control), in `h1`
and `h1-pipelined`:

```bash
git worktree add --detach ../before <commit>                    # the build to compare against
(cd ../before && dotnet build samples/Hello/Hello.asmproj -c Release)
dotnet build samples/Hello/Hello.asmproj -c Release             # the change
benchmarks/ab.sh ../before . 5 10                               # 5 rounds of 10 s
```

`HELLO_IO_A` and `HELLO_IO_B` choose each build's backend (`epoll`, the default, or `uring`).

## Results

**2026-11-26: phase H step 4, the one-pass request head at v2.** With the lookup done, the
browser request's profile showed what the field lines and the lookup could not: 16% of its
instructions in the search for the head's end (`ha_find_lf`, called once per line), a pass that
the field lines then repeat, each line with its own loop exit to predict. From v2 up a head that
arrives whole is now read once (`ha_h1_fields_v2`, request.asm's `.one_pass`), the empty line
found on the way; anything it would not accept goes back to the classic flow, so outcomes are
unchanged (`tests/native/tiers`, 340,298 more parses at every tier).

| Request head | Instructions, before -> after (best tier) | v1 / best, same build | picohttpparser's lead, before -> after |
|---|---:|---:|---:|
| small GET | 804 -> 670 | 0.70x | 2.15x -> 1.58x |
| browser GET | 5,541 -> 3,239 | 0.48x | 1.79x -> 1.03x |
| API POST | 3,030 -> 1,944 | 0.50x | 1.74x -> 1.15x |

Against the commit before (f5ba99a, `bench.sh ab`, 3 processes, all agreeing), the best tier is
1.70-1.72x faster on the browser head with v1 unmoved there (no difference), 1.50-1.51x on the
API POST head and 1.36-1.38x on the small GET, where v1 moved 1.05-1.06x and 1.09-1.14x by
placement. The response parser, which keeps the classic flow, shows no difference at either
tier.

**2026-11-26: phase H step 4, the field-name lookup at v2.** After the field lines, SDE's
profile of the browser request put 20% of its instructions in `ha_field_lookup`, which compared
a candidate name octet by octet (7 instructions an octet). At v2 it now builds the same key from
two 16-bit loads and compares 16 octets at a time against two generated rows per known name, one
lower case and one upper case (`specs/generate.cs`): an octet matches when it equals either, which
is exactly the case-insensitive compare of letters and the exact compare of everything else.

| Case | Instructions, before -> after (best tier) | Against fe7f29b (3 processes): best, v1 |
|---|---:|---:|
| field_id, 12 names (10 known) | 2,536 -> 1,931 | 1.43x faster, v1 not proven (0.96-0.98x) |
| HPACK encode, 18 fields | | 1.06-1.08x faster, v1 no difference |
| HTTP/2 request rules, 18 fields | | 1.29-1.32x faster, v1 1.12-1.15x faster |
| small GET | 825 -> 804 | 0.93-0.95x, v1 0.88-0.90x |
| browser GET | 6,180 -> 5,541 | no difference, v1 no difference |
| API POST | 3,335 -> 3,030 | 1.09-1.11x faster, v1 0.95x |

In the same build the v2 lookup is 1.42x faster than v1 (`parsers/field_id`, tier verdict). The
v1 column is the control: its code changed only by the dispatch test at the lookup's entry, yet
it moved between 0.88x and 1.15x, the code-placement effect again. So the rows where v1 moved
say only that the best tier gained more (API POST, HTTP/2) or lost less (small GET) than the
placement alone. The browser head ran 10% fewer instructions in the same time: its lookups run
beside the line scans, off the path that sets its time, which is the scans' own chain from one
line's end to the next line's start.

**2026-11-26: phase H step 4, the HTTP/1.1 field lines at v2.** SDE's profile of the browser
request (7,653 instructions per call) put 55% in `ha_h1_fields`, which now scans each line 16
octets a step at v2 (docs/DESIGN.md, step 4). On the i9-13900K under WSL2:

| Request head | Instructions, v1 -> v2 | v2 over v1 (paired, 41 rounds) | picohttpparser's lead, before -> after |
|---|---:|---:|---:|
| small GET (37 octets) | 861 -> 832 | 1.10x | 2.15x -> 1.96x |
| browser GET (846 octets) | 7,717 -> 6,536 | 1.17x | 2.49x -> 1.79x |
| API POST (511 octets) | 4,032 -> 3,548 | 1.18x | 2.73x -> 1.88x |

Against the commit before the change (`bench.sh ab fd9a354`, 3 processes, all agreeing), the best
tier measured 1.08x, 1.43x and 1.37x. v1 itself measured 1.23x and 1.14x faster on the two larger
heads, though it runs slightly more instructions (two dispatch tests per line). The inserted code
moved the scalar loop to a placement this CPU runs faster. That is the code-placement effect the
validation measured, so only the tier verdict above is the vector code's own. llhttp is now
slower than HttpAsm on all three heads.

A refinement (fe7f29b) classifies each value step once, and settles a step's bounds with one
compare when it ends within the head. It cut the v2 instructions further (browser 6,536 -> 6,180,
API POST 3,548 -> 3,335, small GET 832 -> 825) with no time difference in an A/B against e0ef184
(3 processes). The same A/B measured v1, whose code had not changed, 4-5% slower on the two
larger heads: placement again, the other way round.

- 2026-11-26, `results/2026-11-26-rivals.md` (i9-13900K under WSL2, the first run, by the
  earlier `rivals` harness and its fastest-sample rule): the baseline for phase H step 4. The
  framework's rivals suite confirms it (paired, 2026-11-26): picohttpparser 2.1-2.5x faster
  on the three heads.
  - **Request heads:** picohttpparser is 2.1-2.3x faster than HttpAsm; llhttp is level or up
    to 1.34x slower.
  - **HPACK:** HttpAsm decodes 1.48x faster than nghttp2.
  - **Tiers:** HttpAsm's best tier equals its v1, because its one vector routine (the field
    value scan) is too small a share of a whole parse to show.

**2026-11-26: `httpasm_field_value_scan` per tier, the tier framework's pilot.** On this
machine (i9-13900K, WSL2, features 0xff03: v3 with VAES, VPCLMULQDQ, SHA-NI and GFNI, no
AVX-512), with the earlier `micro` harness at 41 rounds: the fastest ns per call, then the
baseline's time over the tier's. The framework's paired runs (5 runs of 41 rounds, the same
day) agree: v3 faster from 32 octets (1.36x at 32, 1.71x at 64, 2.05x at 256, 2.10x at 1024),
noise below 32.

| Octets | v1 (SSE2) | v3 (AVX2) | v3 vs v1 | A/A (v1 again vs v1) |
|---:|---:|---:|---:|---:|
| 8 | 2.80 | 2.74 | 1.02x | 0.92x |
| 16 | 2.84 | 2.93 | 0.97x | 0.95x |
| 31 | 3.36 | 4.27 | 0.79x | 0.97x |
| 32 | 3.11 | 2.42 | 1.28x | 1.00x |
| 64 | 6.24 | 3.46 | 1.80x | 1.11x |
| 256 | 15.11 | 7.43 | 2.03x | 1.04x |
| 1024 | 63.25 | 29.24 | 2.16x | 1.10x |
| 4096 | 248.84 | 114.84 | 2.17x | 0.99x |

What it shows:
- **The AVX2 version is kept**: from 32 octets up it beats the baseline by more than the A/A
  gap, 1.3x at 32 and over 2x from 256.
- **Below 32 octets every tier runs the SSE2 code**, so differences there are noise. The
  0.79x at 31 is one row; the same code measured as "v4" gave 1.07x.
- **The AVX-512 version cannot run on this CPU.** It is proven equal to the others under
  Intel SDE (`tests/native/tiers`), and is not timed here: no AVX-512 is measured where the
  CPU lacks it (the owner's rule, 2026-11-26).

Every run's report is in [results/](results/), named by date and time; a report names the
commit it measured (`-dirty` when the tree had uncommitted changes when the run began).

**2026-11-23, b932500: io_uring against epoll** ([report](results/2026-11-23-2008.md)). The same
machine and settings as the run below, 5 rounds of 10 s; at b932500 io_uring was the default,
so `httpasm`, its A/A control and the HTTP/1.1-only build ran on io_uring, and `httpasm-epoll`
was the full build asked for epoll. The server's CPU µs per request, medians (range over the
rounds):

| Scenario | io_uring | io_uring, A/A | io_uring, HTTP/1.1-only | epoll |
|---|---:|---:|---:|---:|
| `h1` | 5.37 (5.11-6.01) | 5.46 (5.21-6.24) | 5.10 (4.84-5.74) | **4.99** (4.51-5.43) |
| `h1-pipelined` | 0.71 (0.60-0.77) | 0.74 (0.61-0.80) | 0.72 (0.65-0.77) | 0.69 (0.62-0.80) |
| `h2` | 1.25 (1.01-1.34) | | | 1.17 (0.89-1.24) |

What it shows:
- **io_uring, as built, is not cheaper than epoll on Linux 5.15.** In `h1` epoll was the
  cheapest of the four HttpAsm processes in every round (tied once), which chance alone would
  give about once in a thousand runs; pipelined and over HTTP/2 the two are within the noise
  (epoll was lower in 4 of the 5 `h2` rounds). The backend arms a one-shot poll again for
  every request, which epoll's lasting registration does not pay; batching the receives and
  sends into one `io_uring_enter` per turn does not win that back.
- **So epoll became the default** (`HTTPASM_SERVER_URING` asks for io_uring), and every test
  runs on both backends. io_uring becomes the default only when a design of it measures
  faster: multishot polls, registered descriptors, and on newer kernels DEFER_TASKRUN,
  multishot receives into provided buffers and zero-copy sends.
- **This run's absolute numbers are higher than the f75c380 run's** (`h1`: nginx 8.44 against
  8.05, HttpAsm's epoll 4.99 against 4.13): the host was busier. Only comparisons within one
  run count. Whether the epoll path itself got dearer when io_uring was added was measured
  directly, with `ab.sh` ([report](results/2026-11-23-2037-ab-epoll.md)): f75c380 against the
  change that made epoll the default, interleaved, with that change twice (its A/A control).
  `h1`: 4.45 µs against 4.52 and 4.40, so the A/A pair brackets f75c380; `h1-pipelined`: 0.58
  against 0.60 and 0.60, a gap that an earlier run of the same comparison (a scratch copy of
  the script) gave the other way round, 0.64 against 0.61 and 0.62. No change is measurable.
- The ring sizes changed after this run (4096 SQEs and 16384 CQEs, then 256 and 4096, for
  the memory charge of Linux 6.14 to 7.2; docs/DESIGN.md section 7, step 4). At 64 connections per worker
  a turn queues at most 192 SQEs and no CQE overflows, so the sizes do not touch these
  numbers.

**2026-11-23, f75c380** ([report](results/2026-11-23-1932.md)): an i9-13900K under WSL2 (Linux
5.15), 4 workers per server, 5 rounds of 10 s. The medians, with the CPU time per request's
range over the rounds:

| Scenario | HttpAsm | same build (A/A) | HTTP/1.1-only build | nginx 1.24 | h2o 2.2.5 |
|---|---:|---:|---:|---:|---:|
| `h1`: requests/s | 1,022,993 | 907,096 | 1,016,105 | 529,168 | 281,458 |
| `h1`: CPU µs/request | 4.13 (3.95-4.59) | 4.17 (4.00-4.56) | 4.11 (4.06-4.43) | 8.05 | 13.07 |
| `h1-pipelined`: requests/s | 7,674,648 | 7,740,854 | 7,584,502 | 714,027 | 493,756 |
| `h1-pipelined`: CPU µs/request | 0.55 (0.53-0.61) | 0.55 (0.54-0.59) | 0.55 (0.54-0.57) | 6.04 | 8.89 |
| `h2`: requests/s | 4,573,014 | | | 574,250 | 939,066 |
| `h2`: CPU µs/request | 0.90 (0.81-0.94) | | | 7.36 | 4.62 |

What it shows:
- **The isolation question:** HTTP/1.1 built next to HTTP/2 from shared source costs nothing
  measurable. The full build and the HTTP/1.1-only one differ by 0.02 µs per request (4.13
  against 4.11) where two processes of the very same build differ by 0.04 (4.13 against 4.17),
  and all three ranges overlap; pipelined, all three measure 0.55. The design of
  [docs/DESIGN.md](../docs/DESIGN.md) section 4 stays.
- **Throughput alone would mislead:** the same build ran at 1.02 and 0.91 million requests/s in
  `h1`, 12% apart, because one request per connection at a time leaves the load generator and
  the loopback as much in charge as the server. CPU time per request is the measure.
- **Against nginx and h2o:** per request, HttpAsm uses about half of nginx's CPU time without
  pipelining, about a tenth with it, and an eighth of nginx's (a fifth of h2o's) over HTTP/2.

Scope: one machine, under WSL2 (a virtualized kernel), with servers and load generators on the
same host; a "Hello, World!" answer, so the protocol work dominates and no application work
hides it. Other machines, kernels and answers will move the numbers.
