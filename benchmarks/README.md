# HttpAsm benchmarks

`run.sh` measures HttpAsm against nginx and h2o, against its own HTTP/1.1-only build, and its
two backends against each other. The second comparison is the isolation measurement of
[docs/DESIGN.md](../docs/DESIGN.md) section 4: it checks whether building HTTP/1.1 from shared
source, next to HTTP/2, costs it anything. The third decides which backend is the default:
`httpasm` runs on epoll, the default, and `httpasm-uring` is the same build asking for
io_uring.

Every report it writes is kept in [results/](results/), named by date and time, with the machine,
the versions and the settings it ran with.

## What is measured

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

## How to run

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

`micro/micro.c` measures single routines, one thread, at every CPU tier (docs/DESIGN.md
sections 2 and 3: a faster version stays only when it measures faster). For each routine and
input size, it measures every tier (v1 to v4), and v1 again as the A/A control, in turn, round
after round, in one process pinned to one CPU, switching tiers with `httpasm_cpu_limit`.

```bash
bin=$(bash tests/native/build.sh Release)   # builds micro and the tier program
$bin/micro 41                               # 41 rounds
```

**How to read it:**
- It ranks by the fastest sample, not the median. On this machine (WSL2 on a hybrid Intel
  CPU), interference only ever adds time, and medians of the very same code swung by 2x
  between the baseline and its A/A twin. The fastest of many 0.5 ms samples kept that gap
  within about 10%.
- "vs v1" is the baseline's fastest sample over the tier's.
- A tier the CPU lacks collapses to the best one it has: here "v4" re-runs v3, since the CPU
  has no AVX-512.

## Results

**2026-11-26: `httpasm_field_value_scan` per tier, the tier framework's pilot.** On this
machine (i9-13900K, WSL2, features 0xff03: v3 with VAES, VPCLMULQDQ, SHA-NI and GFNI, no
AVX-512), with `micro` at 41 rounds: the fastest ns per call, then the baseline's time over the
tier's.

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
  Intel SDE (`tests/native/tiers`), and is timed only where CI's runner has AVX-512 (its job
  summary).

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
