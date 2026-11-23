# HttpAsm benchmarks

`run.sh` measures HttpAsm against nginx and h2o, and against its own HTTP/1.1-only build. The
second comparison is the isolation measurement of [docs/DESIGN.md](../docs/DESIGN.md) section 4:
it checks whether building HTTP/1.1 from shared source, next to HTTP/2, costs it anything.

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

## Results

Every run's report is in [results/](results/), named by date and time; a report names the
commit it measured (`-dirty` when the tree had uncommitted changes when the run began).

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
