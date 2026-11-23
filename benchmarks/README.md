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
commit it measured (`-dirty` when the tree had uncommitted changes). The summary of the latest
run on a committed build follows here once it is recorded.
