# HttpAsm design

HttpAsm is a complete HTTP networking library in x86-64 assembly: HTTP/1.1, HTTP/2 and HTTP/3,
with QUIC and TLS of its own, as both client and server. It is built from the official documents,
and maximum performance is its guiding value. It belongs to the AsmFoundation family, next to
KvAsm, GrpcAsm and AsmSdk, and builds with [AsmSdk](https://asmfoundation.github.io/AsmSdk/).

This file is the single plan: the decisions, the architecture and the milestones. It changes as
decisions are made. Evidence (measurements, test reports) lives next to the code that produced
it.

**Status (2026-11-26):** in development. M1 is complete. Next, to full completion (section 7):
phase H, which hardens and accelerates M1's code, then M2 (crypto and TLS 1.3) and M3 (TLS 1.2
and certificates). Working on Linux x64:
- the server: HTTP/1.1 and HTTP/2 (h2c with prior knowledge, h2spec 146/146) on one port,
  per-core workers on epoll (io_uring on request; epoll measured as cheap or cheaper),
  handlers that answer at once or later from any thread;
- the client: one blocking HTTP/1.1 connection;
- the codecs: HTTP/1.1 both ways, chunked bodies, HPACK, HTTP/2's request rules;
- `specs/` with the requirement registry and the tables generated from the RFC files;
- the C ABI and the .NET tests that trace requirements, with M1's registry gate passing (every
  row of its documents proven or deferred with a reason); benchmarks against nginx and h2o.

Nothing is released.

## 1. Decisions

The owner's decisions, from the brainstorm of 2026-11-21 to 2026-11-23:

| Date | Decision |
|---|---|
| 2026-11-21 | **Scope:** HTTP/1.1, HTTP/2 and HTTP/3, as a complete HTTP networking library, with tests covering every spec. |
| 2026-11-21 | **Each protocol to the fullest:** every feature the current documents specify, including the ones browsers dropped or never shipped (server push in HTTP/2 and HTTP/3, HTTP/1.1 pipelining). |
| 2026-11-21 | **The official documents are the source of truth:** the RFC Editor's canonical files with their verified errata; ISO/IEC standards where they apply (X.509 = ISO/IEC 9594-8, ASN.1 = ISO/IEC 8824-1, DER = ISO/IEC 8825-1, read in their identical, free ITU-T editions); NIST FIPS for the crypto. Only current documents count: obsoleted RFCs (7230-7235, 7540) are history, and what the current ones deprecate is handled as they say. |
| 2026-11-21 | **TLS of our own, in assembly,** written from RFC 8446 and the X.509/ASN.1 standards. |
| 2026-11-21 | **TLS compatibility: TLS 1.2 and 1.3,** client and server, within the bounds the documents set: RFC 9325 and RFC 8996 forbid 1.0 and 1.1, RFC 9325 requires 1.2 and prefers 1.3, RFC 9113 section 9.2 adds HTTP/2's TLS 1.2 rules, and QUIC is 1.3 only (RFC 9001). |
| 2026-11-21 | **Maximum ("ultra") performance** is the guiding value. The benchmarking suite that covers the field comes later. |
| 2026-11-23 | **Home:** github.com/AsmFoundation/HttpAsm, public from the first commit; commits go to main; no tags, packages or releases until the owner decides. |
| 2026-11-23 | **Platforms: Linux x64 only** until the protocols are complete. |
| 2026-11-23 | **Architecture: a sans-I/O core driven by per-core loops** (section 3). |
| 2026-11-23 | **Consumers: .NET's standard interfaces first** (an ASP.NET Core server, an `HttpClient` handler). The design must be ready for a C API, Python and native consumers too: all of them bind to one C ABI. |
| 2026-11-23 | **Shared source, separate code** between the HTTP versions (section 4). |
| 2026-11-23 | **Milestone 1: the shared semantics + HTTP/1.1 + HTTP/2** (section 7). |
| 2026-11-25 | **Next: harden and accelerate everything built so far, then M2 and M3 to full completion.** Every requirement is tested from every angle, security included; extreme single-thread performance through CPU acceleration (SIMD: SSE, AVX2, AVX-512, and the AES, carry-less multiply and SHA instructions), chosen at run time, with a complete fallback (section 7, phase H). |
| 2026-11-26 | **TLS extensions in M2/M3, beyond RFC 9846's own:** Encrypted Client Hello (RFC 9849, with HPKE, RFC 9180), ticket requests (RFC 9149), SSLKEYLOGFILE output (RFC 9850), certificate compression (RFC 8879: zlib, brotli and zstd), delegated credentials (RFC 9345). |
| 2026-11-26 | **Revocation and transparency, the fullest option:** stapled OCSP and supplied CRLs, fetching by the library (CRL distribution points, OCSP, missing intermediates through AIA), and Certificate Transparency (SCTs checked against a supplied log list and policy). |

Documents that moved since the decisions above (RFC Editor, read 2026-11-25):
- **TLS 1.3 is RFC 9846** (July 2026). It obsoletes RFC 8446, so by the "current documents
  only" rule M2 is written from RFC 9846.
- **TLS 1.2's own documents are obsoleted** (RFC 5246 by RFC 8446 and 9846; RFC 7627 and 8422 by
  RFC 9846). A current document still requires TLS 1.2: BCP 195 (RFC 9325, section 3.1.1)
  says "Implementations MUST support TLS 1.2". Read with the owner's TLS 1.2 decision, M3
  implements TLS 1.2 from RFC 5246, 7627 and 8422 within the current documents' bounds:
  RFC 9325 (as updated by RFC 9852), RFC 10015 (no finite-field DH or RSA key exchange in TLS
  1.2), RFC 9155 (no MD5 or SHA-1 signatures) and RFC 9851 (TLS 1.2 is feature-frozen). That
  leaves ECDHE with AEAD cipher suites only.
- **Post-quantum key exchange is standard:** RFC 10024 (August 2026) defines X25519MLKEM768,
  SecP256r1MLKEM768 and SecP384r1MLKEM1024 over ML-KEM (FIPS 203). RFC 9963 (April 2026)
  defines the legacy RSASSA-PKCS1-v1_5 code points for TLS 1.3. Both are in M2.

Open, not decided yet:
- **Where "complete" ends.** The same documents define proxies, gateways and caches (all of
  RFC 9111). Standards-track extensions sit around them: WebSocket on all three versions,
  MASQUE (CONNECT-UDP, CONNECT-IP), datagrams, priorities, Alt-Svc, ORIGIN and 103 Early Hints.
- **The flagship goal.** Proposed:
  - HTTP/3 without QUIC's CPU tax ("QUIC is not Quick Enough over Fast Internet", WWW '24, found
    up to 45.2% less throughput than HTTP/2 on fast links);
  - with "every requirement traced" as the assurance story.
- **Offloads:** whether the fastest measured path wins even when it isn't our assembly (kTLS,
  NIC TLS offload). Proposed: yes, with our code the default and the fallback.
- **Client and server both** is assumed from "complete". M1 builds both directions of the
  HTTP/1.1 codec.

## 2. Principles

- **Measured, not argued.** A design with a rival is decided by a paired measurement, and every
  performance claim records its evidence and scope.
- **Touch each byte once, on the core that owns its connection.** That means SIMD parsing, crypto
  fused with the copy, no allocation per request, and no lock on a request's path.
- **Traceability.** Every MUST, SHOULD and MAY maps to code and to a test that names it
  (section 5).
- **Safety by proof.** Nothing checks assembly for us. We use requirement tests, guard pages
  around buffers, fuzzing, differential fuzzing against reference stacks, and constant-time
  checks for crypto.
- **Tested from every angle** (2026-11-25). Each requirement is tested for:
  - the rule kept, and each way to break it;
  - every limit and boundary, at the value and one past it;
  - every split of its input;
  - the published attacks on it (smuggling, floods, oracles, downgrades);
  - running out of memory and time;
  - both I/O backends, and every CPU tier.

  Around the requirement tests:
  - coverage-guided fuzzing of every parser and state machine;
  - differential fuzzing against reference stacks;
  - an instruction-coverage gate: every block of `libhttpasm.so` runs under the tests, or is
    listed with the reason it cannot;
  - constant-time checks wherever a secret is handled.
- **Fastest tier, every tier proven** (2026-11-25):
  - Each hot routine has a baseline x86-64 version and accelerated versions: SSSE3 and SSE4.2;
    AVX2; AVX-512; and the AES, carry-less multiply, SHA, GFNI, BMI2/ADX and IFMA instructions,
    each where it pays.
  - The version is chosen once, at load, from CPUID.
  - The tests force every tier, so the fallback is as proven as the fastest path.
  - An accelerated version stays only when a single-thread measurement shows it pays.

## 3. Architecture

```text
 Surfaces    .NET (ASP.NET Core IServer, HttpClient handler: first) · C ABI (httpasm.h) ·
             NASM macros (httpasm.inc) · Python (later)
                 all bind to the one C ABI of libhttpasm.so
 Drivers     our per-core loops (epoll; io_uring on request: section 7, step 4)
             or the host's loop (one waitable fd + process() + next_timeout())
             or none (the core called directly: tests, hosts that own their sockets)
 Core        no I/O, no system calls, no allocation; bytes in, bytes and events out,
 (HttpAsm.   in the caller's buffers:
  Core)        HTTP/1.1 · HTTP/2 + HPACK · HTTP/3 + QPACK · QUIC · TLS 1.2/1.3 · crypto
```

- **The core** is `src/HttpAsm.Core`: a freestanding project, so the build itself forbids C
  library calls. Its state lives in memory the caller provides, and its output goes into the
  caller's buffers. Event delivery (records in a caller-provided array, or callbacks) is settled
  in M1 with the first codec.
- **The library** is `src/HttpAsm` (`libhttpasm.so`, a `libc` project). It holds the C ABI and,
  from M1, the Linux driver. `httpasm.map` exports `httpasm_*` and nothing else.
- **Three ways for consumers in,** by who owns the loop:
  1. our loops call the consumer's handlers inline (GrpcAsm's model; the fastest);
  2. the host's loop drives ours through one waitable handle;
  3. the core with no loop at all.

  Events reach consumers as callbacks, as a pull queue (`next_event`), or through shared rings,
  io_uring-style, in batches.
- **The loops:**
  - **Concurrency:** one worker per core, sharing nothing (SO_REUSEPORT). Each worker owns its
    connections, timers and memory.
  - **Idle:** event-based, with no ticks and no spinning. A worker sleeps in the kernel until a
    completion arrives or its nearest timer falls due. Busy polling is an opt-in for latency
    (Linux 6.13's IRQ suspension polls while busy and returns to interrupts when idle).
  - **Async answers:** a handler may park a request and complete it from any thread, which wakes
    the owning worker with an event. In .NET, an `await` resumes on the same worker.
- **Kernel baseline:**
  - Linux 5.15, the WSL2 kernel tests run on here; the io_uring backend needs 5.13.
  - Newer io_uring features (buffer rings, zero-copy send, `MSG_RING`, DEFER_TASKRUN) are to be
    probed at startup and used when present: they are the levers that may make io_uring the
    default (section 7, step 4).
  - CI runs a newer kernel (7.0 on 2026-11-23), so the paths that need one run there.
- **CPU tiers** (section 2, "Fastest tier"; built in phase H, step H1):
  - **The levels:**
    - v1 is the baseline, any x86-64 (SSE2): every routine has a v1 version, and every
      routine that touches secrets has a constant-time one;
    - v2 adds SSSE3, SSE4.1/4.2 and POPCNT;
    - v3 adds AVX2, BMI1/2, FMA and MOVBE;
    - v4 adds AVX-512 F/BW/CD/DQ/VL.
  - **Instruction groups** are detected on their own: AES-NI, PCLMULQDQ, SHA-NI,
    VAES/VPCLMULQDQ, GFNI, ADX, AVX512-IFMA/VBMI/VBMI2.
  - **Choosing:** CPUID is read once, at load, and each routine's best version is chosen then.
    An environment variable caps the level and drops groups, for tests and measurements.
  - **This machine** is an i9-13900K: v3 with VAES, VPCLMULQDQ, SHA-NI and GFNI, and no
    AVX-512. The AVX-512 paths are proven under Intel SDE's emulation, and measured on CI
    hardware that has AVX-512.

## 4. Sharing between the HTTP versions

The three versions are not separate copies, and they do not share machine code where speed
lives:

| Part | How |
|---|---|
| Framing parsers and serializers | Separate per version: HTTP/1.1 text with SIMD; HTTP/2's 9-byte frames; HTTP/3's varint frames |
| Connection state, pools | Separate. An HTTP/1.1 connection stays small; HTTP/2 carries streams and HPACK tables; HTTP/3 carries QUIC state |
| Response encoders, pre-encoded caches | Separate: HTTP/1.1 text templates; HTTP/2 HPACK static indices; HTTP/3 QPACK |
| RFC 9110 rules | **One source**, written as NASM macros (`include/semantics/*.inc`) and assembled inline into each version's code: no call, no version check, no indirection |
| What handlers receive | One shape, built in place: known-field ids plus pointers into the received bytes. HTTP/1.1 finds ids with a perfect hash; HTTP/2 and HTTP/3 take them from the static-table index |
| Crypto, Huffman, integers, routing, timers, pools, loops | One shared copy: nothing version-specific in them |

HTTP/2 and HTTP/3 also share their stream logic: a request per stream, pseudo-header rules, push,
priorities and extended CONNECT. HPACK and QPACK share their prefix integers, the Huffman code
and their table bookkeeping. Sharing rules also guards security: HTTP/2-to-HTTP/1.1 request
smuggling feeds on versions that disagree about one message.

**Proof:** M1 measures HTTP/1.1 built this way against a hand-isolated HTTP/1.1. The design
stays only if the difference is within noise.

## 5. Requirements traceability (`specs/`)

- **`specs/documents.json`** pins the official files by SHA-256: the prepped RFCXML v3 for RFCs
  from 2019 on, the text for older ones.
  - Today: RFC 9110, 9111, 9112, 9113, 7541, 6585, 8446, 9000, 9001, 9002, 9114 and 9204.
  - Each milestone adds its documents (section 7 lists M2's and M3's). M2 starts by replacing
    RFC 8446 with RFC 9846, which obsoleted it in July 2026.
  - NIST's standards and the ITU-T's X.680 and X.690 are published as PDF, not RFCXML. Their
    requirements enter as rows per algorithm, parameter set and direction, each proven by the
    official test vectors.
- **`specs/specs.cs`** (a .NET file-based app):
  - `fetch` downloads the files and checks their hashes;
  - `extract` writes `specs/requirements.tsv`;
  - `extract --check` (CI) fails when the committed registry differs from what the pinned files
    produce.
- **Row ids** come from the documents:
  - `RFC9112-6.3-2.1` is the paragraph the RFC Editor's XML numbers `section-6.3-2.1`, and its
    HTML anchors with the same name. Several keywords in one paragraph get `#1`, `#2`.
  - Text RFCs, which have no such numbers, get `RFC7541-5.1-p3` (the section's third paragraph).
  - Grammar blocks are rows with the keyword `ABNF`.
- **The registry today:** 2,542 BCP 14 requirements and 102 ABNF blocks in the 11 documents.
  The keyword boilerplate is excluded.
- **Tests name their rows:** `[Requirement("RFC9110-5.5-5#1")]`. The test project:
  - fails on a name that is not a row;
  - reports, per document, how many rows the tests prove.

  At M1's end the report becomes a gate for the M1 documents: every row proven, or deferred
  with a written reason.
- **Errata:** verified errata are recorded with the document they correct, when a milestone
  reaches it.

## 6. Code conventions

- **System V AMD64 throughout.** The core's internal symbols are `ha_*` and hidden; the C ABI's
  are `httpasm_*`.
- **Every function documents its contract:** inputs, outputs, clobbered registers, memory it
  reads, and the requirement rows it implements.
- **Tables are computed by NASM from the grammar** (`semantics/tables.asm`), or generated from
  the RFC text (HPACK's and QPACK's tables, the Huffman code), never typed in.
- **Every NASM and C# warning is an error.**
- **Tests:**
  - xunit v3 on Microsoft.Testing.Platform, calling the C ABI.
  - The native tests run on Linux x64, through `tests/run-linux.sh` in a container elsewhere.
  - `HTTPASM_REQUIRE_LINUX=1` turns a skip into a failure.
  - Buffers that end at an inaccessible page prove that nothing reads past its input.

## 7. Milestones

**M1: the shared semantics + HTTP/1.1 + HTTP/2** (complete, 2026-11-23):
1. *Scaffolding (done):* the repository, `specs/` and the registry, the core and library
   projects, the C ABI, the tests and CI.
2. *Shared rules (done):* tokens and field values (`httpasm_token_length`,
   `httpasm_field_value_scan`); field names per version (HTTP/2 adds lower case); the field-id
   perfect hash; the request view every version fills (`httpasm_request`); the event model:
   handlers called inline by the loops, answering at once or later from any thread.
3. *HTTP/1.1 (done),* RFC 9112 with the RFC 9110 semantics it needs, in both directions:
   - request and status lines (sections 3 and 4) and field lines (section 5);
   - body length with Content-Length and chunked, and the smuggling defenses of section 6.3;
   - persistence and pipelining (section 9);
   - SIMD parsing (SSE2: line ends, field values).
4. *The Linux driver (done):* per-core loops: accept with SO_REUSEPORT, timers as deadline
   lists, idle without polling, back-pressure, graceful stop, the server's and the client's
   calls in the C ABI. Two backends drive the same connection code, and the tests run in full
   on each (CI and `tests/run-linux.sh` run the suite twice):
   - **epoll, the default** (measured below);
   - **io_uring on request** (`HTTPASM_SERVER_URING`, `src/HttpAsm/uring.asm`): each worker
     on its own ring, or on epoll where the kernel refuses one (before 5.13, a seccomp
     profile such as Docker's, the memory budget below). Its design:
     - readiness stays level-triggered: one one-shot POLL_ADD per connection, armed with the
       events the connection wants; a change while it is armed removes it and arms it anew
       (updating an armed poll in place, IORING_POLL_UPDATE_EVENTS, left connections stalled
       under back-pressure in the tests on 5.15, so it is not used);
     - the I/O is batched: the turn's RECVs, SENDs and polls reach the kernel in the one
       `io_uring_enter` that then waits; every RECV and SEND carries MSG_DONTWAIT, so it
       completes inside that call and no buffer is lent to the kernel past it;
     - SQEs are written only right before `io_uring_enter`, from each connection's state
       then, so none names a descriptor number reused since; a closed connection is freed
       only when its last operation has completed (`conn.uops`);
     - the ring's memory budget: Linux 6.14 to 7.2 charge every page of a ring to the
       user's RLIMIT_MEMLOCK (8 MiB by default on Ubuntu 24.04, shared by all of the user's
       processes), unless the kernel carries upstream commit b59cabf9b4ac (2026-10-06). That
       commit calls the charge a 6.14 regression and reaches stable kernels as a backport, so
       CI's runners have shown both behaviors. Rings of 4096 SQEs and 16384 CQEs (132 pages)
       let 10 to 15 workers have one where rings are charged, and a CI runner put the rest on
       epoll; 256 and 4096 (21 pages) allow 57 to 97. `httpasm_server_io` says MIXED when
       only some workers got a ring.
   - **Why epoll is the default** (`benchmarks/README.md`, 2026-11-23, Linux 5.15): io_uring
     as built cost 5.10 to 5.46 µs of server CPU per HTTP/1.1 keep-alive request against
     epoll's 4.99, and was never cheaper than epoll in five interleaved rounds; pipelined and
     over HTTP/2 the two are within the noise. The likely cost is the one-shot poll armed
     again for every request, which epoll's lasting registration does not pay. io_uring
     becomes the default only when a design of it measures faster; the levers to measure are
     multishot polls, registered descriptors, and on newer kernels DEFER_TASKRUN, multishot
     receives into provided buffers and zero-copy sends.
5. *The isolation measurement (done, `benchmarks/`):* the same sources built without HTTP/2
   (the `H1Only` configuration) against the full build, with an A/A control (the full build
   twice) as the noise floor. On 2026-11-23 (f75c380): 4.11 and 4.13 µs of CPU per HTTP/1.1
   request, where the A/A pair differs by more (4.13 and 4.17); 0.55 for all three pipelined.
   No measurable cost, so the design stays. Against nginx 1.24 and h2o 2.2.5 too: see
   `benchmarks/README.md`.
6. *HTTP/2 (done):*
   - frames, stream states, flow control, SETTINGS (`src/HttpAsm/h2.asm`);
   - HPACK, with its static table and Huffman code generated from RFC 7541 (the encoder
     reproduces Appendix C octet for octet);
   - h2c with prior knowledge, on the same port as HTTP/1.1;
   - h2spec: 146/146, pinned and required in CI;
   - every frame the server sends is checked against RFC 9113's sending rules in every test;
     GOAWAY before every close, a graceful stop's two GOAWAYs (2^31 - 1, then the last stream),
     400 before the reset of a malformed request, the flood guards (rapid reset, CONTINUATION).
7. *The registry gate (done):* every row of RFC 9110, 9112, 9113, 7541 and 6585 is proven by a
   test that names it or deferred in `specs/deferred.tsv` with its milestone and a reason;
   `RegistryTests.AccountsForEveryM1Row` fails on a row that is neither and on a stale rule.
   On 2026-11-23: RFC 7541 20 of 20 proven; RFC 9113 184 of 302 (the rest: TLS, push, the
   HTTP/2 client, intermediaries, options); RFC 9112 112 of 160; RFC 9110 97 of 509 (most of
   the rest is the application's, the client's or an intermediary's).

*Exit:* every RFC 9112, RFC 9113 and RFC 7541 row proven, or deferred with a reason. The RFC
9110 rows M1 needs are proven; the others are deferred with reasons. h2spec 146/146,
request-smuggling cases, and recorded measurements.

**M1 is complete (2026-11-23):** the exit criteria hold. The registry gate passes (step 7),
h2spec runs its 146 cases in CI, the request-smuggling defenses of RFC 9112 section 6 are
tested end to end on both backends (`ServerTests.RefusesBadRequestsAndCloses`: Content-Length
with Transfer-Encoding in either order with a request hidden behind the body, two lengths,
chunked not last, Transfer-Encoding in HTTP/1.0, bare LF, obs-fold, two Hosts; and the
parser's own cases in `H1RequestTests`), and the measurements are recorded in
`benchmarks/results/` (the isolation question, step 5; io_uring against epoll, step 4).

**Then, to full completion (the owner, 2026-11-25): phase H, M2, M3.** Every step ends with
its tests from every angle (section 2), on every CPU tier and both backends, and with its
single-thread measurements recorded.

**Phase H: hardening and acceleration of M1's code** (HTTP/1.1, chunked bodies, HPACK,
HTTP/2, the drivers, the client):
1. *The CPU tier framework* (section 3, "CPU tiers"), done 2026-11-26:
   - `cpu/cpu.asm` reads CPUID and XGETBV. The library's constructor applies `HTTPASM_CPU`,
     and `httpasm_cpu_found`, `_features` and `_limit` are in the C ABI. Each multi-version
     routine reads one mask at its entry (`cpu.inc`).
   - The .NET suite runs at v1, v2, v3 (and v4 on AVX-512 hardware), each on both backends
     (`tests/run-linux.sh`, and CI through it).
   - Intel SDE hangs on the .NET runtime, but runs native programs in seconds. So
     `tests/native/tiers.c` runs every multi-version routine at every tier in one process,
     against an oracle and a guard page: natively, and under SDE as a Sapphire Rapids. The suite
     proves v1; identical results prove the rest. A planted AVX-512-only bug passed natively and
     failed under SDE, as it must.
   - `benchmarks/micro` times each tier single-threaded, ranked by the fastest of 41 samples
     with an A/A control: the host's medians swing up to 2x.
   - The pilot is `httpasm_field_value_scan`. Its AVX2 version is kept: 1.28x faster at 32
     octets, 1.8x at 64, 2.0-2.2x from 256 up; below 32, every tier runs the SSE2 code. Its
     AVX-512 version is proven equal, and waits for AVX-512 hardware to be timed
     (`benchmarks/README.md`).
2. *The instruments:*
   - **instruction coverage** of `libhttpasm.so` under the tests, and its gate: every block
     runs, or is listed with the reason it cannot. Built 2026-11-26 (`tests/coverage/`):
     - **How it works:** the Coverage configuration assembles each source through
       `instrument.cs`. That expands macros with NASM's `-E` and inserts a flag-neutral marker
       store at every block and on both edges of every conditional branch (the taken edge
       through a trampoline). It also marks code after `jmp`/`ret` that no label reaches.
       `coverage_rt.asm` writes the marks when a process exits.
     - **What runs:** `run.sh` runs everything `run-linux.sh` runs against that build, and
       `report.cs` merges the marks and gates against `unreachable.tsv`.
     - **The first measurement,** every tier, both backends, the native programs and SDE:
       4,022 markers; blocks 91.8%, branch edges 79.5%, no dead code; 678 markers not run, the
       work list of step 3. It found code no test reached, such as the default worker count,
       which every test sets explicitly. `semantics/tables.asm` is data only and cannot be
       preprocessed alone (an `%if` over symbols), so it is listed as not instrumented.
   - **coverage-guided fuzzing** of every parser and state machine (HTTP/1.1 requests and
     responses, chunked bodies, HPACK, HTTP/2 frames and connections). Built 2026-11-26
     (`tests/fuzz/`), starting with HTTP/1.1 requests:
     - **How it steers:** assembly has no compiler instrumentation, so the Fuzz configuration
       reuses the coverage instrument: the same markers, placed in libFuzzer's
       `__libfuzzer_extra_counters` section (`instrument.cs --section`). libFuzzer then steers
       by the core's own 2,389 blocks and branch edges, not only by the C harness's. This
       replaces the first plan, AFL++ in binary-instrumentation mode: it needs no emulator and
       runs at native speed. libFuzzer cannot see what the assembly compares against, so each
       fuzzer has a dictionary of the words its parser compares (`<name>.dict`).
     - **What each fuzzer checks,** with clang's libFuzzer, AddressSanitizer and
       UndefinedBehaviorSanitizer: every input at every CPU tier, with identical results; the
       input against an inaccessible page, so a read past it crashes; the result's documented
       forms; every pointer returned lies inside the input; and the input arriving in two to
       five reads, cut where its hash says (a cut taken from its first octet fell near 28% of
       nearly every request), gives the one-shot result.
     - **The fuzzers:** `h1_request`; `h1_response` (also RFC 9112 6.3's framing outcome for
       the status and method); `chunked`, against an oracle written from the decoder's
       documented grammar, state for state, whole, in reads and one octet at a time, then the
       trailer section; `hpack`, block sequences sharing a table, with every fully decoded
       block encoded again and decoded by a peer, whose table must stay entry for entry the
       encoder's; `h2_request`, field lists through RFC 9113's request and trailer rules, with
       everything accepted checked apart from the library (pseudo-fields, names, values, the
       request record) and against HTTP/1.1's parser; `server`, whole connections (HTTP/1.1,
       or HTTP/2 after the preface) to a running server on loopback with its drivers linked
       in. The server must close after the client's FIN, and must answer the first request
       as `httpasm_h1_parse_request` judges it: the refusal's status, the handler's 200
       naming the same method, target and body length, or 413. A broken first request-line
       with no `HTTP/` in it gets the close alone, by design: it is no HTTP/1.x request,
       RFC 9112 2.2. HTTP/2 answers must be whole frames, SETTINGS first, and a plain GET on
       a new connection must still be answered after every input.
     - **The first campaigns:** `h1_request`, 10.7 million inputs in 60 s; `chunked` 3.6
       million; `h1_response` 7.8 million; `hpack` 19.5 million in 300 s. Planted failures
       (in a check, and in the chunked oracle) were found within seconds and printed in base64.
     - **What they found** (each fixed, with a regression test and seed):
       - the response parser framed a 204 to CONNECT as a plain 204 and a 099 to CONNECT as a
         tunnel; every 2xx to CONNECT is a tunnel (RFC 9110 9.3.6), and an invalid code below
         100 is framed as a 5xx's (RFC 9110 15);
       - the field lookup folded every octet with `| 0x20`, which is exact only for tokens, but
         HPACK looks up names nobody has validated yet: the decoder gave `\x1apath` the id of
         `:path`, and the encoder would send `content\rlength` as the static table's
         `content-length`. Only letters fold now;
       - HTTP/2 accepted authorities HTTP/1.1 refuses, which an HTTP/2 front could pass to an
         HTTP/1.1 hop: CONNECT's `:authority` without a port (`example.c43`), `:authority` and
         Host with any octets but CTLs and `@`, and `[%:]`, which only HTTP/1.1's target scan
         caught. `h2_request` checks every accepted list against `httpasm_h1_parse_request`.
         Now one text, `include/semantics/authority.inc`, checks HTTP/1.1's Host, CONNECT
         target and http(s) absolute-form authority and HTTP/2's `:authority` and Host:
         `uri-host [ ":" port ]` with IP-literals held to IPv6's and IPvFuture's octets, and
         for CONNECT a port of 1 to 65535 (RFC 9110 9.3.6).
     - Seeds live in `tests/fuzz/seeds/<name>/`. Every finding becomes a seed and a regression
       test once fixed. CI runs each fuzzer for 30 s;
   - **differential fuzzing** against llhttp and picohttpparser (HTTP/1.1) and nghttp2 (HPACK,
     HTTP/2). Every difference in verdict or parsed fields is triaged against the RFC. Built
     2026-11-26, with the references pinned by SHA-256 in `tests/tools.sh` (nghttp2 1.71.0,
     llhttp 9.4.4, picohttpparser dd573d8) and compiled into the fuzzers only (`one.sh`):
     - `hpack_nghttp2`: block sequences through HttpAsm's decoder and nghttp2's inflater. Same
       verdict, same fields and never-indexed marks, same table size after every block.
       Limits under 4096 are left out on purpose: HttpAsm's decoder then starts at the limit,
       nghttp2's at 4096 waiting for a size update. 1.34 million inputs, no difference;
     - `h1_request_diff`: request heads through HttpAsm, llhttp (strict) and picohttpparser.
       Where two accept, everything both report must agree: head length, method, target,
       version, fields, and llhttp's framing. Where one refuses what the other accepts, the
       class must be listed in `h1_request_diff.triage` with its RFC reason. 38 classes
       triaged from surveys (`HTTPASM_FUZZ_SURVEY`) of 19 million inputs, then of about 190
       million (16 workers, 10 minutes); CI's own campaign found one more, which a gate that
       fails on unknown classes is for. They include HTTP/0.9 lines llhttp takes, bare LF, and
       the Host and framing rules the references leave to the application. It found one real
       difference: `Transfer-Encoding: chunked\xD8` (an obs-text
       octet after the token, or `chunked x`) was read as chunked, where llhttp reads another
       coding. A coding's token must now end its element (OWS, then `,`, `;` or the end).
   - **a single-thread benchmark harness:** each routine on fixed inputs, in nanoseconds per
     call and bytes per cycle, paired A/B with an A/A control, against picohttpparser, llhttp
     and nghttp2;
   - **constant-time checks**, for M2: valgrind with secrets marked undefined, and statistical
     timing tests.
3. *Tests from every angle* for M1's rows: section 2's matrix for each proven row. Also the
   published attack corpora (request smuggling, HTTP/2 floods, HPACK bombs, slowloris on both
   versions), memory and connection exhaustion, and races between deferred answers and stops.
   Known open item: an IP-literal's IPv6 structure (eight groups, one "::", the IPv4 tail's
   dec-octets) is not checked yet, only its octets (`semantics/authority.inc`); RFC 3986's
   grammar and its published test vectors close it.
4. *Acceleration:* SSE4.2, AVX2 and AVX-512 versions of the hot paths. These are line and
   field scanning, token and value validation, header-name lookup and case folding,
   chunk-size parsing, HPACK's Huffman code and integers, frame headers, and response writing.
   Each is measured against its v1 version and the rivals.

*H is done when:* the coverage gate passes; set-length fuzzing campaigns run clean (short ones
in CI); differential fuzzing has no untriaged difference; every row passes on every tier and
both backends; the measurements are recorded.

**M2: crypto in assembly + TLS 1.3 (RFC 9846)**:
1. *Documents:*
   - re-pin RFC 9846 in place of RFC 8446;
   - TLS: RFC 10024, 9963, 8449, 7301, 6066, 7919, 9849 with 9180, 9149, 9850, 9345;
   - certificate compression: RFC 8879 with 1950, 1951, 7932 and 8878;
   - crypto standards: FIPS 180-4, 202, 197, 198-1, 186-5 and 203; SP 800-38D and 800-186;
     RFC 7748, 8032, 8439, 5869 and 8017;
   - their official test vectors (NIST CAVP/ACVP, the documents' own), and Project
     Wycheproof's.
2. *Crypto primitives,* each with a constant-time v1 version and accelerated tiers:
   - **hashes:** SHA-256, SHA-384/512, SHA-3 and SHAKE;
   - **MACs and KDFs:** HMAC, HKDF;
   - **AEADs:** AES-128/256-GCM (AES-NI, VAES and VPCLMULQDQ at 256 and 512 bits, a bitsliced
     fallback), ChaCha20-Poly1305;
   - **key exchange:** X25519, X448, ECDH on P-256/384/521, FFDHE 2048-8192, ML-KEM-768/1024,
     and RFC 10024's hybrids;
   - **signatures:** ECDSA P-256/384/521, Ed25519, Ed448, RSA-PSS and PKCS#1 v1.5
     (2048-8192 bits);
   - **randomness:** getrandom.

   Proof: every official vector and Wycheproof's, differential fuzzing against OpenSSL,
   constant-time checks, every tier. Measured single-threaded against OpenSSL, BoringSSL and
   AWS-LC.
3. *The DER reader* (M3 step 2, brought forward), and loading the server's own chain and key
   (PEM, PKCS#8).
4. *The TLS 1.3 engine*, sans-I/O in the core, server and client:
   - the record layer, the handshake and its key schedule, HelloRetryRequest;
   - PSK resumption, tickets and ticket requests; 0-RTT with anti-replay;
   - KeyUpdate and post-handshake authentication;
   - every group and signature scheme of RFC 9846, and the post-quantum hybrids;
   - SNI, ALPN, record size limit, delegated credentials, ECH (HPKE), the key log;
   - certificate compression, with zlib, brotli and zstd codecs in assembly.
5. *HTTPS:*
   - TLS in the drivers on both backends, with h2 or http/1.1 chosen by ALPN;
   - TLS in the C ABI client;
   - the C ABI for certificates, keys and configurations.
6. *Proof:*
   - the registry gate for M2's documents;
   - RFC 8448's example handshakes, where they still hold under RFC 9846;
   - BoringSSL's test runner (BoGo) through a shim; tlsfuzzer;
   - interop with OpenSSL, BoringSSL, GnuTLS, rustls, .NET's SslStream, curl, and Chrome and
     Firefox on claude-desktops;
   - h2spec over TLS; fuzzing of every TLS parser;
   - handshakes per second and bulk throughput, single-threaded, against OpenSSL (alone and
     in nginx and h2o).

**M3: TLS 1.2 + certificates**:
1. *Documents:*
   - certificates: RFC 5280 with its updates; X.680 and X.690 (ITU-T); RFC 5480, 4055,
     8410, 9525, 5958, 7468; RFC 7292 with 9579 and 9879; RFC 8018;
   - revocation and transparency: RFC 6960 with 8954 and 9654; RFC 6962 and 9162;
   - TLS 1.2: RFC 5246, 7627, 8422, 5288, 5289, 7905, 5746, 9325, 10015, 9155, 9851, 9852.
2. *Encodings:*
   - ASN.1 DER: a strict reader and a writer;
   - X.509 certificates and CRLs;
   - PEM and PKCS#8;
   - PKCS#12, with PBES2, PBKDF2 and PBMAC1, and decryption of the legacy 3DES and RC2
     encryption of older .pfx files.
3. *Verification:*
   - path building and validation (RFC 5280 section 6: name constraints, policies, key
     usage), service identity (RFC 9525), the system trust store;
   - revocation: stapled OCSP, supplied CRLs, and the library's own fetching (CRL
     distribution points, OCSP, AIA intermediates) through our client, with a cache and a
     policy;
   - Certificate Transparency: SCTs from the certificate, the TLS extension or OCSP, checked
     against a supplied log list and policy.
4. *TLS 1.2,* server and client:
   - ECDHE (X25519, X448, P-256/384/521) with AES-GCM and ChaCha20-Poly1305 only;
   - extended master secret required; renegotiation_info without renegotiation;
   - session resumption, OCSP stapling, SCTs;
   - RFC 9113 section 9.2's rules for HTTP/2.
5. *Proof:*
   - the registry gate for M3's documents;
   - x509-limbo, Wycheproof, and BoGo's and tlsfuzzer's TLS 1.2 tests;
   - interop with Windows' SChannel (claude-desktops) and the rest;
   - fuzzing of the DER, X.509, PKCS#12, OCSP and CRL parsers;
   - differential verification against OpenSSL.

**After M3, in order:**
- **M4:** QUIC + HTTP/3 + QPACK (RFC 9000, 9001, 9002, 9114, 9204), and server push, built
  once for HTTP/2 and HTTP/3 with the stream logic they share (section 4).
- **M5:** the .NET standard interfaces (ASP.NET Core `IServer`, an `HttpClient` handler). The
  handler is the full client: HTTP/2, redirects, credentials, retries, pipelining; M1's C ABI
  client is one blocking HTTP/1.1 connection.
- **M6:** the extensions and roles that "complete" is decided to include.

Other platforms (Windows, macOS, ARM64), Python's ASGI and the benchmarking suite follow once
the protocols are complete.
