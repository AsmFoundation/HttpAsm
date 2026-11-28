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
  - **Timeouts** (phase H, 2026-11-26): the idle timeout is a window, judged when it ends
    (`ha_conn_expire`). Each window gets a verdict:
    - **Nothing in progress:** the connection closes. That covers HTTP/1.1 between requests or
      within a head (slowloris), and HTTP/2 with no active stream and nothing to send. PINGs
      and other control frames are not activity.
    - **A transfer in progress:** it gets another window if it moved at least
      `min_data_rate` octets a second (default 240, Kestrel's). That covers a body arriving or
      an answer leaving, so a transfer takes as long as it needs (RFC 9112 9.5), while
      RUDY-style slow bodies and slow reads close.
    - **HTTP/2 streams** are also judged one by one (`ha_h2_sweep`): one whose request stopped
      gets 408 (Request Timeout), and one whose answer stopped is reset with CANCEL.
    - **A deferred answer** holds its connection: the handler decides.

    Counting octets costs one add per send or read. New windows start at a request head
    (HTTP/1.1's body; HTTP/2's request) and at an answer queued.
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
  - Today: RFC 9110, 9111, 9112, 9113, 7541, 6585, 9000, 9001, 9002, 9114 and 9204 (M1, M4,
    open), and M2's 22 (2026-11-27): TLS 1.3 itself, RFC 9846, in place of RFC 8446, which it
    obsoleted in July 2026; RFC 10024, 9963, 8449, 7301, 6066, 7919, 9849, 9180, 9149, 9850 and
    9345; certificate compression, RFC 8879, with its codecs' formats, RFC 1950, 1951, 7932 and
    8878; and RFC 7748, 8032, 8439, 5869 and 8017.
  - Each milestone adds its documents (section 7 lists M3's).
  - The codecs' formats hold no BCP 14 keyword and no grammar block, so they give no rows:
    like NIST's standards, they are proven by test data, their own and the reference
    implementations'.
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
- **The registry today:** 3,089 BCP 14 requirements and 102 ABNF blocks in 29 documents (M2's
  documents hold 1,015 of the rows; RFC 9846 has 500, RFC 8446 had 480). The keyword
  boilerplate is excluded.
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
   - The tiers are timed single-threaded by the benchmark framework (`benchmarks/bench.sh`,
     its tiers suite), every tier in one process, with an A/A control.
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
       preprocessed alone (an `%if` over symbols), so it is listed as not instrumented. A
       source the build cannot mark is assembled as it is, and the gate fails when its object
       holds instructions (`instrument.cs` counts them): `client.asm` once dropped out of
       sight that way, silently, through one `%if` over `equ` symbols.
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
       a new connection must still be answered after every input; `h1_write`, the HTTP/1.1
       writers, whose every accepted output must parse back with the caller's status, method,
       target, Host and fields, and the framing and persistence the writer reported. It found
       two places where HttpAsm wrote what its own parsers refuse:
       - a Content-Length past 2^63 - 1, now refused by both writers;
       - a request target whose form did not suit the method (`PO S HTTP/1.1`). The request
         writer now applies the parser's form rules (CONNECT's authority-form through the
         shared authority macros), and checks Host with `HA_URI_HOST`;

       and `client`, the HTTP/1.1 client against an in-process server that answers with the
       input. Every response the client returns must be what the parsers read in those
       octets: status, fields, the body by its framing, and trailers. It found
       `httpasm_client_connect` failing with -EINTR when a signal interrupted the connect;
       connect is never restarted. The client now waits for the attempt with `poll` against
       the timeout and reads `SO_ERROR`. `tests/native/signals` connects 2,000 times under a
       100 µs timer signal; it fails without the fix and passes with it.
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
         for CONNECT a port of 1 to 65535 (RFC 9110 9.3.6);
       - the HPACK encoder reused a dynamic entry's name by known-field id alone (CI's campaign,
         2026-11-27): a known name without a static entry, `connection`, after a field spelled
         `connectiOn`, came back from the peer as `connectiOn`, whose spelling the peer's entry
         keeps. Only a name with a static entry went in by that entry's index, with the static
         table's lower-case spelling on both sides; any other entry's name now serves only a
         name spelled the same, octet for octet. HttpAsm's own HTTP/2 answers lower-case their
         names first, so only a direct caller of `httpasm_hpack_encode` saw it;
       - the client returned a parser's status, -431 or -400, for a refused trailer section,
         where its contract promises -HTTPASM_ERROR_* (a 10-minute campaign of `client`,
         2026-11-27). The finding itself was the oracle's: it gave a response's trailers the
         head's 128 field records where the client gives them what its 256 leave
         (`HTTPASM_CLIENT_FIELDS`, now in `httpasm.h`), and it took any result below -37 for
         I/O, so no refusal of trailers was ever checked. The trailer parser now names its
         rule (in `edx`, which its C signature has no place for), the client returns it, and
         the oracle accepts nothing outside -HTTPASM_ERROR_* and -errno.
     - Seeds live in `tests/fuzz/seeds/<name>/`. Every finding becomes a seed and a regression
       test once fixed. CI runs each fuzzer for 30 s.
     - **Replay:** `run.sh merge` minimizes each fuzzer's corpus into `tests/fuzz/corpus/<name>/`,
       which is committed (2,940 inputs, 460 KB, on 2026-11-26). `replay.sh` builds each harness
       with `replay.c` instead of libFuzzer and runs it on the seeds and the corpus, with every
       check. `run-linux.sh` does this on every test run against the build's own objects, so
       the fuzzers' findings stay deterministic tests. In the coverage run it does the same
       against the Coverage objects, so what the fuzzers reached counts toward the gate.
       Adding the replay exposed a bug in the test runner: `run_native`'s status was its last
       command's, so on AVX-512 runners a failing tier or fallback program passed.
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
     call and octets per nanosecond, paired with an A/A control, against picohttpparser,
     llhttp and nghttp2. Built 2026-11-26 as `benchmarks/rivals/` and `benchmarks/micro`, then
     the same day folded into one framework, `benchmarks/bench.sh` (`benchmarks/README.md`):
     tiers, parsers and rivals suites; verdicts from paired rounds with a bootstrap 95%
     interval against the A/A twin; an in-process A/B of two builds; exact instruction counts
     under Intel SDE; llvm-mca's loop predictions. Each instrument was validated before use
     (the README has the numbers). The rivals are compiled at their best (`-O3
     -march=native`), in one process on one core, interleaved. The first run is step 4's
     baseline:
     - picohttpparser parses request heads 2.1-2.3x faster than HttpAsm, while checking
       little beyond line structure;
     - llhttp is level with HttpAsm, or up to 1.34x slower;
     - HttpAsm decodes HPACK 1.48x faster than nghttp2;
     - HttpAsm's best tier equals its v1. Acceleration must reach the whole parse, not one
       routine;
   - **constant-time checks**, for M2: valgrind with secrets marked undefined (done 2026-11-27:
     `tests/ct/run.sh`, M2's proof below), and statistical timing tests (done 2026-11-28:
     `tests/ct/dudect.sh`, local only, the same bullet).
3. *Tests from every angle* for M1's rows: section 2's matrix for each proven row. Also the
   published attack corpora (request smuggling, HTTP/2 floods, HPACK bombs, slowloris on both
   versions), memory and connection exhaustion, and races between deferred answers and stops.
   The IP-literal's IPv6 structure was an open item (only its octets were checked): closed
   2026-11-26 by `semantics/ipv6.asm`. It enforces eight pieces, or seven at most with one
   "::", an IPv4 tail last, and dec-octets without a leading zero. `AuthorityTests` holds all
   eight entry points (HTTP/1.1's Host, absolute-form and CONNECT, parsed and written;
   HTTP/2's :authority and Host) to one RFC 3986 verdict on 78 vectors, RFC 4291 2.2's
   among them.

   Progress, 2026-11-26:
   - **Coverage:** the fuzz corpora replayed in the coverage run raised it to 94.2% of blocks
     and 88.0% of branch edges. Where coverage was thin, new fuzzers were written:
     - `h1_write`: the writers emitted a Content-Length and target forms that HttpAsm's own
       parsers refuse;
     - `client`: connect failed on EINTR;
     - `server` on io_uring too.
   - **Stops and races:** a graceful stop now waits for one measured round trip on every
     HTTP/2 connection, idle ones included. It sends GOAWAY(2^31 - 1), then a PING, and
     sends the final GOAWAY after the ACK. Closing idle connections at once refused requests
     already on their way, which CI's coverage run caught (`ShutsDownGracefully`). The
     client tests' fake server no longer races its own test's end.
   - **CPU detection:** `tests/native/cpu` checks `httpasm_cpu_found()` against an independent
     reading of CPUID and XGETBV, natively and under 13 of SDE's CPU models (from SSE3-only to
     AVX-512 with SHA512), each with the x86-64 level it must reach. All 22 models SDE offers
     matched when first run.
   - **Error paths:** `tests/native/faults` fails each allocation of a whole server's life in
     turn, by interposing malloc, calloc and realloc. It also fails 16 system calls, one each,
     through seccomp. Every case runs in a child that must end by itself: no crash, no hang.
     On the first run, 49 children ended by themselves. 23 of them saw the failure reported by
     an API (create, start, the client's connect or send), and 26 finished whole. None crashed
     or hung.
   - **Descriptor exhaustion:** when `accept4` failed with EMFILE (or ENFILE, ENOBUFS, ENOMEM),
     the worker returned to its wait. The connection it could not take stayed in the backlog,
     so the listener stayed readable, and both backends woke the worker again at once: a core
     at full CPU for as long as descriptors stayed short. The listener now rests 100 ms
     (`pause_accept`; nginx rests 500 ms), then takes the backlog. `tests/native/faults` checks
     it two ways. Every child must stay under 1.5 s of CPU: the one whose `accept4` always
     fails used 9.95 s before the fix and 0.01 s after. A server whose process may open only 4
     more descriptors gets 12 connections from another process, on each backend: it used
     1,088 ms of CPU in the second that followed before the fix and about 1 ms after. Once
     descriptors free, it answers the request that waited in the backlog.
   - **The attack corpora,** under way:
     - **HPACK bomb** (RFC 7541 7.3): past its output's limits, the decoder still copied every
       field it could fit, so each 1-octet reference to a 600-octet dynamic entry copied the
       entry again. Once the output is full it now writes nothing and only measures, at a
       constant cost per octet (`HpackTests.WritesNothingOnceTheOutputIsFull`: a canary
       after the records survives every kind of field; the old decoder overwrote it).
     - **The HTTP/2 floods** (RFC 9113 10.5). `tests/native/floods` runs 17 published floods
       against a server in its own process, on each backend, and checks three things. Each
       flood must be served or cut with ENHANCE_YOUR_CALM, as it should be. The server's CPU
       per octet must stay within 4x a PING flood's (an HPACK bomb within 4x a same-size block
       of static references). A client that never reads must not grow the heap (malloc is
       interposed). The before and after (fastest of 3 runs, WSL, i9-13900K):

       | Flood | Published as | Before | After |
       |---|---|---|---|
       | SETTINGS of 2,730 `INITIAL_WINDOW_SIZE` values, 100 streams open | RFC 9113 10.5 | 11.19x | 0.69x |
       | WINDOW_UPDATE on stream 0, 100 streams open | RFC 9113 10.5 | 10.61x | 0.53x |
       | empty SETTINGS | CVE-2019-9515 | 5.10x | 2.32x |
       | WINDOW_UPDATE on each of 100 streams | RFC 9113 10.5 | 3.20x | 1.37x |
       | 1-octet references to a 400-octet entry | RFC 7541 7.3 | 5.89x plain | 1.10x plain |
       | PRIORITY, empty DATA, unknown types | CVE-2019-9513, 9518 | served | cut |
       | resets the server is made to send | CVE-2025-8671 | served | cut |

       The fixes (src/HttpAsm/h2.asm):
       - **A glitch budget** (nghttp2 1.71's: 10,000 at once, 330 a second): PRIORITY, empty
         DATA without END_STREAM, unknown frame types, refusals, and every stream error the
         peer causes.
       - **Server-provoked resets count:** resets the peer makes the server send count for
         the rapid-reset rule like its own (CVE-2025-8671, "MadeYouReset").
       - **SETTINGS:** checks each `INITIAL_WINDOW_SIZE` in order, then applies the frame's
         net change in one walk over the streams.
       - **WINDOW_UPDATE on stream 0** walks the streams only when a body waits for the
         connection's window.
       - **Stream lookup:** a stream is found by four ids per SSE2 compare.
       - **Empty copies are skipped:** an empty `rep movsb` costs about 30 ns here, because
         FSRM's fast path starts at 1 octet. It made every empty SETTINGS frame's ACK cost
         2.3 times a PING's.
       A non-reading client never grew the heap: the server stops reading the moment its
       socket refuses output, before the 1 MiB mark. `Http2FrameTests` holds the protocol
       side: each glitch flood, the budget's refill, four ways to provoke resets, and
       `INITIAL_WINDOW_SIZE` repeated in one frame (in order, and only the net change applied).
     - **Slow clients, and the deadline that cut transfers.** The deadline was set when a head
       began (HTTP/1.1), when an answer was queued (HTTP/1.1), or when any frame arrived
       (HTTP/2), and expiring closed the connection whatever was in flight. That caused three
       bugs:
       - an answer or an upload that took longer than the idle timeout was cut. In the tests,
         an 8 MiB answer read at about 6 MB/s arrived with 4,453,647 of 8,388,608 octets;
       - an HTTP/2 connection that only sent PINGs stayed open forever;
       - a field block trickled one empty CONTINUATION at a time lived until the CONTINUATION
         limit.

       The idle timeout is now a window judged by progress (Architecture, "Timeouts"). Tests,
       each failing against the old library where it should:
       - `SendsAnswersLongerThanTheIdleTimeout` (both versions) and
         `TakesBodiesLongerThanTheIdleTimeout`;
       - `CutsSlowRequests`: slowloris and RUDY on HTTP/1.1, and slow headers and a slow body
         on HTTP/2;
       - `CutsSlowReaders`: 16 MiB read at 200 octets a second; what arrives is what the
         kernel buffered;
       - `ClosesIdleConnectionsThatOnlyPing`;
       - `AnswersStuckStreams408`: a stuck upload behind a stream of real requests.
     - **Request smuggling** (`SmugglingTests`). The two published mutation sets are
       reproduced octet for octet from their pinned sources (`SmugglingCorpus`):
       - defparam/smuggler's default and exhaustive configs, 750 mutations, UTF-8 as
         smuggler.py sends them;
       - PortSwigger's HTTP Request Smuggler, 94 HTTP/1 Transfer-Encoding and Content-Length
         permutations.

       Each case is judged twice: by `httpasm_h1_parse_request`, and by a strict RFC 9112
       head check written for the test alone. The two agree on all of them. Both tools send
       Content-Length with every mutation, so a server that refuses the two together never
       reads the mangled coding at all. Each Transfer-Encoding mutation therefore runs again
       without Content-Length (827 more), where the coding alone decides.

       Against the parser from before `2ce3f44`, 132 of those disagree (for example,
       `chunked X: X` taken as chunked). The published sets alone would not have caught it.
       PortSwigger's 12 HTTP/2 permutations (CR LF in values, names with spaces, stuffed
       pseudo-fields, `h2CL`) are each refused before any handler sees them.
   - **The coverage gate** (2026-11-26) is on in CI: every marker runs under the tests or is
     listed in `tests/coverage/unreachable.tsv` with its reason, and no listed marker runs.
     A reason is a proof (`unreachable:`), a named condition no test provokes yet (`rare:`),
     or an exemption from going stale: a race (`race:`, between threads or between the worker
     and the kernel's completions) or a kernel's behavior (`kernel:`, since the gate runs on
     WSL's 5.15 and on CI's runner kernel). The walk read every unrun marker, from 678 at the
     first measurement, and gave each a test or its entry. Reading why a branch never ran was
     a bug detector of its own; it found and fixed:
     - a remote heap overflow in the server's trailers, an out-of-bounds read in the client's
       trailers, and an allocation sized by an untrusted Content-Length;
     - a worker at 100% CPU, on both backends, for a client that half-closed and read nothing
       while its answer waited for the socket (epoll's EPOLLRDHUP asked for while output
       waited; io_uring's polls report POLLRDHUP to a poll for room on kernels before upstream
       74c1f1048e44, so a writer's poll is multishot now);
     - a stuck HTTP/2 stream's 408 or reset left unsent until the connection's next activity
       (the expiry now flushes what the sweep answered), the client writing a request into a
       CONNECT tunnel, a connect timeout reported as EINPROGRESS, and a server that could not
       answer during the epoch's first second;
     - a half-closed client losing answers: an HTTP/2 connection closed at the end of the
       stream without its deferred streams' answers, and a FIN seen while an HTTP/1.1
       exchange was deferred counted as the end read, so the requests sent before it were
       never read (the connection closed over them, a reset). Found when CI's gate saw
       markers run in one run and not the next: the faults scenario's deferred HTTP/2 answer
       was encoded only when its thread beat the client's FIN;
     - tests whose comments claimed paths they never reached (each made to reach it, or its
       claim corrected).
     Fault injection became deterministic on the way (`tests/native/faults`). On the
     scenario's own thread, an allocation is named by its ordinal. On the worker and the
     answering threads, it is named by the scenario's step (one connection each), its call
     site and which call of that site it is: an ordinal over threads that run at once named a
     different allocation from run to run, and the HTTP/2 answer's copy went unfailed in one
     coverage run. Every system call's k-th call fails through a seccomp supervisor. Three
     floods joined the corpus, each ending at a glitch site of its own.
4. *Acceleration:* SSE4.2, AVX2 and AVX-512 versions of the hot paths. These are line and
   field scanning, token and value validation, header-name lookup and case folding,
   chunk-size parsing, HPACK's Huffman code and integers, frame headers, and response writing.
   Each is measured against its v1 version and the rivals.
   - **How each change is chosen and proven** (the owner's decisions, 2026-11-26): the
     benchmark framework (`benchmarks/bench.sh`) profiles a routine exactly (SDE's
     instruction counts per function), the change is kept only when its tier verdict, or an
     A/B against the commit before it in 3 processes that agree, proves it faster. Nothing
     AVX-512 is written where it cannot be measured (this machine has none), so the versions
     are v2 (SSE4.2, SSSE3) and v3 (AVX2).
   - **The HTTP/1.1 field lines** (2026-11-26), the first: 55% of a browser request's
     instructions. `ha_h1_fields` scans each line 16 octets a step at v2: the name's octets
     classified as tchar by two pshufb lookups (tables computed from the RFC's definition and
     proven at assembly time for all 256 octets), the value's CR and its forbidden octets
     found in one pass. Request heads parse 1.10-1.18x faster than at v1; picohttpparser's
     lead fell from 2.5x to 1.8x, and llhttp is now slower on every head measured.
     `tests/native/tiers` compares every tier with v1 on 44,850 heads that end against an
     inaccessible page.
   - **The field-name lookup** (2026-11-26), 20% of the browser request's instructions after
     that. `ha_field_lookup` serves HTTP/1.1, HPACK and the writers. At v2 it compares a
     candidate 16 octets at a time against two generated rows per known name (lower case and
     upper case; an octet must equal one of them, which keeps the compare exact for any octet),
     with the key from two 16-bit loads. 1.42x faster than v1 in the same build; against the
     commit before, 1.43x on the lookup alone, 1.06x on HPACK encoding and 1.10x on the API
     POST head, while the browser head ran 10% fewer instructions in the same time: its lookups
     are not on the chain of line scans that sets its time. `tests/native/tiers` compares every
     tier on 279,050 names: every known one, in mixed case, with each octet replaced by near
     misses, against the guard page.
   - **The one-pass request head** (2026-11-26). The classic flow finds the head's end first
     (`ha_find_lf` line by line, every LF checked for its CR), then parses every line again: a
     second pass, 16% of the browser request's instructions, with a loop exit to predict per
     line. From v2 up, a head searched from its request-line (a message's first call) is read
     once: the method and the request-target 16 octets a step (`ha_target_lo`, the target
     class as a pshufb table, proven like tchar's), the HTTP-version and the target's form by
     the classic code, and the field lines by `ha_h1_fields_v2`, which finds the empty line on
     the way and applies the same rules (`H1_FIELD_RULES`, one source expanded in both
     routines). Every read stays below min(len, max_head), the bound no acceptable head
     crosses. The one-pass flow only ever accepts: a refusal, a cut head, a long method or a
     step near a page's end restarts the classic flow, which names the outcome, so the two
     flows cannot disagree (request.asm's `.one_pass` gives the argument). A resumed search
     keeps the classic flow, which scans only the new octets. The browser request now parses
     2.09x faster than at v1 and 1.70-1.72x faster than before (A/B, 3 processes, v1 unmoved),
     and picohttpparser's lead fell from 1.79x to 1.03x. `tests/native/tiers` adds 340,298
     parses: request-lines of every form and error, framing fields that pass and fail each
     rule, small limits, heads resumed after a cut, and every prefix of one head in 16, all
     against the guard page.
   - **HPACK's Huffman decoding** (2026-11-26). An HTTP/2 server decodes a header block on
     every request, and a browser request's block cost 2.3 us, 60% of it in the Huffman
     automaton: two dependent table loads per octet, about 10 cycles per symbol. From v2 up a
     table decoder takes the next 12 bits at a time from a 64-bit window: one lookup in
     `ha_huff_pair` (generated, 16 KiB) gives up to two symbols, their bits and their count;
     the bits sit in the dword's low byte, so the load feeds the window's shift directly; codes
     past 12 bits go to the canonical tables (`ha_huff_limit`, `_offset`, `_sorted`; the
     generator checks the code is canonical), and a string's last bits to `ha_huff_first_bits`
     (its last symbol and its padding, without a search). Errors, padding and the room are v1's
     exactly: `tests/native/tiers` compares every tier on 233,032 decodes of valid and arbitrary
     Huffman strings against the guard page, with the room from none to plenty. The block
     decodes 1.49x faster than at v1, and nghttp2 is now 2.2x slower than HttpAsm. At v3 the
     same decoder (one macro, `H2_DECODER`) shifts its window with BMI2's `shlx`, which
     touches no flags (`shl` by `cl` merges them, so each shift waited for the compare before
     it): 3.5-5% faster than v2 in the same build, two runs agreeing (`tiers/hpack_decode`).
   - **Whole-token checks and the response writer** (2026-11-27). `ha_token_length` scans a
     token 16 octets a step from v2 (the writers' field names, `httpasm_field_id`,
     `httpasm_token_length`: a 45-octet name 4.6x faster); the writer copies its pieces with
     moves sized to each (no `rep movsb`, whose start-up cost was most of each short copy) and
     makes its decimal digits by multiplication. A 200 with six fields is written 1.17x faster.
     `tests/native/tiers` checks the token scan at every tier on 206,680 inputs against the RFC.
   - **HPACK's Huffman encoding** (2026-11-27). The encoder summed each string's code
     lengths octet by octet, then wrote the codes an octet per flush (7 instructions an
     octet). The sum now takes four octets a step into two independent sums, and the codes go
     out 32 bits at a time (one byte-swapped store): the browser request's 18 fields encode
     1.67x faster at every tier, octet for octet the same block (60,000 blocks compared
     between the two builds).
   - **Chunk sizes** (2026-11-27). The chunked decoder is a state machine that keeps its
     state between calls, octet by octet: about 20 instructions per octet of framing, most of a
     small chunk's cost. At a chunk's first octet it now takes a whole chunk at once when the
     size line is plain and the chunk is all here (the size in registers, the data moved down
     by moves sized to it, both CRLFs checked before anything is written), and gives anything
     else (extensions, whitespace, a numeral the state machine refuses, a chunk not all here)
     back to the state machine at that octet, unchanged: 2.6x faster on 16-octet chunks, 1.04x
     on 1 KiB ones (the copy dominates). Serves every tier; the chunked fuzzer's oracle checks
     it whole, in reads and one octet at a time (4.5 million inputs, the corpus merged).
   - **The one-pass response head** (2026-11-27), the client's side of the same change. From
     v2 up, a response head searched from its start is read once: the status-line's 13 fixed
     octets by the classic checks, the reason-phrase 16 octets a step to its CR, and the field
     lines by `ha_h1_fields_v2` in the response mode (a second rule table, `h1_response_rule`:
     only the framing rules). The response parser rewrites an obs-fold in place, which only the
     classic flow does: the one-pass flow hands such a head back untouched, as it hands back a
     refusal, a cut head or a step near a page's end, so the two flows cannot disagree
     (response.asm's `.one_pass`). A typical 200 with twelve fields parses 2.16x faster than
     at v1 (186 ns) and 1.60-1.62x faster than before (A/B, 3 processes); picohttpparser's lead
     of 1.6x is gone (1.009x, noise), and llhttp takes 2.16x as long. `tests/native/tiers` adds
     330,147 response parses at every tier, each tier on a fresh copy of the input with the
     octets each parse leaves in the buffer compared too (the obs-fold rewrite), and a stale
     resume point past the data (now documented in `httpasm.h`: ignored, the search starts
     over), which the coverage gate found untested.
   - **HTTP/2's request rules** (2026-11-27). On the browser request's 18 fields
     `httpasm_h2_request` ran 5,133 instructions, 30% of them in `h2_name` (each name octet by
     octet) and 512 in the `:path`'s octet loop. From v2 both use `ha_span_v2`, one routine for
     every span of a nibble-table class (`ha_token_length`'s v2, made a routine: the table in
     `xmm3`): names with `ha_ltchar_lo` (a tchar but A-Z, proven like tchar's), the `:path` by
     runs of target octets between percent-encodings (`ha_target_lo`). Pseudo-field names are
     compared by two loads instead of `repe cmpsb`. 3,706 instructions; 1.13-1.16x faster
     (A/B, 3 processes). v1 measured 0.90-0.92x of itself before: its two loops had moved, and
     starting them on 32-octet windows brought it to 0.97x, the rest being the per-name tier
     test. `tests/native/tiers` compares every tier on 70,165 header lists, names and paths
     against the guard page.
   - **Frame headers and HPACK integers: measured, nothing to gain** (2026-11-27). The whole
     server under SDE (one worker, h2load, 20,000 HTTP/2 requests one at a time): 4,960
     user-space instructions a request, of which reading a frame's 9-octet header is about 20
     (0.4%) and writing the answer's frames about 105 (2%); a header block's integers are 2.9%
     of its decoding (6 instructions each on the one-octet path every index and length in a
     browser's block takes). Nothing there for vectors, and less than the A/A noise for scalar
     work. The same profile shows where an HTTP/2 request's instructions go instead: the request
     rules (about 20%, `:authority`'s octet-by-octet grammar the largest part on a short
     request), HPACK (18%), the allocator (11%: a stream and a head block per request, freed
     after), the head's copy into its stream (9%).
   - **AVX2 for the one-pass head: measured, not kept** (2026-11-26). 32-octet steps (with a
     VEX-encoded lookup) ran 13.5% fewer instructions and 1-2% more time than v2 in the same
     build (`tiers/h1_parse_request`, every tier): a head's time is the chain from one line's
     end to the next line's start, which wider steps do not shorten. v3 runs v2's code.

*H is done when:* the coverage gate passes; set-length fuzzing campaigns run clean (short ones
in CI); differential fuzzing has no untriaged difference; every row passes on every tier and
both backends; the measurements are recorded.

*The closing campaign* (2026-11-27, every fuzzer 600 s on one core each, every input at every
tier the CPU has, after step 4's last change): h1_request 85.2 million inputs, h1_request_diff
43.8 million (every difference from llhttp and picohttpparser in its triaged classes), h1_response
62.2 million, chunked 33.9 million, h2_request 104.2 million, hpack 46.3 million, hpack_nghttp2
2.0 million (no difference from nghttp2), h1_write 2.5 million, client 5.1 million, server 3.7
million: clean, once the campaign's one finding (the client's trailer refusals, above) was fixed.
CI's 30-second campaigns found the other (the HPACK encoder's names, above) the same day.

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
   - **The vectors** are pinned in `tests/tools.sh` like the test tools: NIST's CAVP archives
     (from 2026-11-27, SHA-1/SHA-2's byte-oriented ShortMsg, LongMsg and Monte files), and
     Project Wycheproof's files at commit 65ca494 (2026-11-11) as each primitive needs them.
     `tests/run-linux.sh` names the directory in `HTTPASM_VECTORS` with
     `HTTPASM_REQUIRE_VECTORS=1`, so a vector test cannot skip there.
   - **Constant time** (2026-11-27), `tests/ct/run.sh` (CI runs it): every function of the C ABI
     that takes a secret runs under valgrind's memcheck with the secret marked undefined
     (`tests/native/ct.c`: hashes, HMAC and HKDF, AES and its GCM, ChaCha20, Poly1305 and their
     AEAD, X25519 and X448, P-256, P-384 and P-521's public keys, shared secrets and signatures,
     n - 18 among P-521's keys, Ed25519 and Ed448, ML-KEM's three sizes with a valid and a
     tampered ciphertext, FFDHE, RSA's prepared keys and both signatures at 1024 and 2048 bits),
     at every tier valgrind's CPU offers (v1, v2, v3). memcheck follows undefinedness bit by bit
     and reports a branch, a memory address or a system call argument it reaches; cmov, masks,
     adc of masks and table scans by mask are data flow, which it lets through, so the check
     sees exactly what constant time forbids. The library under it is the ConstantTime build
     (`Directory.Build.props`: `-DHTTPASM_CT`), which differs from Release in two ways:
     `HA_DECLASSIFY` (`httpasm_core.inc`) marks defined the few values computed from a secret
     whose outcome is public by design, each at its site with its reason (a private key refused
     as out of range, RFC 6979's redrawn candidate, r or s of 0, an AEAD tag's verdict, X25519's
     and X448's all-zero output, ML-KEM's rho and dk's embedded ek, an RSA prime's length and its
     key's checks); and its CPU detection takes ADX with BMI2, which valgrind's CPU executes but
     does not report, so the curves' and RSA's mulx/adcx/adox versions run too. A negative
     control (a branch on a secret octet) must be reported first. What memcheck cannot run is
     named in the script: the SHA extensions and VAES (valgrind raises SIGILL; the AES-NI and
     scalar versions run instead) and AVX-512, straight-line versions that tests/native/tiers
     proves equal to v1. *Its first run found* (all fixed in the same commit, each a site memcheck
     named): RSA's private numbers (p, q, dp, dq, q^-1) and signing's EM were loaded by
     rsa_load_be, which skips leading zero octets and so looked at secret ones (now
     `rsa_load_secret`: every octet placed by its position, the octets past the limbs ORed into
     one verdict); p q = n, the key's test signature and signing's fault check compared with
     `repe cmpsq`, which stops at the first differing limb of a secret value (now `rsa_differ`:
     an OR of XORs, one verdict); and RS_LEAVE wiped the 4 KiB under the frame below rsp, which
     the System V ABI does not lend beyond the red zone (now rsp moves down over them first). Its
     reports also showed the expected public-by-design sites above, and no finding in the curves,
     the Edwards and Montgomery code, ML-KEM, the AEADs or the hashes. The fixes cost nothing
     measurable: `bench.sh ab` against the commit before them (RSA signing at 2048, 3072 and
     4096 bits with both paddings, key preparation, verification, FFDHE2048) says "no
     difference" at the best tier and at v1, every process within 0.991x to 1.010x. Measured:
     under a minute with the build (the memcheck run itself about five seconds).
     *On the hardware,* `tests/ct/dudect.sh` (local only, like the benchmarks: a shared runner's
     timing is noise) applies dudect's method (Reparaz, Balasch and Verbauwhede, DATE 2017) to
     what memcheck cannot run or cannot see: the best tier's SHA-extension and VAES versions (and
     AVX-512's on a CPU that has it), and instructions whose latency follows their operands. A
     fixed secret chosen to be special (zero keys, d = 1, P-521's n - 18, a valid ML-KEM
     ciphertext, RSA's zero digest, FFDHE's exponent 2^255) and random ones are interleaved in a
     random order, each call timed with rdtscp between lfences, and Welch's t compares the classes
     over all times and below the 99th, 95th, 90th, 75th and 50th percentiles; |t| above 10
     fails, above 4.5 warns (dudect's thresholds). A negative control must fail first: a 64-octet
     compare that stops at its first differing octet (about 135 ticks a call) reached t = 339
     in 20,000 calls. On the i9-13900K (WSL, pinned to one performance core; 2026-11-28, scale 4:
     8,000 to 800,000 calls a line) all 22 lines, eleven functions at v1 and at the best tier
     (v3 with VAES and the SHA extensions; no AVX-512 there), pass: the largest |t| is 2.49.
     Median TSC ticks, v1 / best: AES-256-GCM sealing 1 KiB 28,786 / 612; ChaCha20-Poly1305
     3,814 / 2,564; HMAC-SHA256 of 64 octets 3,288 / 910; X25519 115,174 / 97,348; P-256 ECDH
     159,284 / 154,790 and signing 61,646 / 46,396; P-521 ECDH 1,300,968 / 769,164; Ed25519
     signing 36,046 / 30,530; ML-KEM-768 decapsulation 169,518 / 32,644 (valid and implicitly
     rejected ciphertexts alike); RSA-2048 PKCS#1 signing 3,856,596 / 1,684,814; FFDHE2048's
     public key from a 256-bit exponent 2,040,564 / 892,196. A pass bounds an effect (none this
     many calls could see), it does not prove there is none: memcheck's run is the proof, this
     the hardware's witness. Scale 1 takes 23 seconds with the build.
   - **SHA-256** (2026-11-27), `crypto/sha256.asm`: the running hash and the one-shot form of
     the C ABI (`httpasm_sha256_ctx`), over `ha_sha256_blocks` in two versions: v1 the 64
     rounds unrolled with the working variables renamed by the assembler (no moves between
     rounds), and the SHA extensions' (`sha256rnds2`, `sha256msg1/2`; with SSSE3 and SSE4.1).
     Constant time by construction: no branch or address depends on the data. `final` wipes
     the context and its stack pad. Proven by NIST's 65 short, 64 long and 100 Monte Carlo
     checkpoints at every tier, by .NET's SHA256 on every length to 1,000 octets fed in random
     pieces, and by `tests/native/tiers` against the guard page (15,903 digests). Against
     OpenSSL 3.0.13's `SHA256` on the i9-13900K: 4.38x faster on 64 octets (103.5 against
     453.5 ns: OpenSSL 3's one-shot fetches its provider per call), 1.44x on 1 KiB, level on
     16 KiB (1.41 against 1.37 octets/ns: both at the SHA extensions' own speed). v1 runs at
     0.22x of them. Next for CPUs without the SHA extensions (Intel's client cores before 2021):
     a v3 version with BMI2's `rorx` and an AVX2 message schedule, measured against v1 with the
     SHA bit capped off.
   - **HMAC-SHA256 and HKDF-SHA256** (2026-11-27), `crypto/hmac.asm`, over SHA-256's public
     functions (so SHA-384's versions will be the same code): the HMAC context holds both
     hashes already past their key blocks, the key itself is not kept, and a copy of a fresh
     context MACs under the same key without hashing it again, which HKDF-Expand does once per
     output block. K0, the pad blocks, the inner digest and HKDF's T(i) are wiped before each
     function returns. Proven by RFC 4231's seven examples, NIST's CAVP HMAC file (every
     SHA-256 record, truncated tags included), Wycheproof's 174 HMAC and 86 HKDF tests (the
     8,160-octet limit refused without a write), and .NET's HMACSHA256 and HKDF on random
     keys, messages and lengths, at every tier. Against OpenSSL 3.0.13's `HMAC()`: 6.0x faster
     on 64 octets (253 against 1,524 ns), 2.31x on 1 KiB; HKDF-Expand of one 32-octet key from
     a 32-octet secret takes 230 ns (four SHA-256 compressions), 3.83x v1's.
   - **SHA-512 and SHA-384** (2026-11-27), `crypto/sha512.asm`: one context
     (`httpasm_sha512_ctx`, 208 octets) and one update for both, two inits and two finals (the
     H(0) and the digest's length are all that differ), one-shot forms, over
     `ha_sha512_blocks` in two versions: v1 the 80 rounds unrolled as SHA-256's, with K(t) +
     W(t) added to h before anything that waits for e; v3 (AVX2 with BMI2) the message
     schedule of two blocks at once in YMM registers (one block a 128-bit lane, since
     `vpalignr` and the shifts work per lane; sigma0's ROTR8 as one `vpshufb`), stored as
     W + K while the first block's rounds run and read again by the second block's, and
     scalar rounds with `rorx` and `andn` in the arrangement of OpenSSL's "AVX2 + BMI" code
     (Ch and Maj summed into h piece by piece, a ^ b kept as the next b ^ c, Sigma0 added to
     the next a one round late); a lone last block runs in both lanes. Proven by NIST's
     129 short, 128 long and 100 Monte Carlo checkpoints of each, .NET's SHA512 and SHA384 on
     every length to 1,100 octets in random pieces, and `tests/native/tiers` against the guard
     page. The round sets the speed: alone it takes 6.9 cycles on this core where its
     dependencies allow 5.0 (a dataflow count over 400 rounds); 72 random valid reorderings of
     its 24 instructions, the r13-based LEAs as adds, and copies moved off the chain changed
     nothing beyond the noise, and Intel's arrangement (the Linux kernel's) runs 7.6. So bulk
     hashing is level with OpenSSL, which runs the same rounds; short messages are not.
     Against OpenSSL 3.0.13's `SHA512`/`SHA384`: 2.60x faster on 64 octets (241.5 against
     628.3 ns), 1.20x on 1 KiB, level on 16 KiB (0.61 octets/ns each); v3 is 1.26x v1. The
     SHA512 extensions (Arrow Lake and later) wait for a CPU that can measure them. Next for
     HMAC: the key setup's two compressions (K0 ^ ipad, K0 ^ opad) are independent, so one
     interleaved pass could take them at the cost of about one.
   - **HMAC-SHA384 and HKDF-SHA384** (2026-11-27), TLS_AES_256_GCM_SHA384's key schedule:
     `crypto/hmac.asm` now writes each hash's six functions from one macro (names, block and
     digest sizes, the context's size as literal move counts, so the coverage build's
     preprocessor can expand it); the SHA-256 instance is instruction for instruction the code
     it replaced (objdump compared). `httpasm_hmac_sha384_ctx` is two `httpasm_sha512_ctx`
     (416 octets); HKDF-Expand refuses past 255 * 48 = 12,240 octets. Proven by RFC 4231's
     seven SHA-384 examples, NIST's 300 [L=48] MACs (keys of 50 to 145 octets around the
     128-octet block, tags of 24 to 48), Wycheproof's 174 HMAC and 83 HKDF tests (pinned at
     65ca494 beside SHA-256's), and .NET's HMACSHA384 and HKDF to the limit, at every tier.
     Against OpenSSL 3.0.13's `HMAC()` with `EVP_sha384()`: 2.39x on 64 octets (941.7 against
     2,251 ns: four SHA-512 compressions), 1.50x on 1 KiB; HKDF-Expand of 48 octets from a
     48-octet secret 985 ns, 1.17x v1.
   - **HMAC-SHA512 and HKDF-SHA512** (2026-11-27), RFC 6979's HMAC at P-521 (its HMAC_DRBG
     runs on the digest's hash: ecdsa_secp521r1_sha512's nonces are HMAC-SHA512's): the macro's
     third instance (`crypto/hmac.asm`; SHA-512's start, final and one-shot hash declared there,
     as `crypto/ed25519.asm` and `crypto/rsa.asm` declare them). `httpasm_hmac_sha512_ctx` has
     SHA-384's layout (two `httpasm_sha512_ctx`, 416 octets, struct size 22); HKDF-Expand refuses
     past 255 * 64 = 16,320 octets. No TLS 1.3 cipher suite uses either; both are in the C ABI for
     a caller's protocol. Proven by RFC 4231's seven SHA-512 examples, NIST's 375 [L=64] MACs
     (keys of 100 to 142 octets around the 128-octet block, tags of 32 to 64), Wycheproof's 174
     HMAC and 83 HKDF tests (pinned at 65ca494), .NET's HMACSHA512 and HKDF to the limit, and the
     three HMACs told apart under one key, at every tier. Against OpenSSL 3.0.13's `HMAC()` with
     `EVP_sha512()` (41 rounds): 2.41x on 64 octets (961 against 2,315 ns), 1.51x on 1 KiB.
   - **The AES block cipher** (2026-11-27), `crypto/aes.asm`: AES-128 and AES-256 encryption
     (no AES-192: no TLS 1.3 or QUIC suite uses it; no decryption: GCM, CTR and QUIC's header
     protection never decrypt with the block cipher). Two versions: AES-NI (`aeskeygenassist`
     for the schedule), and v1, constant time without a table (a lookup indexed by key or data
     leaks them through the cache): eight blocks bitsliced over `xmm0-xmm7` with SSE2 only, each
     64-bit lane four blocks in the arrangement of BearSSL's `aes_ct64` (Thomas Pornin, MIT:
     interleave, ortho, ShiftRows and MixColumns as shifts inside a lane; MixColumns' rotations
     here one `pshuflw`/`pshufhw`/`pshufd` each), and the S-box as Boyar and Peralta's circuit
     (115 gates, `specs/circuits/aes_sbox.txt`). `specs/circuits.cs` (a new generator, checked
     in CI) proves that circuit on all 256 inputs against the S-box computed from FIPS 197's
     definition, allocates its values to the 16 XMM registers and 13 spill slots by Belady's
     farthest-next-use rule, runs the generated 192 instructions on all 256 inputs at once as
     bit planes, and only then writes `include/generated/aes_sbox.inc`. v1's key schedule
     computes SubWord with the same circuit. Every key holds both schedules (FIPS 197's round
     keys and v1's compressed ones), so a key made at one tier works at every other. Designed in
     a Python model first (scratchpad `ct64_model.py`: every piece against `cryptography`),
     then translated. Proven by FIPS 197 appendices A and C, NIST's AESAVS ECB known answers
     (GFSbox, KeySbox, VarKey, VarTxt: 568 AES-128 and 810 AES-256 records), .NET's AES on
     4,000 random keys and blocks (in place too), and `tests/native/tiers` (80,000 keys made
     and used at every pair of tiers). One chained block: AES-NI 12.8 ns (AES-128) and 16.9 ns
     (AES-256), level with OpenSSL 3.0.13's EVP; v1 544 and 728 ns, eight blocks' work for
     one, which counter mode fills.
   - **AES-GCM** (2026-11-27), `crypto/gcm.asm`, as TLS 1.3 and QUIC use it: 12-octet nonces,
     16-octet tags, `httpasm_aes_gcm_init`/`_seal`/`_open` over a 1024-octet key (the AES key,
     H, and H^16..H^1 reflected and twisted with their Karatsuba halves). Two versions: AES-NI
     with PCLMULQDQ (counter mode eight blocks at a time; GHASH eight blocks per reduction, each
     times its own power of H, OpenSSL's twisted-H arrangement with the two-phase shift
     reduction; round keys and powers copied to the stack because the legacy SSE forms need
     aligned memory and the key need not be aligned), and v1, constant time (counter mode by the
     bitsliced cipher, eight counters a call, J0 among the first eight; GHASH by integer
     multiplications of bit-spread operands, BearSSL's ghash_ctmul64 design). The init computes
     the powers with PCLMULQDQ where it can and with v1's multiplication otherwise: the same
     octets either way, so any tier uses any key. open hashes the ciphertext before writing over
     it (in place works), compares tags without data-dependent branches, and zeroes its output on
     a mismatch. SP 800-38D's limits (2^36 - 32 octets of text, 2^61 - 1 of AAD) are refused
     before anything is touched. Both GHASH arrangements were modeled in Python first (every
     operation as the instructions do it) against GHASH computed bit by bit from the standard.
     Proven by NIST's CAVP GCM files (all 96-bit-IV records of AES-128 and AES-256: 2,625
     encrypt and 2,625 decrypt each, every tag length, 1,363 and 1,317 marked FAIL), Wycheproof's
     133 tests, .NET's AesGcm on 3,000 random cases (in place, and forgeries in the tag, the
     ciphertext and the AAD refused with zeros), and `tests/native/tiers` (keys and seals equal at
     every tier, outputs fenced by canaries). Against OpenSSL 3.0.13's EVP (a TLS 1.3 shape: the
     key set once, a new IV and a 5-octet AAD per record): 2.6x faster on 64 octets, 1.29x on
     1 KiB, but 0.73x on 16 KiB (3.77 against 5.14 octets/ns): OpenSSL's code interleaves the
     AES rounds of the next blocks with the GHASH of the last ones, this version does one after
     the other. A third version followed the same day: VAES with VPCLMULQDQ (v3), sixteen
     blocks a step in eight YMM pairs, the GHASH of sixteen blocks interleaved with the AES
     rounds (one register pair after each of the first eight rounds; measured first: `vaesenc`
     ymm 2 a cycle, `vpclmulqdq` ymm 1 a cycle on another port, the two together 2.7 a cycle),
     seal hashing the previous step's output, open its own input; the last octets (under 256)
     one more step through a zeroed buffer and one aggregated GHASH. Its first build was right
     at every tier, and slow on 16-255-octet tails: 1,520 cycles against 254 for 1 octet,
     because `ha_copy_short`'s legacy SSE `movdqu` ran with the YMM upper halves live (the
     AVX-SSE transition); a VEX copy (`gcm_copy_vx`) brought them to 227-279. Measured against
     OpenSSL 3.0.13's EVP: 2.91x on 64 octets (76.7 against 223.0 ns), 2.69x on 1 KiB, 1.85x on
     16 KiB (9.51 against 5.15 octets/ns); AES-256-GCM 2.65x and 1.84x; the VAES version 2.06x
     and 2.50x the AES-NI one. Then the same interleaving for the AES-NI version (the path of
     CPUs without VAES: Intel's before Ice Lake, AMD's Zen 1 and 2): eight blocks a step, one
     GHASH block after each of AES rounds 1-8, the seal lagging a step, and the batched tail
     (one step through a zeroed buffer, one aggregated GHASH of up to eight blocks): 16 KiB 1.30x
     faster than before (3,350 against 4,358 ns, 4.89 octets/ns: level with OpenSSL's 5.14,
     whose AVX code is of the same kind), 1 KiB 1.21x (262 ns, 1.56x OpenSSL), 255 octets 173 to
     127 ns. Its legacy SSE forms need copies a VEX form would not: a VEX xmm version for CPUs
     with AVX but no VAES is the next lever there.
   - **ChaCha20-Poly1305** (2026-11-27), `crypto/chacha20_poly1305.asm`, RFC 8439 as TLS 1.3
     (TLS_CHACHA20_POLY1305_SHA256) and QUIC use it: `httpasm_chacha20` (the raw cipher, with
     its 32-bit block counter wrapping as RFC 8439 defines it; QUIC's header protection takes
     one block of it), `httpasm_poly1305` (the one-time authenticator alone),
     `httpasm_chacha20_poly1305_seal` and `_open` (12-octet nonces, 16-octet tags, keys as raw
     octets: ChaCha20 keeps no schedule and Poly1305's key is new for every message). ChaCha20
     in three versions: v1 (SSE2) and v2 (SSSE3's pshufb for the byte rotations) four blocks at
     once, each XMM register one state word of the four (OpenSSL's ChaCha20_4x arrangement:
     two words of the third row wait on the stack, swapped in pairs twice a double round); v3
     (AVX2) eight blocks in YMM registers the same way; and in every version, work of 128
     octets or less through two blocks side by side in the horizontal layout (a block's rows in
     four registers, its diagonals lined up by pshufd), whose time is one block's chain of
     dependent instructions. Poly1305 on 64-bit limbs (h0, h1 and a small h2; s1 = r1 + r1/4
     folds the products past 2^128 back as 2^130 = 5), mul at v1 and v2, mulx at v3; partial
     reduction after each block, one conditional subtraction (cmov) at the end. The AEAD
     interleaves the two, as BoringSSL's AVX2 code does: Poly1305 hashes one block after each
     pair of quarter rounds of every four- or eight-block step (20 or 40 slots for 16 or 32
     blocks made), on the integer units while the vector units run ChaCha20; seal hashes the
     ciphertext written in earlier steps, open its input ahead of the output (in place works).
     The one-time key is block 0, made with block 1 in the horizontal layout before anything
     else. Proven by every test vector of RFC 8439 itself, read from the pinned text (the block
     function, encryption, Poly1305 with the reduction's edge cases, key generation, the AEAD
     both ways), Wycheproof's 316 tests with 96-bit nonces (65ca494), .NET's ChaCha20Poly1305
     on 3,000 cases (every driver path's edge lengths, in place, forgeries refused with zeros),
     a BigInteger Poly1305 on 4,000 random and extreme keys and messages, a plain C# ChaCha20
     across the counter's wrap, every bit of the tag (RFC 8439 4: no truncation), and
     `tests/native/tiers` (4,000 rounds of cipher, MAC, seal and open equal at every tier, 16 KiB
     records against the guard page). Measured (benchmarks/bench.sh, 11 rounds, the TLS 1.3
     shape: a new nonce and a 5-octet AAD per record) against OpenSSL 3.0.13's EVP: 2.12x on
     64 octets (208.6 against 443.3 ns), 1.14x on 1 KiB, 1.14x on 16 KiB (1.89 against 1.66
     octets/ns); v3 is 1.84x v1 on 16 KiB, v2 1.17x. The stitching was proven by a build
     without it (Poly1305 after the cipher): 16 KiB took 1.50x as long at v3, 1.40x at v2,
     1.34x at v1. Alone, ChaCha20 runs at 1.11 cycles an octet and Poly1305 at 1.01 (its chain
     of about 15 cycles a block); together 1.44: the scalar Poly1305 uops the scheduler sends
     to ports 0, 1 and 5 take slots from ChaCha20's vector work. Measured and not kept: products
     reordered (2.5% slower: h1 s1 last delays the carry the chain waits for) and the fold's
     times 5 as one lea (3% slower Poly1305). Kept: a short record's driver wipes only the frame
     octets its path wrote (11% faster on 64 octets at v3).
   - **X25519** (2026-11-27), `crypto/x25519.asm` over `include/crypto/fe25519.inc` (the field,
     Ed25519's too): `httpasm_x25519` (the shared secret; -1, with the zeros written, when
     the result is all zeros, a small-order point that TLS 1.3 must refuse, RFC 9846 7.4.2)
     and `httpasm_x25519_public_key` (the scalar times u = 9). One Montgomery ladder, RFC 7748
     5's step for step (scalar clamped, u's bit 255 masked and non-canonical u taken modulo p,
     swaps by mask, x2 / z2 by Fermat with ref10's addition chain, until Ed25519 brought
     `ha_modinv256`, below), expanded over two fields:
     v3 (BMI2 and ADX) four 64-bit limbs kept below 2^256 (modulo 2^256 - 38 = 2p), sixteen
     mulx a product in two carry chains (adcx on CF, adox on OF; OpenSSL's fe64 arrangement),
     ten for a square; v1 five 51-bit limbs with mul, the 19-folded products summed per limb
     (curve25519-donna's arrangement). Measured on the parts first (latency through the frame,
     and four independent at once): a product 48 and 26 cycles, a square 40 and 22, an addition
     13; then the ladder in RFC 7748's order of operations took 128k cycles a call in either
     version, about 500 a step, where the parts allow about 300: only operations adjacent in
     the code overlap (the reorder buffer holds about five of them). With the independent ones
     side by side (the two products DA and CB with the two squares, then x2's product, E, the
     squarings and the multiplication by 121666) a call takes 97.5k cycles at v3 and 111k at
     v1. Proven by RFC 7748's vectors read from the pinned text (5.2's two and its iterations
     to 1,000, 6.1's Diffie-Hellman example), Wycheproof's 518 tests (65ca494: twist points,
     non-canonical and small-order public keys, the 31 zero results reported), the ladder in
     BigInteger on 300 random cases, the small-order points under random scalars, and
     `tests/native/tiers` (every tier equal to v1, inputs against the guard page). Measured
     (benchmarks/bench.sh, 9 rounds): 33.8 us a shared secret at v3, 1.20x v1, 1.18x OpenSSL
     3.0.13's EVP derive alone (40.2 us); a TLS 1.3 key share (the public key and the shared
     secret) 68.3 us, 1.28x OpenSSL's per-handshake EVP sequence (87.3 us). Then z2 inverted by
     safegcd (`ha_modinv256`, `crypto/inverse.asm`, on z2 fully reduced so a small-order point's
     0 still comes back 0) in place of the chain: 2.11 us against 3.76 at v3 and 4.03 at v1;
     `bench.sh ab` against 9ba6d8d, three processes: a shared secret 1.047-1.051x at v3 and
     1.055-1.057x at v1 (the tiers suite, proven at every tier), a key share 1.052-1.065x
     (proven); 32.3 us a shared secret at v3, 37.8 at v1. Then the public key from a
     precomputed table of base-point multiples, as this entry planned: Ed25519's fixed base
     (`ha_x25519_base_v` in `crypto/ed25519.asm`: k B on edwards25519 from its 43-window table,
     constant time, then u = (Z + Y) / (Z - Y) by RFC 7748 4.1's birational map, which takes B to
     u = 9), the ladder's octets on 2,062 scalars and every tier; `bench.sh ab` against e5a7526:
     a public key 3.65x, 3.57x, 3.64x (8.92 us against 32.5; OpenSSL 44.0: 4.9x), a key share
     1.540x, 1.538x, 1.535x at v3 and 1.56x at v1 (41.2 us; OpenSSL 87.0: 2.1x), all proven.
   - **Randomness** (2026-11-27), `src/HttpAsm/random.asm` (the OS-side library: the core makes
     no system call): `httpasm_random(buffer, length)`, getrandom(2) with no flags (the urandom
     source: it blocks only until the kernel's pool is first initialized, at boot). Short reads
     (past 32 MiB - 1, or a signal after some octets) and -EINTR (a signal before any) are
     continued until the buffer is full; a refusal (-ENOSYS, a seccomp filter's -EPERM,
     -EFAULT) is returned, with nothing weaker substituted; a filter that answers "error 0"
     (no octets, no error) is -EIO, not a spin. Proven by `tests/native/random` (every length
     to 4 KiB and 64 MiB, a 1 MiB histogram's chi-square, ten 64 MiB fills under a 50 us
     interval timer without SA_RESTART, about 37,000 signals, and the three refusals each in a
     forked child behind its own seccomp filter) and RandomTests (lengths 0-300 and to 1 MiB,
     nothing written past the end; 1,000 32-octet values all different; the histogram).
   - **P-256** (2026-11-27), `crypto/p256.asm` over `include/crypto/p256.inc`:
     `httpasm_p256_public_key`, `httpasm_p256_ecdh` (TLS 1.3's secp256r1 key share and the
     ECDH half of SecP256r1MLKEM768), `httpasm_p256_sign` and `httpasm_p256_verify` (ECDSA as
     ecdsa_secp256r1_sha256 and certificates use it). Keys are SEC 1's uncompressed points
     (04, x, y) and 32-octet scalars, signatures r || s. *The field:* Montgomery form, four
     64-bit limbs fully reduced, Gueron and Krasnov's reduction for this p (the quotient is the
     low limb, m p one product), in two versions: v3 mulx with adcx/adox, v1 mul. *Points* in
     Jacobian coordinates, infinity as all zeros: OpenSSL's doubling (4M + 4S), add-2007-bl and
     madd-2007-bl, an input at infinity replaced by mask after the addition. *Scalar
     multiplications,* constant time (every table entry read and masked, digits from public
     positions only): the variable base by 5-bit Booth digits over a table of 1P..16P (52
     windows, five doublings and one addition each), the fixed base by 7-bit Booth digits over
     37 tables of 64 affine points (151.5 KB, `include/generated/p256_table.inc`, written by
     `specs/p256.cs`, which proves the curve, every constant and every point by a second route
     first; CI checks it), one mixed addition a window. *No addition meets the doubling case*
     for a scalar k in [1, n - 1], so the formulas skip it: in the fixed base, the accumulator
     before window j is A G with A = (k mod 2^(7j)) - b 2^(7j) (Booth's digits telescope; b the
     bit below the window), |A| <= 2^(7j - 1), and the addend is d 2^(7j) G with 1 <= |d| <= 64,
     so A +- d 2^(7j) is nonzero and, below the top window, smaller than n; in the top window
     A + d 2^252 is k itself and A - d 2^252 = k - 2d 2^252 vanishes modulo n only for a k whose
     own top digit is not d (each d from 1 to 16 checked). In the variable base the
     accumulator before window j is B P with B a multiple of 32 and the addend d P with
     1 <= |d| <= 16, so B +- d is nonzero and below n except in window 0, where B + d = k and
     B - d = k - 2d is a multiple of n only for k = 2d or n + 2d, neither of which has d as its
     low digit (n = 17 mod 32). The accumulator is infinity exactly until the first nonzero
     digit, which the masks handle. *Inversions* (to affine, ECDSA's k^-1 and s^-1): Bernstein
     and Yang's divsteps in libsecp256k1's modinv64 arrangement (590 half-delta divsteps in 10
     batches of 59 on the low 62 bits, the 2x2 matrix then applied to f, g and the Bezout
     coefficients in signed 62-bit limbs), constant time, one routine for p and for n.
     *ECDSA:* the nonce is RFC 6979's (HMAC-SHA256: RFC 6979's own k for a SHA-256 digest),
     hedged with the caller's 32 octets of entropy as RFC 6979 3.6's extra input when given;
     a digest of any length counts by its leftmost 256 bits (FIPS 186-5 6.4.1). Verification
     (inputs public, so variable time) computes u1 G + u2 Q in one pass from the top (Straus):
     wNAF digits, u1's by 7 bits over G's odd multiples (the fixed-base table's window 0 holds
     1G..64G: no table of its own), u2's by 5 bits over 1Q..15Q built per call, the doublings
     shared, the additions branching on infinity and on equal and opposite points (a crafted key
     or signature can bring them about; the tests build one of each); then it compares x(R)
     with r in Jacobian coordinates (X = r Z^2, or (r + n) Z^2 when r + n < p) without an
     inversion. The first version (a90bcdf) ran both constant-time multiplications: 65.1 us
     against 55.6 now. *Validation:* a public
     key must be 04 || x || y with x, y below p on the curve (RFC 9846 4.2.8.2; it also stops
     the invalid-curve attack); private keys, r and s must be in [1, n - 1]; every refusal
     writes zeros where there is an output. Proven by RFC 6979 A.2.5 read from the pinned text
     (pinned with this entry: the key pair, the two SHA-256 signatures exactly, all ten
     verified), NIST's CAVP P-256 records (KAS ECC CDH's 25; FIPS 186-4's KeyPair 10, PKV 12,
     SigGen 60 with each k's point checked, SigVer 75 with SHA-1 to SHA-512; SHA-224 by a
     managed implementation in the tests), Wycheproof's 355 ECDH tests on raw points (the 204
     EdgeCaseDoubling and the 16 invalid-curve points among them) and its ECDSA P1363 tests
     with SHA-256 (262) and SHA-512 (332) (point duplication, Shamir edge cases, r and s at
     every boundary), .NET's ECDiffieHellman and ECDsa on 150 random keys both ways, a
     BigInteger model on 200 scalars from the edges (1, n - 1, all-negative Booth digits) with
     digests of every length to 80 octets, RFC 6979's retry after a candidate k of n or more
     (one signature in about 2^32: a key, digest and entropy that take it were found by a
     search over 702 million draws, and the test checks the refusal against the reference; the
     retries after r = 0 or s = 0, about 2^-256 each, are listed as rare for the coverage gate;
     verification's refusal of R at infinity, which would otherwise pass X = r Z^2 as a
     forgery, is reached by the signatures built for the pass's edges), and
     `tests/native/tiers` (800 rounds of every
     function equal at every tier, inputs against the guard page, outputs fenced). *Measured*
     (benchmarks/README.md has the table and every experiment): against OpenSSL 3.0.13's EVP,
     a shared secret 1.37x (52.0 us), a public key 3.0x, a TLS 1.3 key share 2.7x, a signature
     1.72x (15.5 us), a verification 1.54x (55.6 us); v3 1.05x v1 on a shared secret and 1.31x
     on a signature. Why the gains are what they are: every carry instruction, cmov and shift
     runs on ports 0 and 6 only, which llvm-mca's model puts at 94% busy in a product (37 cycles
     a product apart, where the multiplier allows 20), so the products are near their bound
     and v3's mulx gains little over mul; what moved the needle was taking work off those ports
     (the reduction's shifts as one mulx: doubling 378 to 356 cycles), the 7-bit fixed-base
     window (11.85 against 13.3 us a public key at 5 bits) and the inversion (2.16 against
     Fermat's 4.1 us). Measured and not kept: the final subtraction by masks (14 cycles more
     latency a product), five doublings expanded in one routine (no change). Next levers: a
     variable-time inversion for verification's s^-1 (public: divsteps with early exit, about a
     third of the constant-time one's 2.16 us), the divsteps' 6-cycle step chain (both zeta
     outcomes computed ahead: about 4), and on CPUs with AVX-512 IFMA a 52-bit-limb field (no
     machine here to measure it on).
   - **RSA verification** (2026-11-27), `crypto/rsa.asm`: `httpasm_rsa_public_key_init`,
     `httpasm_rsa_verify_pkcs1` (RSASSA-PKCS1-v1_5: certificates' sha256WithRSAEncryption and
     its kin, SHA-1 and SHA-224 for legacy chains) and `httpasm_rsa_verify_pss` (RSASSA-PSS with
     MGF1 on the same hash, SHA-256, -384 or -512: TLS 1.3's rsa_pss_rsae_* and rsa_pss_pss_*),
     for moduli of 1024 to 8192 bits and odd exponents from 3 to 2^64 - 1. *The key*
     (`httpasm_rsa_public_key`, 2080 octets, struct size 16): n, R^2 mod n, -n^-1 mod 2^64, e,
     k and the bit length; a refused key is all zeros and fails every verification (a
     signature of length 0 too: its own octet count). *The arithmetic,* on k limbs (n's,
     rounded up to 8): the Montgomery product (CIOS), the square (the products above the
     diagonal once, eight rows at a time so each row's part past its block is whole 8-limb
     groups, a shared routine the carry chains run through, call and ret keeping the flags;
     then doubled with the squares added, then k reduction rows) and the reduction alone (out
     of Montgomery form), each in two versions: v3 mulx with adcx/adox, v1 mul (its square and
     reduction are products). All constant time, for the signing to share. The public
     operation: s R by the product with R^2, square-and-multiply from the top, the reduction
     at the end (65537: 16 squares, 2 products, 1 reduction). *R^2 mod n* by long division
     (Knuth's algorithm D on the single-bit dividend 2^(128k + s), mul only, variable time: n is
     public): 1.8 us at 2048 bits, where the first version's eleven squarings took 13.2; its
     rare paths (the clamped digit, the clamp whose remainder passes 2^64, one and two
     lowerings, a lowering stopped by the remainder, the add-back) each reached by a modulus
     a model of the division found (2^1024 - 2^64 + 1, 2^1024 - 2^128 + 1, 2^1024 - 2^65 + 1,
     2^1023 + 2^960 - 1, 2^1023 + 3, 2^1024 + 1). *The encodings:* RFC 8017 8.2.2 builds the
     expected EM (00 01 FF.. 00, the DigestInfo with its NULL, the digest) and compares it
     whole, so no BER variant, missing NULL or garbage after the digest passes (Bleichenbacher's
     2006 forgery against e = 3 fails); 8.1.2 and 9.1.2 step by step (the length, 0xbc, the top
     bits, MGF1's unmasking, the zero padding, the 01, H'). *Why the gains are where they are*
     (benchmarks/README.md has the probes): a multiply-accumulate costs about 1.4 cycles in
     every shape tried - rows, two rows interleaved 8 limbs at a time (slower: 3.3k^2 cycles a
     product against 2.85k^2), product scanning with one to three accumulators (1.4 to 1.7) -
     because two flag chains with mulx's ports 1 and 5 beside them cap at 1.5 a unit; so the
     time went into doing fewer: the square (1.28x the product at 2048 bits), the reduction
     alone, the division. *Proven by* FIPS 186-3's SigVer15 (270), SigVerPSS (270), SigGen15
     (80) and SigGenPSS (80), Wycheproof's RSASSA-PKCS1-v1_5 files at 2048 to 8192 bits
     (3,364 tests; the "acceptable" missing NULL refused) and its PSS files (1,411: the misc
     file's every hash pair, SHA-1 and MGF1-SHA1 refused), .NET's RSA on seven key sizes both
     ways, RFC 8017's DigestInfo prefixes read from the pinned text, a BigInteger model of the
     init (every field, 80 moduli at every 64- and 512-bit boundary and the division's shapes)
     and of the encodings (signed with d on prime moduli 2^1023 + 1155, 2^1024 + 643 and
     2^2048 + 3211, the last two with PSS's encoded message an octet short of the signature),
     encodings one detail off, signatures outside the rules, and `tests/native/tiers` (200
     rounds: keys and both verifications equal at every tier, n, e, the key, the digest and
     the signature each against the guard page). *Measured* against OpenSSL 3.0.13's EVP: a
     verification with the key kept 1.24x at 2048 bits (15.8 us), 1.27x at 3072, 1.25x at
     4096; with the key made from n and e each time (a TLS certificate's case: its key
     verifies one signature) 1.85x (17.7 us against 33.0), 1.52x and 1.39x; v3 2.38x v1. Next:
     signing (below), then on CPUs with AVX-512 IFMA 52-bit limbs.
   - **RSA signing** (2026-11-27), `crypto/rsa.asm`: `httpasm_rsa_private_key_init` (an
     RSAPrivateKey's numbers: n, e, p, q, dp, dq, q^-1; no d), `httpasm_rsa_sign_pkcs1` (every
     hash verification takes) and `httpasm_rsa_sign_pss` (SHA-256, -384, -512 with the caller's
     salt: TLS 1.3's CertificateVerify under an RSA certificate). *The key*
     (`httpasm_rsa_private_key`, 6720 octets, struct size 17): the public key first (the same
     octets: it verifies as one), then p, q, dp, dq, each prime's R^2 and R^3, q^-1 R mod p, the
     n0s and k, the larger prime's limbs rounded up to 8 (both primes run on it: their sizes need
     not match, as Wycheproof's e = 3 keys with primes of 681 and 343 bits show). The init
     refuses (zeros) a public part the verification refuses, a prime even, 1 or over 4096 bits,
     p q other than n, dp, dq or q^-1 not below its prime, and any key whose test signature (of
     2) does not verify under e; R^2 mod each prime in constant time (2^(bits - 1) doubled by
     masks to 2^c R, then squared: no division, which would branch on the secret prime).
     *Signing:* the encoding (RFC 8017 9.2's 00 01 FF.. 00 DigestInfo digest; 9.1.1's maskedDB,
     H and bc, the salt given), then CRT: per prime m R^-1 as the reduction of m's low k limbs
     plus its high k limbs (m < p q < p R keeps the high half below the prime), times R^3 into
     Montgomery form; the exponentiation by fixed windows over the exponent's whole width 64k,
     5 bits up to k = 16 and 6 above (width and positions depend on k alone), the table (32 or
     64 entries) built whatever the exponent, every window's entry read by a constant-time
     gather (every entry ANDed with a compare mask: v3 AVX2 sixteen limbs a pass, v1 SSE2
     eight); at k = 16 (RSA-2048's primes)
     v3 runs the power on a square and a product of its own, straight lines instead of a call per
     row and a loop per 8-limb group, with "almost Montgomery" results (below R, not below p: n
     subtracted once when t's top limb is set, so one masked pass ends each operation), which
     the reduction out of Montgomery form takes below p; Garner's recombination (s_q mod p, the
     difference mod p by masks, times q^-1 R, then h q + s_q, below n) runs on the generic
     product, whose results are below p. The result is verified under e before it
     leaves (s^e mod n = m, else -1 and zeros: one faulty half would hand out a prime, Boneh,
     DeMillo and Lipton's attack), and the stack the routine used, about 48 KiB with 4096 below
     its frame for the callees, is zeroed on return. Constant time in the key and the message
     (the hash's and the salt's lengths are public), with no blinding. *Proven by* FIPS 186-3's
     SigGen15 (80) and SigGenPSS (60 signed under the file's salts, the 20 with SHA-224
     refused) octet for octet, each key's primes recovered from n, e and d (SP 800-56B C.2: the
     files give no primes); Wycheproof's rsa_pkcs1_*_sig_gen files at 1024 to 4096 bits (158
     signatures exact, the unbalanced e = 3 keys among them); .NET's RSA on six key sizes (1024,
     1032, 2048, 2056, 3072, 4096: PKCS#1 v1.5 equal to .NET's, PSS verified by .NET and equal to
     the model's encoding signed with d); keys from chosen primes at 1025 and 2049 bits (24 limbs:
     a limb past 1024 bits) with e = 3 and 65537, every hash and salts of 0, 1, hLen and the
     largest that fits; twenty inconsistent keys refused, each of the init's checks in turn;
     calls outside the rules; one bit flipped in dp, dq, q^-1 R or R^3 after the init caught by
     the fault check; and `tests/native/tiers` (a 1024-bit key, 200 rounds, and a 2048-bit one,
     50, which takes v3's k = 16 path: each key equal at every tier with each of its seven
     numbers against the guard page, both signatures equal at every tier, verified, the octets
     after them untouched). *Measured* against OpenSSL 3.0.13's EVP (the key kept, the context
     made once; OpenSSL blinds and checks each result under e): PKCS#1 v1.5 at 2048 bits 611 us
     against OpenSSL's 693 (1.13x, 41 rounds), at 3072 2.10 ms and 4096 4.77 ms (parity); PSS
     613 against 701 us at 2048 bits (1.14x, a salt drawn with httpasm_random each call),
     parity above; v3 2.31x v1; the init 0.59 ms at 2048 bits (its test signature is most of
     it). The first
     version (the generic square and product in the power) took 743 us, 0.92x OpenSSL: at k = 16
     the calls per row and per group were a fifth of a square (705 cycles, now 573) and a tenth
     of a product (795, now 709), which now sit at the floor of about 1.4 cycles a
     multiply-accumulate; at 3072 and 4096 bits the rows are long enough that the generic ones
     sit there too, as OpenSSL's bn_power5 (mulx and adcx/adox, 5-bit windows) does. Measured and
     not kept: the k = 16 product in CIOS order (731 cycles against 709), two table entries a
     gather step, a window's squares in one call (OpenSSL's power5 way: 575 cycles a square
     against 568). 5-bit windows up to k = 16 (a 32-entry table: half the gather and half the
     table's operations for a fifth more products) took about 2% (`bench.sh ab`, 41 rounds,
     three processes: PSS 1.017-1.022x, proven; PKCS#1 1.014-1.023x); by the measured
     operations k = 24 would break even and k = 32 lose 35,000 cycles an exponentiation, so 6
     bits stay there. Weighed and not taken: the fault check per prime at k = 16 instead of
     under n at k = 32 (about 17,500 cycles, 1%, for a second check path in place of the public
     key's, which would also need s < n checked apart).
   - **P-384** (2026-11-27), `crypto/p384.asm` over `include/crypto/p384.inc`:
     `httpasm_p384_public_key`, `httpasm_p384_ecdh`, `httpasm_p384_sign`, `httpasm_p384_verify`
     (48-octet scalars, 97-octet SEC 1 points, 96-octet r || s): TLS 1.3's secp384r1 key share
     and ecdsa_secp384r1_sha384, and above all the WebPKI's P-384 chains (Let's Encrypt's E5-E9
     intermediates and ISRG Root X2 sign with P-384: a TLS client verifies those signatures in
     every such chain). P-256's design at six limbs, routine for routine: the same formulas
     (OpenSSL's doubling for a = -3, add-2007-bl, madd-2007-bl, infinity by masks), Booth
     recodings (5 bits for the variable base, 77 windows; 7 bits for the fixed base, 55 windows
     of 64 affine points: 337,920 octets in `include/generated/p384_table.inc`, written and
     proven by `specs/p384.cs`, which CI runs with --check), table scans (v3 AVX2, v1 SSE2),
     Straus verification with wNAF digits (u1 by 7 bits over the table's window 0, u2 by 5 over
     1Q..15Q), the x(R) check without an inversion, RFC 6979 nonces hedged with the caller's
     entropy (HMAC-SHA384: RFC 6979's own k for a SHA-384 digest) and the same validation.
     *The field:* one generic Montgomery product (CIOS over a modulus in memory and its n0, two
     carry chains at v3, mul at v1, the eight limbs of t turning through r8..r15) serves p and
     n; 130 cycles chained, 114 at throughput (scratchpad p384/f6.asm). p's own form (n0 =
     2^32 + 1; m p = m 2^384 - m (2^128 + 2^96 - 2^32 + 1)) was weighed and not taken: m by
     shl and add instead of imul measured no faster (131), and the special reduction trades six
     mulx for about fourteen carry instructions a step on ports 0 and 6, the ports the generic
     step already fills. *The inversion:* safegcd as P-256's but with original divsteps (eta =
     -delta from -1, the swap's eta -eta - 1): Bernstein and Yang's Theorem 11.2 bounds them at
     floor((49 384 + 57) / 17) = 1110 for any input below 2^384, so 18 batches of 62 on seven
     signed 62-bit limbs (the half-delta variant's tighter bound is a computation libsecp256k1
     made for 256 bits only). *Proven by* RFC 6979 A.2.6 read from the pinned text (the key
     pair, both SHA-384 signatures exactly, all ten verified, each k's point), NIST's CAVP P-384
     records (KAS ECC CDH 25; FIPS 186-4 KeyPair 10, PKV 12, SigGen 60 with each k's point, SigVer
     75), Wycheproof's ECDH tests on raw points (790: 771 valid, 16 invalid-curve points refused)
     and its ECDSA P1363 tests with SHA-384 (280) and SHA-512 (318), .NET's ECDiffieHellman and
     ECDsa on 60 random keys both ways, a BigInteger model (Jacobian, with RFC 6979 in C#) on 120
     scalars from the edges and digests of 0 to 100 octets, the verification's equal and
     opposite points reached on purpose, refusals of every invalid key, point and signature,
     and `tests/native/tiers` (800 rounds at every tier, inputs against the guard page). RFC
     6979's retry after a candidate of n or more has no test: P-384's n is within 2^190 of
     2^384, so no search finds such a seed (listed as a rare condition). *Measured* against
     OpenSSL 3.0.13's EVP, whose P-384 is its generic EC_GFp_mont_method (no assembly for this
     curve), 41 rounds: a shared secret 3.9x (209 us against 812), a public key 20x (37.4 us), a
     key share 8.1x (253 us), a signature 17.6x (47.5 us), a verification 3.3x (231 us); v3
     1.22x v1. Then v3's square of its own (the 15 products above the diagonal once, doubled
     with the six squares added, the low half reduced and the high half added: 21 + 36 mulx
     against the product's 72; about 15% under the product of a value with itself a call in
     the scratchpad): `bench.sh ab` against a162801, three processes, a shared secret, a
     verification and a key share 1.03x each (proven), a signature and a public key about 1.02x;
     less than the square's own gain because the doublings' and additions' small operations
     (adds, subtractions, halvings, the selections by mask) are a large part of them. Next: those
     small operations (fused into the products, or values kept in registers between them).
   - **Ed25519** (2026-11-27), `crypto/ed25519.asm` over `include/crypto/fe25519.inc` (X25519's
     field, both versions): `httpasm_ed25519_public_key` (the seed's A),
     `httpasm_ed25519_private_key_init` (a prepared key: a mod L, the prefix, A),
     `httpasm_ed25519_sign` (RFC 8032 5.1.6 over the message itself) and
     `httpasm_ed25519_verify` (5.1.7, cofactorless): TLS 1.3's ed25519 scheme and Ed25519
     certificates (RFC 8410). *The key:* signing takes only a prepared key whose A the library
     computed from the seed: r = SHA-512(prefix || M) does not depend on A, so one message signed
     under two public keys gives a = (S1 - S2) / (k1 - k2) mod L (the "double public key
     oracle" of libraries that take A from their caller; a test plants a wrong A in a prepared
     key and recovers a that way). *The group:* extended coordinates with dbl-2008-hwcd (4M +
     4S) and add-2008-hwcd-3 (8M, 7M against a precomputed (y + x, y - x, 2d x y) point), which
     are complete on edwards25519 (a = -1 a square, d not): no input is exceptional, so no
     masks. v1's additions stay uncarried as in X25519, and two values here are sums of three
     carried ones (G = 2Z + C, F' = 2Z^2 + G'), whose products stay below 77 * 3 * 2^103 < 2^111,
     the field's limit. *The fixed base* (public keys, R = r B), constant time: P-256's signed
     digits at 6 bits, 43 windows of m 2^(6i) B for m = 1..32 (132,096 octets in
     `include/generated/ed25519_table.inc`, written and proven by `specs/ed25519.cs`, which CI
     runs with --check), each window's entry scanned (v3 AVX2, v1 SSE2), negated by a swap and
     a masked negation, digit 0 the neutral (1, 1, 0); one mixed addition a window, no doubling.
     *Verification* (public inputs, variable time): S below L first (non-malleable); A decoded
     by RFC 8032 5.1.3 (y below p, x from the square root, x = 0 with the sign bit refused);
     [S]B + [k](-A) in one Straus pass, S's width-6 NAF over the table's window 0, k's width-5
     NAF over -A's odd multiples 1..15 (cached form, built per call), and doublings without T
     where no addition follows (dbl-2008-hwcd never reads T: one product fewer on about 175 of
     the 253); then the result's encoding compared with R octet for octet (a non-canonical R
     never matches). Small- and mixed-order public keys are not refused by policy (Wycheproof
     lets either policy pass them; the cofactorless equation decides). *Scalars modulo L:*
     four-limb Montgomery products with mul (a signature takes five): a 512-bit hash h1 R + h0
     reduces as REDC(REDC(h1, R^3) + REDC(h0, R^2), 1), S as REDC(REDC(k, a), R^2) + r. *The
     inversion* (each encoding): P-256's safegcd, moved to `crypto/inverse.asm` as
     `ha_modinv256` with 2^255 - 19's record (`fe25519.inc`'s FE25519_INVERSE_RECORD, which
     `specs/ed25519.cs` proves): 2.11 us where this field's Fermat chains (254 squarings, each
     waiting for the last) take 3.76 us at v3 and 4.03 us at v1 (scratchpad ed25519/inv.asm, the
     same inverses on 20,000 inputs). *Proven by* RFC 8032 7.1's five vectors read from the
     pinned text, Wycheproof's 210 verifications (65ca494: 117 valid pass, 64 invalid fail, the
     29 small- and mixed-order "acceptable" ones get the model's answer, which takes all 29), a
     BigInteger model of RFC 8032 (section 6's code in C#) on 120 seeds with messages across
     SHA-512's block edges up to 1 MiB (public keys, every part of the prepared key, signatures
     octet for octet), S's digits at their edges under the neutral, order-2 and order-4 keys
     (where [k]A cannot hide S), refusals of every non-canonical or off-curve key, x = 0 with the
     sign bit, S of L or more, a non-canonical R and single flipped bits, signatures into a
     buffer over the message, and `tests/native/tiers` (1,600 rounds over the four tiers, each
     input against the guard page in turn). A scratch run against Python's cryptography package
     agreed octet for octet at both versions. *Measured* against OpenSSL 3.0.13's EVP (its C
     curve25519.c; contexts made once, as 3.0.13 takes repeated one-shot calls), 41 rounds: a
     public key 9.17 us (4.9x), a signature of a 130-octet CertificateVerify content 10.27 us
     (4.3x), a verification 44.1 us (2.7x); v3 1.18x v1 on a signature, 1.10x on a
     verification. The first cut (Fermat's inversion, every doubling with T) took 10.85, 11.95
     and 47.3 us: the safegcd took 1.65 us from each encoding, the doublings without T about
     1.5 us more from a verification. X25519's public key now comes from this fixed base too
     (its entry: 8.92 us against the ladder's 32.5). Next: the field itself (four coordinates at
     once in AVX2 lanes, as curve25519-dalek's backend does, for verification's doublings).
   - **SHA-3 and SHAKE** (2026-11-27), `crypto/sha3.asm`: SHA3-224, SHA3-256, SHA3-384,
     SHA3-512, SHAKE128 and SHAKE256 (FIPS 202), ML-KEM's hashes and XOFs: one running context
     (`httpasm_sha3_ctx`, 216 octets, struct size 20) started by the kind's init, the shared
     `httpasm_sha3_update`, `httpasm_sha3_final` (wipes) and `httpasm_shake_squeeze` (the stream
     goes on across calls), and the one-shot forms; `ha_keccak_f1600_v` and `ha_keccak_absorb_v`
     hidden for ML-KEM. *The permutation*, Keccak-f[1600] in two versions chosen once a call:
     v3 rorx (rotations without copies or flags) and andn (chi's ~b & c), v1 rol and not + and.
     Each round: theta's column parities in five registers, D in five more, then each output
     row's five lanes read straight from their places before pi (pi's inverse gives them),
     rotated, through chi, stored, iota on lane (0, 0): 14 registers, nothing spilled; the state
     alternates between its home and a 200-octet stack copy (wiped after), one round each way.
     *No constant is typed in:* the round constants come from FIPS 202 Algorithm 5's LFSR and
     rho's offsets from section 3.2.2's walk, computed by NASM's preprocessor (equal to FIPS
     202's tables, checked when written; every vector depends on them). *The sponge:* the input
     is XORed into the state at once (a partial block's octets wait in the state, no buffer),
     the padding is the suffix (0x06 SHA-3, 0x1F SHAKE) and 0x80. *Proven by* NIST's
     byte-oriented SHA3VS files (sha-3bytetestvectors.zip and shakebytetestvectors.zip, pinned
     in `tests/tools.sh`): every ShortMsg and LongMsg record of all six (the padding at every
     place of every rate's block), SHAKE's VariableOut (1,126 and 1,246 output lengths), and the
     Monte Carlo tests (the SHAKE one: each message the last output's first 128 bits, zero-padded
     when shorter, its length drawn from the last output's final 16 bits); .NET's SHA3_256,
     SHA3_384, SHA3_512, Shake128 and Shake256 on every length to 700 octets and long ones, fed and
     squeezed in random pieces; forks by copy, wipes on final; `tests/native/tiers` (97,218
     outputs above v1, inputs against the guard page, outputs behind canaries). *Measured*
     against OpenSSL 3.0.13's EVP (keccak1600-x86_64; algorithm fetched once, context reused),
     41 rounds: SHA3-256 1.41x on 64 octets (305 ns against 421), 1.13x on 1 KiB, 1.09x on 16
     KiB; SHAKE128 1.47x, 1.12x, 1.08x; v3 1.23-1.25x v1. The permutation takes about 774 cycles
     (32 a round, against about 26 for its 130 ALU operations on five ports). *Four states at
     once* (`ha_keccak_f1600_x4_v3`, hidden, AVX2): a ymm register holds the same lane of four
     interleaved states (lane L of state i at 32 L + 8 i), the round the scalar one's lane by lane
     (C and D in registers, each output row read before pi, chi stored, the state alternating
     with an 800-octet stack copy, wiped after); rho by two shifts and an OR, but by vpshufb for
     the rotations by 8 and 56, and theta's rotation by 1 doubling with vpaddq (another port).
     1,720 cycles for four permutations against 812 for one: 1.89x the throughput (proven equal
     to v3's and v1's on 20,000 random state sets). For ML-KEM's matrix and noise.
   - **ML-KEM** (2026-11-27, first step: v1), `crypto/mlkem.asm`: ML-KEM-512, -768 and -1024
     (FIPS 203), for RFC 10024's X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 and the
     pure ML-KEM groups: `httpasm_mlkem{512,768,1024}_keypair` (from a 64-octet seed d || z),
     `_encaps` (with the caller's 32-octet m; -1 and zeroed outputs when ek fails 7.2's modulus
     check, which TLS answers with illegal_parameter) and `_decaps` (-1 and a zeroed key when dk
     fails 7.3's hash check; a modified ciphertext gives J(z || c), implicit rejection). Every
     function deterministic: the caller draws the randomness, which makes them testable against
     fixed vectors. *v1, scalar*, the library's own reference: 16-bit coefficients modulo q = 3329
     with Montgomery products (R = 2^16) and Barrett reduction as in the CRYSTALS-Kyber reference
     code's design, written from FIPS 203's algorithms: the NTT and its inverse in FIPS 203's
     coefficient order (the inverse ends times 1441 = R^2 / 128, undoing the R^-1 the base-case
     products leave), base-case products summed over a vector in one pass, SampleNTT from
     SHAKE128 (three blocks, then one at a time), SamplePolyCBD for eta 2 and 3 by bit masks,
     Compress_d as ((2^d x + 1664) * 10321340) >> 35 (an exact division by q for every x below q
     at d = 1, 4, 5, 10, 11: checked exhaustively), Decompress_d as (q y + 2^(d - 1)) >> d. The
     zetas are computed by the preprocessor (17^BitRev7(i) R mod q); the hashes are
     `crypto/sha3.asm`'s; the matrix is sampled a row (key generation) or a column (encryption)
     at a time, never stored whole; constant time in every secret (the re-encryption compare by
     OR of XORs, K' or J(z || c) by mask); up to about 10 KiB of stack, wiped. *Proven by*
     Wycheproof's twelve ML-KEM files (65ca494, pinned): key generation from seeds (100 a set,
     FIPS 203's), encapsulation (133 valid a set exactly; 108, 112 and 116 invalid keys refused
     with zeros: FIPS 203's and CCTV's modulus overflows), decapsulation from seeds (160 to 162 a
     set: implicit rejection, CCTV's strcmp case, malleable ciphertexts) and from expanded keys
     (aws-lc's and reenc's: hash-check refusals); a model of FIPS 203 in C# (plain integers,
     .NET's SHA-3 and SHAKE) on 40 random seeds a set, each ciphertext also with a bit flipped and
     replaced by noise; the modulus check at every kind of place (q, q + 1, 4095 refused, q - 1
     accepted, both halves of a pair, first, middle and last polynomial); the hash check on the
     ek part and the stored hash; canaries after every output; `tests/native/tiers` (1,600 rounds,
     each input against the guard page in turn). A scratch Python reference of FIPS 203
     (scratchpad mlkem/mlkem_ref.py) passed all 2,268 Wycheproof cases first. *Measured* against
     mlkem-native 2.1.0 (pq-code-package's, its AVX2 backend and four-way Keccak; OpenSSL 3.0.13
     has no ML-KEM), 41 rounds: ML-KEM-768 key pair 31.3 us against 10.8, encapsulation 41.1
     against 12.3, decapsulation 56.8 against 16.3; ML-KEM-1024 48.3 / 60.6 / 81.1 against 15.6 /
     17.7 / 23.6: about 3x slower, as scalar against AVX2.
     *v3, AVX2* (2026-11-27, second step), sixteen 16-bit coefficients a register, every routine
     of v1 again: coefficients stay in FIPS 203's order except inside the NTT and its inverse,
     whose last three layers (lengths 8, 4, 2) pair lanes of the same register and so work on a
     shuffled order (two registers' 32 coefficients exchanged by vperm2i128, vpunpck{l,h}qdq and a
     dword blend, each its own inverse) and shuffle back before storing. Butterflies are the
     Kyber reference's Montgomery products in three multiplications (zeta's q^-1 multiple
     precomputed); the forward NTT is v1's exactly, lane for lane (same butterflies, same
     Barrett: vpmulhw by 20159, then vpmulhrsw by 32 is floor((h + 512) / 1024)); the inverse
     Barrett-reduces only its third and sixth layers' sums (the peak stays below 4q). Base-case
     products: each second factor's cache once ([b0, b1 gamma] and [b1, b0] pairs), then two
     vpmaddwd a register give a0 b0 + a1 b1 gamma and a0 b1 + a1 b0 exactly in 32 bits, summed
     over the vector and Montgomery-reduced once from 32 bits. Compress_d for every d by one
     formula on anything in (-2q, 2q) (no reduction before it): x + 2q, the quotient estimate
     vpmulhrsw(x, floor(2^(15+d) / q)) (the quotient or one less), the exact remainder in 16 bits
     decides; Decompress_d is vpmulhrsw(y << (15 - d), q); the encodings by vpmaddwd, vpshufb,
     vpsllvd / vpsrlvq and lane joins, every load and store kept inside its buffer;
     SamplePolyCBD by bit sums in octets (eta 2) and in 24-bit groups (eta 3); SampleNTT's
     rejection 16 candidates at a time through a 256-entry compaction table (popcnt). Every
     formula was proven before the assembly: a register simulation of the shuffled layout (0
     mismatches against FIPS 203's NTT, inverse and products) and an emulation of each
     instruction sequence with exact 16- and 32-bit wrapping (Compress and Decompress on every
     input, the inverse's and the products' bounds); then a harness against v1's routines on
     random inputs (0 mismatches; NTT 3,458 -> 280 cycles, inverse 5,502 -> 286, a k = 3 product
     6,556 -> 198 + 62 for the cache, the compressions 13-29x). *The hashes became the cost*
     (44 Keccak permutations in a 768 encapsulation, about 86% of v3's time with one state at a
     time), so the matrix (k^2 SHAKE128 runs) and the noise (2k or 2k + 1 SHAKE256 runs) are
     sampled four at a time through `ha_keccak_f1600_x4_v3` (a lone last run alone); the matrix
     is stored whole for k = 2, 3 (the entries are public: above the wiped part of the frame), a
     row or column at a time for k = 4. A call goes up to 20,800 octets deep (ML-KEM-1024; 11,048
     at v1), so both versions now touch the stack every 4032 octets on the way down: a nearly
     spent thread faults on its guard page instead of the frame stepping over it into whatever
     lies below (a stack clash). `tests/native/stack` proves it for every function at v1 and at
     the best tier: the depth measured on a painted stack, then 254 runs in forked children on
     stacks too small by 64 octets to all but 1 KiB, each above a PROT_NONE guard and a 64 KiB
     shared sentinel: every one faults inside its guard page with the sentinel intact, and each
     function on its depth + 1 KiB returns the main stack's octets; a control (an unprobed
     20,000-octet frame) is caught stepping over. *Proven by* the same tests at v3 and v1
     (MlKemTests, `tests/native/tiers`: 1,600 rounds at every tier equal to v1's).
     *Measured* (41 rounds, paired): ML-KEM-768 key pair 10.58 us against mlkem-native's 10.87
     (1.04x), encapsulation 10.92 against 11.79 (1.08x), decapsulation 14.38 against 15.17
     (1.08x); ML-KEM-1024 14.25 / 14.96 / 20.02 against 15.68 / 17.17 / 22.41 (1.10x, 1.15x,
     1.12x); v3 is 3.3-4.2x v1. With the arithmetic in AVX2 but one Keccak state at a time it
     was 14.25 / 15.59 / 18.85 (mlkem-native 1.19-1.44x ahead): the four-way permutation is what
     passed it.
     *The pool* (2026-11-27, third step): what one state at a time still ran was hashing, H(ek)
     in an encapsulation (9 to 12 blocks) and H(ek) and J(z || c) in a decapsulation, long
     absorptions beside the matrix's short squeezes. `mk_pool_v3` runs different sponges in the
     four lanes of the same permutations: a hash lane absorbs a block per permutation (its input
     XORed in qword by qword at its lane's place; then the suffix and 0x80, and after the next
     permutation its 32 octets out), a matrix lane squeezes 168 octets a permutation into its
     buffer and rejection-samples after the third (a fourth block on its own when needed), and
     a lane that finishes takes the queue's next entry. An encapsulation runs H(ek) in lane 0
     and the k^2 entries of A transposed in the others (at ML-KEM-768 9 permutations for H and
     all 9 entries); a decapsulation H(dk's ek) in lane 0 and J(z || c) in lane 1 (z absorbed as
     the first 4 qwords) beside the entries, then the hash check (refused as before: the work
     before it touched only public data and z, all wiped). So the matrix is now sampled whole
     before the products, at k = 4 too (8 KiB more stack: 27,232 octets deep at most, still
     proven by `tests/native/stack`: 278 runs). *Proven faster* by `bench.sh ab 81a1e79`, three
     processes unanimous: ML-KEM-768 encapsulation 1.19x, decapsulation 1.21-1.24x; ML-KEM-1024
     1.13x and 1.20x; key generation (no hash to pool) and every v1 row (the layout control)
     unchanged. Now: ML-KEM-768 key pair 9.92 us against mlkem-native's 10.91 (1.10x),
     encapsulation 8.60 against 11.99 (1.40x), decapsulation 11.12 against 15.40 (1.39x);
     ML-KEM-1024 14.19 / 13.39 / 16.63 against 15.70 / 17.16 / 22.06 (1.10x, 1.29x, 1.34x); v3
     3.5-5.2x v1.
   - **Stack clash** (2026-11-27, hardening found while sizing ML-KEM's frames): a function that
     takes more than a page of stack in one subtraction and then writes below it can step over a
     thread's guard page (one page: glibc's pthreads default) into whatever is mapped below, when
     that thread's stack is nearly spent (CVE-2017-1000364's class; compilers probe for it with
     -fstack-clash-protection). A listing of every single subtraction from rsp in the .so found
     four such frames besides ML-KEM's: P-384's (5,056 octets), RSA's verification and key
     setup (6,464), its signing and private-key setup (43,968) and rsa_rr_div (4,184). Each now
     takes its frame through `HA_STACK_DOWN` (httpasm_core.inc: a touch every 4032 octets on the
     way down, a loop whose test sits at the top so its edges run for any count; ML-KEM's MK_ENTER
     does the same by %rep), and no function of the library subtracts more than 4032 octets at
     once. `tests/native/stack` proves it for 29 functions at v1 and at the best tier (ML-KEM,
     P-256, P-384, Ed25519, X25519, RSA's six): the depth measured on a painted stack (RSA's
     private-key setup goes 54,992 octets deep, its signing 48,192, ML-KEM-1024 at v3 27,232),
     then on stacks too small by 64 octets to all but 1 KiB, each above a PROT_NONE guard and a
     64 KiB shared sentinel in a forked child: 781 runs, every one faulting inside its guard with
     the sentinel intact, and each function on its depth + 1 KiB leaving the main stack's outputs.
     Its negative control is real: built from the sources before the fix, RSA's public-key setup
     at v1 on a 3,872-octet stack did not fault and wrote into the sentinel below the guard.
   - **FFDHE** (2026-11-27), RFC 7919's five groups (TLS 1.3's ffdhe2048 .. ffdhe8192, by their
     NamedGroup codes; generator 2): `httpasm_ffdhe_size`, `httpasm_ffdhe_public_key` (2^x mod p)
     and `httpasm_ffdhe_shared` (Y^x mod p after RFC 7919 5.1's check 1 < Y < p - 1), outputs p's
     size in octets, left-padded (RFC 9846 4.2.8.1, 7.4.1). *The primes* come from
     `specs/ffdhe.cs` (CI --check), which rebuilds each from Appendix A's formula with Euler's
     number summed exactly (floor(2^(b-130) e) from the series with 128 guard bits, accepted only
     when the guard settles the floor), checks it equal to the pinned text's hex p and q, both
     prime (Miller-Rabin, 32 bases), 2 of order q, and writes the limbs, R^2 mod p and n0. *The
     exponentiation* is RSA signing's (crypto/rsa.asm's last section shares its frame and
     rsa_power: table, gather, windows, the CPU's Montgomery operations), so the exponent meets
     only constant-time code; what changed for it: rsa_power scans RS_EBITS bits (RSA keeps 64k,
     its exponents' lengths secret; FFDHE gives 8 times its exponent's length, which the caller
     chooses and is public: Appendix A's advised minimum, 225 to 400 bits, up to p's size, which
     the functions enforce), 5-bit windows at every size (32 entries of 128 limbs fill the 32 KiB
     table; short exponents favour the smaller table), three of the frame's slots grown to 128
     limbs, and the exponent loaded by position alone (rsa_load_be's skipping of leading zero
     octets would have looked at a secret). *Proven by* FfdheTests (ModPow over the primes read
     from the pinned RFC text at every group and every kind of exponent length, random peer keys,
     the range check's both ends and every refusal writing nothing, canaries),
     `tests/native/tiers` (50 rounds over the five groups at every tier equal to v1's, inputs
     against the guard page), `tests/native/stack` (49,792 octets deep: signing's frame).
     *Measured* against OpenSSL 3.0.13's own named-group path (DH_new_by_nid, our exponent as its
     private key, DH_generate_key / DH_compute_key_padded), the advised minimum exponents (its
     defaults too), 41 rounds: ffdhe2048 public key 270 us against 330 (1.21x), shared secret 288
     against 352 (1.23x); ffdhe3072 697 / 739 against 843 / 898 (1.21x); ffdhe4096 1.43 / 1.52 ms
     against 1.77 / 1.88 (1.24x); v3 2.3-2.5x v1.
   - **X448** (2026-11-27), `crypto/x448.asm`: `httpasm_x448` (the shared secret; -1, the zeros
     written, for a small-order point) and `httpasm_x448_public_key` (X448(k, 5); -1 for the one
     clamped scalar whose key is zero: 4q, which X448's clamped range holds, unlike X25519's).
     *The field*, at both versions: eight 56-bit limbs, Karatsuba over phi = 2^224 (phi^2 = phi
     + 1 folds whole limbs): a product is 48 multiplications in OpenSSL's arch_64 column form
     (from libdecaf), a square three 4-limb squares (30); sums and differences stay uncarried (a -
     b is a + 2p - b); v3 multiplies with mulx, v1 with mul. Seven 64-bit limbs were weighed and
     left: as many products, but 2^224 falls mid-limb (every reduction shifts by 32) and every
     sum needs carries. A scratchpad model (x448/model.py) ran this arithmetic step for step
     over RFC 7748's vectors and iterations, Wycheproof and random cases, checking every column
     sum (below 2^120: a column's carry fits a qword) before the assembly, which then passed
     everything on its first run. *Speed, measured on the way* (TSC ticks): a product chained to
     the next took 105 ticks while the products' sums were vector loads of qword-stored outputs
     (a load spanning several stores waits for them to reach the cache; 89 with qword loads, 113
     with the outputs packed into vectors instead, which costs port 5 that mulx already fills),
     so elements move as qwords only. Unchained, a product still costs ~89 ticks where its 48
     multiplications alone take 51 (one mulx a cycle): llvm-mca's Golden Cove model puts the
     product at 438 micro-operations, dispatch-bound; its sums, column ends and final carries
     cost ~40 ticks (each part measured by leaving it out). The ladder computes its products in
     pairs interleaved column by column (FE448_MUL2, FE448_SQR2: no pointer registers, frame
     offsets), so one chain fills the other's waits: 81.6 ticks a product paired against 90.5
     alone, the whole function 405k ticks to 372k. Constant time: cmov swaps, the scalar's qword
     following the public bit number; z2^(p - 2) by a 453-squaring chain. *Proven by* X448Tests
     (RFC 7748 5.2's vectors and its 1 and 1,000 iterations, 6.2's keys and secret, Wycheproof's
     498 tests that fit 56 octets with its 11 zero secrets, a BigInteger ladder on 120 random
     and non-canonical cases, the public key against the ladder at u = 5 on 324 scalars, small-
     order points, the zero public key of 4q, inputs against guard pages, outputs exactly 56
     octets, in place), `tests/native/tiers` (400 runs at every tier equal to v1's),
     `tests/native/stack` (2,248 octets deep). *Measured* against OpenSSL 3.0.13 (EVP_PKEY_X448,
     41 rounds): shared secret 124.6 us against 204.7 (1.64x), public key 115.7 against 187.0
     (1.62x), a key share 241 against 390 (1.62x); v3 and v1 equal (mul and mulx cost the same
     here). Since Ed448 (below), the public key comes from its fixed base: 38.4 us (4.9x
     OpenSSL), a key share 165 us (2.4x).
   - **Ed448** (2026-11-27), `crypto/ed448.asm` over `include/crypto/fe448.inc` (X448's field,
     moved there to be shared): `httpasm_ed448_public_key`, `httpasm_ed448_private_key_init` (a
     176-octet prepared key: s, the prefix, A, all from the seed; struct size 21),
     `httpasm_ed448_sign` and `httpasm_ed448_verify` (RFC 8032 5.2: pure Ed448, SHAKE256 with
     dom4, any context of 0 to 255 octets - TLS 1.3 uses none - longer refused). *The group:*
     extended coordinates on edwards448 (a = 1), dbl-2008-hwcd and add-2008-hwcd with H = B - A,
     complete (d is not a square); their products in X448's interleaved pairs (a mixed addition
     four pairs, a doubling two pairs of squares and two of products). *Fixed base* (public keys,
     R, and now X448's public keys), constant time: signed 5-bit digits over 90 windows (450 bits:
     any scalar below 2^448 goes in unreduced, since s B = (s mod L) B), each window's 16 points
     (x, y, d x y) in `include/generated/ed448_table.inc` (276,480 octets), written and proven by
     `specs/ed448.cs` (built by affine additions, each point checked by double-and-add in extended
     coordinates; the primes; d not a square; and the 4-isogeny taking B to u = 5, which lets X448
     take this table: X448(k, 5) = (y / x)^2 of k B for every clamped k, 4q giving the neutral
     point and 0); a scan reading all 16 entries a window (AVX2 at v3, SSE2 at v1), a negative
     digit taking 2p - x and 2p - d x y; one mixed addition a window. *Verification*, variable
     time: Straus over width-5 NAFs, S's from window 0's entries, k's from -A's odd multiples, the
     doublings shared; cofactorless, R compared octet for octet with [S]B - [k]A's encoding (a
     non-canonical R never passes). *Decoding*: x = u^3 v (u^5 v^3)^((p - 3) / 4), which is the
     inverse's chain stopped two squarings early: fe448's power routine now has both entries
     (ha_fe448_pow_p34, ha_fe448_invert). *Scalars* modulo L by Montgomery products on seven limbs
     (a 912-bit hash as REDC(REDC(h2 R^4) + REDC(h1 R^3) + REDC(h0 R^2))). Each comparison of a
     whole value is one decision (the OR of the differences, or a sub/sbb borrow): a branch per
     qword would leave edges no input reaches (a y of p or more always differs in its lowest
     limb; L's all-ones qwords can never be exceeded), which the coverage gate would rightly
     refuse. Designed in a Python model first (scratchpad ed448/model.py: RFC 8032 7.4's nine
     vectors and Wycheproof's 75 fitting tests). The assembly's first run had all keys and
     signatures right and every verification wrong: two bugs, each a lesson - `ED_COPY rbp +
     EF_ODD + q` inside a loop counting in q passes the inner macro's own %assign q (NASM resolves
     an argument's %assign names where the inner body uses them), and S was kept in a slot the
     hash's reduction uses as scratch. *Proven by* Ed448Tests (RFC 8032 7.4 with its context case,
     Wycheproof's 87 (12 of other lengths counted), a BigInteger model of RFC 8032 5.2 on seeds,
     message and context lengths across SHAKE256's block, the cofactorless edges under the neutral
     and small-order keys, refusals (non-canonical y, stray bits, x = 0 with the sign, S of L or
     more, a non-canonical R, flipped bits), contexts (dom4's length separation, 256 refused with
     nothing written), signing over the message, the double-public-key oracle shown on a planted
     key), `tests/native/tiers` (400 rounds at every tier equal to v1's, every input against the
     guard page in turn), `tests/native/stack` (6,472 octets deep). *Measured* against OpenSSL
     3.0.13 (EVP_PKEY_ED448, the 130-octet CertificateVerify content, 41 rounds): public key 39.2
     us against 191.6 (4.9x), signature 44.3 against 205.6 (4.6x), verification 176.6 against
     230.4 (1.30x: 446 doublings dominate it; next to try there: doublings without T when no
     addition follows).
   - **P-521** (2026-11-27), `crypto/p521.asm` over `include/crypto/p521.inc`:
     `httpasm_p521_public_key`, `httpasm_p521_ecdh`, `httpasm_p521_sign`, `httpasm_p521_verify`
     (66-octet scalars, 133-octet SEC 1 points, 132-octet r || s): TLS 1.3's secp521r1 key share
     and ecdsa_secp521r1_sha512, the last group and signature scheme of RFC 9846's lists that M2's
     primitives lacked. P-384's design (formulas, Booth recodings, table scans, Straus
     verification with wNAF digits, the x(R) check without an inversion, RFC 6979 nonces hedged
     with the caller's entropy, the validation) over a new field. *The field:* p = 2^521 - 1
     reduces a product by its form, and the values are plain (no Montgomery form: no conversion
     in or out, plain constants): the 1042-bit t splits at bit 521 (hi by nine shrd), w = hi + lo
     + 1, and one pass masks the top limb to 9 bits and adds c - 1 (c = w's bit 521: 0 or all
     ones), which gives the fully reduced value with no branch (hi + lo = 2p never occurs for a
     product of values below p). Sums take the same tail; a difference that borrows masks the top
     limb and subtracts 1; halving and doubling (4x, 8x too) are rotations of the 521-bit string
     (2^521 = 1 mod p), which keep values below p; negation is the complement, masked so that 0
     stays 0. A generic Montgomery product at nine limbs would add 81 multiplications. *The
     products are called routines* (p521_fmul_v3/_v1, p521_fsqr_v3/_v1, hidden globals): about
     300 instructions each, so the point formulas with every product written out would pass the
     L1 instruction and decoded-micro-op caches (P-384's object holds about 312 KB of code beside
     its table; P-521's 72 KB). v3: rows of mulx with adcx/adox over a window of ten limbs that
     turns through ten registers, the row's lowest limb retired to the frame's scratch (F9_SCR:
     nothing secret lands below the frame, which is wiped); squares by the triangle (36 products,
     t_k and t_(k+9) sharing a register, then one pass doubling on CF and adding the nine squares
     on OF: 45 mulx against 81). v1: mul, one carry chain, the row's multiplier a memory operand
     (the window, rax, rdx and the carry take all fourteen registers); squares through the
     product. Measured (TSC ticks a call; this host's core runs at about the TSC's rate, a chain
     of imuls shows): a product 117.5 at throughput and 153 chained, a square 95 and 126; v1's
     product 204; a sum 15, a rotation 10. The independent product is within about 5% of its
     port bound (81 mulx on port 1, about 190 adcx/adox/adc on ports 0 and 6). *Windows:* 5-bit
     Booth digits for the variable base (105 windows; the top one, bits 519..524, never
     negative), 6-bit for the fixed base (87 windows of 32 affine points: 400,896 octets in
     `include/generated/p521_table.inc`, written and proven by `specs/p521.cs`, which CI runs with
     --check; P-384's 7 bits would make 691,200). *The doubling case P-256 and P-384 never meet:*
     the variable base's last addition adds d0 P to (k - d0) P, equal when k = 2 d0 (mod n) with
     k - d0 a multiple of 32: for d0 < 0, k = n + 2 d0 with d0 = -n (mod 32). P-256's n gives
     d0 = -17 and P-384's -19, outside Booth's [-16, 16]; P-521's n is 9 mod 32, so d0 = -9 and
     the key n - 18 meets it (the Python model searched every digit: n - 18 is the only one).
     add-2007-bl gives garbage there (H = r = 0, Z3 = 0), so window 0's addition is
     p521_add_last: the sum by selection, then the addend doubled, and the double taken by mask
     when H = r = 0 with neither input at infinity (one doubling more a shared secret). The
     fixed base cannot meet it (below window 86 the partial sum is below 2^(6i - 1) in magnitude
     and the addend at least 2^(6i); at the top window it would need k above n). *Inversion:*
     P-384's divsteps at nine signed 62-bit limbs, 25 batches of 62 (Theorem 11.2's bound for
     inputs below 2^521: 1505 divsteps). *Scalars:* Montgomery products modulo n (CIOS with t in
     the frame, the window sliding a qword a round; R = 2^576; mul at both versions). *RFC 6979*
     with HMAC-SHA512 (the commit before this one added it): qlen = 521 > hlen = 512, so a
     candidate is two HMAC blocks, k their first 66 octets shifted right 7 (bits2int), as a
     digest of 66 octets or more is. Designed in a Python model first (scratchpad p521/model.py:
     the field's limb arithmetic, the divsteps at nine limbs, CIOS modulo n, the windows' digits
     and the scalar multiplications with these formulas and selections, which found n - 18, and
     RFC 6979 A.2.7's SHA-512 signature exactly), then the field checked alone (scratchpad
     p521/h: every routine at both versions, in place too, against Python integers) before the
     whole: the assembly passed every vector on its first run, and the one failing test had a
     wrong helper (a 66-octet digest is shifted by bits2int, so the equal-points test passes
     e << 7). *Proven by* P521Tests (11, at v3 and v1): the curve's constants against .NET's
     explicit nistP521; RFC 6979 A.2.7 read from the pinned text (values on three lines: the key
     pair, both SHA-512 signatures exactly, all ten verified, each k's point); NIST's CAVP P-521
     records (KAS ECC CDH 25; FIPS 186-4 KeyPair 10, PKV 12, SigGen 60 with each k's point,
     SigVer 75); Wycheproof's ECDH tests on raw points (661: 632 valid, 16 invalid-curve points
     refused with zeros, 13 compressed or empty encodings never valid) and its ECDSA P1363 tests
     with SHA-512 (318: 231 valid, 14 of other sizes), both pinned at 65ca494; .NET's
     ECDiffieHellman and ECDsa on 40 random keys both ways; a BigInteger model (Jacobian, RFC
     6979 with HMACSHA512) on 100 scalars from the edges (n - 18 among them) and digests of 0 to
     100 octets; the doubling case itself (the digit and the multiple checked, then ECDH at
     n - 18 and its neighbours against the model on eight peers and against .NET); the
     verification's equal and opposite points; refusals of every invalid key (0, n, 2^521, the 66
     octets all ones), point (x or y of p, 2^521, 2^528 - 1; off the curve; every first octet
     but 04) and signature. `tests/native/tiers`: 400 rounds at every tier equal to v1's, n - 18
     among the keys, each of the four inputs against the guard page in turn. `tests/native/stack`:
     10,112 octets deep (a signature at the best tier; 8,912 at v1). The coverage gate: crypto/p521.asm 128 of 131 markers and 148 of 154 branch sides ran (1,070 tests in each of the six suite runs), the rest signing's nine retry markers, listed as rare.
     RFC 6979's retry after a candidate of n or more has no test: P-521's n is within 2^261 of
     2^521 (a rare condition in the gate's list, with r = 0 and s = 0). *Measured* against OpenSSL
     3.0.13, whose P-521 is its dedicated 64-bit code (ecp_nistp521.c: faster than its generic
     P-384, 3,089 ECDH a second against 1,352), 41 rounds: a shared secret 262.7 us against 356.9
     (1.36x), a public key 57.5 against 201.3 (3.50x), a key share 325.6 against 873.3 (2.68x), a
     signature 70.6 against 297.3 (4.21x), a verification 290.3 against 570.0 (1.96x); v3 1.4x to
     1.7x v1. Next to try (the products being near their port bound, each a few percent): the
     doubling's serial tail (alpha, alpha^2, X3, alpha (4 beta - X3): three products and five
     small operations in a row) overlapped with the next doubling's independent start (Z3^2 as
     soon as Z3 is known); the variable base's table made affine by one batched inversion
     (mixed additions: five products fewer a window); dbl-2001-b's 3M + 5S.
3. *The DER reader* (M3 step 2, brought forward), and loading the server's own chain and key
   (PEM, PKCS#8), done 2026-11-28: a chain file is read a block at a time (`httpasm_pem_read`'s
   `end` says where the next one starts, each block's DER through `httpasm_certificate_read`);
   the C ABI that takes a whole configuration is step 5's. The coverage gate holds the four
   files: every block and branch side runs (pem.asm all 116 sides, keys.asm 379 of 380,
   x509.asm 358 of 360, asn1.asm 428 of 436) or is listed with its proof of unreachability (the
   checks a gather repeats after the segment walk made them, the SET OF comparison's padded
   tail no two readable encodings reach, a small INTEGER's sign after its first octet's check,
   the RDN walk's reads after `httpasm_asn1_check_set_of` read them).
   - **The documents** (2026-11-28): ITU-T X.690 (02/2021), the encoding rules, and RFC 7468
     (PEM), 5958 (OneAsymmetricKey), 5915 (ECPrivateKey), 5480 (EC public keys), 8410 (the
     Edwards and Montgomery keys), 4055 (RSASSA-PSS's parameters), all M2's, and RFC 5280, M3's,
     whose certificate structure this step reads. X.690 is the ITU's PDF, free to download but
     not to redistribute: `specs/documents.json` pins its SHA-256 (format "itu"), `specs.cs
     fetch` downloads it into `specs/itu/` (ignored by git) only to check the hash, and its 75
     rows are transcribed by hand, clause by clause in its words, in `specs/x690.tsv` (ids
     `X690-<clause>[letter]`), which `extract` reads instead (`ItuRows`).
   - **The ASN.1 reader** (2026-11-28), `asn1/asn1.asm`: `httpasm_asn1_read` reads one element
     under DER or BER, in place (nothing copied, nothing past the input read): the identifier
     (the high-tag form only above 30, without leading zero bits; numbers up to 2^28 - 1), the
     length (never 0xFF; BER's indefinite form only for a constructed encoding, its
     end-of-contents found by reading the nested elements; DER's definite form in the fewest
     octets), and for a universal tag its type's rules: BOOLEAN, INTEGER and ENUMERATED, BIT
     STRING (DER: unused bits zero), OCTET STRING, NULL, OBJECT IDENTIFIER, SEQUENCE and SET,
     the strings' character sets (PrintableString's table, NumericString, IA5String,
     VisibleString, UTF-8 in the fewest octets without surrogates, BMPString and
     UniversalString without surrogates; the ISO 2022 types as octets), UTCTime and
     GeneralizedTime in DER's form (Z, the seconds, no trailing fraction zero) and BER's
     (X.680's: optional seconds, differentials, local time, fractions), every field in range
     with leap years, and BER's constructed strings segment by segment (a constructed time
     gathered first, 64 characters at most). Universal types the library cannot check (REAL,
     the TIME types, ...) are refused, not passed through. The reader follows nesting itself
     only for indefinite lengths and segments, 32 levels at most (each takes under 100 octets of
     stack). `httpasm_asn1_check` applies a universal type's rules under an IMPLICIT tag,
     `httpasm_asn1_check_set_of` DER's SET OF order (11.6), `httpasm_asn1_octets` and
     `httpasm_asn1_bits` join BER's segments. Constant time: only INTEGER and OCTET STRING
     contents may hold a key's secrets (8.3.2's verdict on an INTEGER's first two octets is
     branch-free; an OCTET STRING's are never read); the rest is public by design and the
     ConstantTime build marks it so where it is loaded. Proven by `Asn1Tests` (every rule's
     keeping and breaking encodings under both rules, every prefix against a guard page, and a
     differential walk against .NET's System.Formats.Asn1 over 2,000 random structures and
     8,000 mutations, element by element, with no disagreement), and `tests/fuzz/asn1.c`
     (against an independent C model of the same rules, which checks a string's characters on
     its joined value where the assembly streams them through the segments; DER a profile of
     BER; 342,418 inputs in its first minute without a difference). Its first long run (15
     minutes beside the other three ASN.1 fuzzers) and the minute after its fix found two bugs,
     both fixed with their inputs kept as seeds: the reader was exponential in nested indefinite
     segments (it found a
     constructed string's end by reading every segment whole, then walked the segments again to
     check them, each pass re-reading the deeper levels whole: 26 levels of `23 80`, 107 octets,
     took 1.1 s, 32 would take 72 s, a denial of service in a few hundred octets of a key file or
     of any BER a caller reads; the segment walk now ends the string as it checks it, each
     segment's header read once, `AR_HEAD`/`AF_UNENDED`, 32 levels in under a microsecond:
     `Asn1Tests.ReadsDeepSegmentsInLinearTime`), and `httpasm_asn1_bits` lost the unused-bits
     count when an empty constructed segment followed the last primitive one (now or-ed: only the
     last primitive segment's can be non-zero). The model's own walk had the same doubling and
     now reads such contents structurally, so the two still reach their verdicts by different
     roads. The functions that take an element refuse a `flags` value the reader never returns
     (its internal mark of an unended string would make the walk write a const element). Then
     20 minutes of the four ASN.1 fuzzers side by side found nothing (asn1 5,906,454 inputs,
     pem 37,957,200, key 6,133,151, x509 68,208,138), and their corpora are minimized into
     `tests/fuzz/corpus/` (asn1 497 inputs, pem 163, key 216, x509 201), which the replay and the
     coverage gate run. A structural mutation test walks real files too (`DerMutations`: every
     element removed, doubled, trailed, replaced, retagged, made unreadable, its value changed,
     the DER an OCTET or BIT STRING holds entered): 788 mutations of seven key files and over
     800 of certificates and public key infos, each refused cleanly or still a key of its
     kind that works.
   - **PEM** (2026-11-28), `asn1/pem.asm`: `httpasm_pem_read` decodes the first block of a text
     whose BEGIN line starts the text or a line: exactly five hyphen-minuses, the ABNF's labels,
     RFC 7468's lax base64 (whitespace anywhere, VT and FF included, pads absent or right, a
     final quantum's pad bits zero), the END line's label the BEGIN line's, and the next block
     from where this one ended. Other characters refuse the block, against RFC 7468's SHOULD
     ignore them, as OpenSSL, BoringSSL, Go and .NET refuse them (a text whose characters a
     parser drops is ambiguous, its section 14). The base64 is decoded in constant time: each
     character's class (base64, whitespace, pad, the END line's hyphen) steers the decoder and
     is public by design (the layout and the length), its six bits never do. The output is
     written only once the block has been checked. Proven by `PemTests` (RFC 7468's and RFC
     8410's examples, the latter's six-dash END line refused, every length to 300 octets in nine
     layouts, every malformation, files of several blocks, -2 with the room needed) and a
     differential against .NET's PemEncoding over 12,000 texts (6,655 blocks read alike; the
     differences all triaged: unpadded quanta and VT/FF whitespace, which RFC 7468 allows and
     .NET does not, and a sixth hyphen-minus after an END line, which .NET does not look at),
     and `tests/fuzz/pem.c` (against a C model with a table-driven base64).
   - **Private keys** (2026-11-28), `asn1/keys.asm`: `httpasm_private_key_load` takes PEM or
     DER, PKCS#8 (v1 and v2), PKCS#1 and SEC1, BER throughout (RFC 5958 2's MUST): RSA of two
     primes (rsaEncryption, and id-RSASSA-PSS unbound or bound to SHA-256/384/512 with MGF1 over
     the same hash: a key bound to SHA-1 is refused, as no TLS 1.3 signature could use it),
     P-256/384/521 on their named curves (a scalar shorter than the curve's, as OpenSSL before
     1.1.0 wrote one key in 256, padded; a public key given must be d G's, uncompressed or
     compressed), Ed25519 and Ed448; X25519 and X448 keys, other algorithms, multi-prime RSA
     and every inconsistency are refused with the key left all zeros, and "ENCRYPTED PRIVATE
     KEY" answers -2 (its decryption, PBES2, is M3's). Every buffer that held key material is
     wiped before it returns; the frame (33 KiB) is taken a page at a time. Constant time: the
     memcheck check loads keys whose whole PEM text is secret (RSA in PKCS#8 and PKCS#1, the
     three curves, both Edwards keys, a BER key), so everything decoded from it is too: the
     loader marks public what is public by design (the structure, the algorithm, the version, n
     and e) and nothing else steers it (its first run found one site, the DER-or-PEM test of
     the first octet, now marked). Proven by `KeyTests` (keys .NET makes of each kind, size and
     format, each then signing with the library under .NET's verification; RFC 8410's and RFC
     8032's Edwards keys by their public keys; BER rewrites; PSS parameters; combined files;
     every refusal; the 54 cases of RSASSA-PSS parameters both PSS readers are held to,
     `KeyTests.PssCases`) and `tests/fuzz/key.c` (every tier the same key; a loaded key holds
     together: d G recomputed, an RSA key's own signature verifying; DER and PEM alike;
     325,733 inputs in its first minute; 35 minutes in two long runs without a finding).
   - **Certificates** (2026-11-28), `asn1/x509.asm`: `httpasm_certificate_read` reads a
     certificate's DER (RFC 5280 4.1) in place, every part a pointer into it: the TBS's fields
     in order (the version present only as v2 or v3, DER's omission of v1; the inner signature
     algorithm the outer one's octets exactly, 4.1.1.2; issuer and subject as RDNSequences of
     non-empty SETs in DER's order of { type, value }; the validity's two times as seconds
     since 1970, UTCTime's YY as 1950-2049, GeneralizedTime without fractions; the unique
     identifiers in v2 and v3 only, in order, once each; the extensions in v3 only, one at
     least, each { extnID, critical TRUE or absent, extnValue }), the signature whole octets,
     nothing after. `httpasm_public_key_read` takes a SubjectPublicKeyInfo: rsaEncryption
     (parameters NULL, RFC 4055 1.2) and id-RSASSA-PSS (the private keys' parameter rules) with
     RSAPublicKey prepared for verification; id-ecPublicKey on P-256/384/521 with an
     uncompressed point; Ed25519's and Ed448's keys, parameters absent; anything else refused
     with the key all zeros. `httpasm_private_key_matches` pairs a private key with a
     certificate's (either RSA identifier with either: TLS picks the schemes by the
     certificate). Chain validation (names, constraints, the extensions' meanings and
     uniqueness, revocation, time) is M3's. RFC 8410's example certificate encodes critical
     FALSE, the DEFAULT DER omits, and is refused: a strictness to weigh against x509-limbo's
     cases in M3. Proven by `CertificateTests` (.NET's certificates of each kind, validities on
     both sides of 2050 and before 1970, with and without extensions, read field for field as
     X509Certificate2 reads them and their TBS verifying under .NET's key; public key infos of
     every kind, RSA keys verifying .NET's signatures; the PSS table; every pairing of six keys
     and the structures the library never fills; unique identifiers; 77 certificates and 53
     public key infos that each break one rule) and `tests/fuzz/x509.c` (every tier the same;
     every part inside the input and in its place; the validity against a model of the
     calendar by another algorithm, Hinnant's days_from_civil; an RSA key against
     `httpasm_rsa_public_key_init` of the n and e a model walks to; a pairing only of one key's
     halves; 6,362,114 inputs in two minutes, then 15 and 20 minutes, 68,208,138 inputs in
     the last, without a finding).
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
2. *Encodings* (the reader, BER's and DER's, the certificates' structure, PEM and PKCS#8 were
   brought forward to M2 step 3, done 2026-11-28):
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
