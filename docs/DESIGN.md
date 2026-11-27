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
   - **constant-time checks**, for M2: valgrind with secrets marked undefined, and statistical
     timing tests.
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
