# HttpAsm design

HttpAsm is a complete HTTP networking library in x86-64 assembly: HTTP/1.1, HTTP/2 and HTTP/3,
with QUIC and TLS of its own, as both client and server. It is built from the official documents,
and maximum performance is its guiding value. It belongs to the AsmFoundation family, next to
KvAsm, GrpcAsm and AsmSdk, and builds with [AsmSdk](https://asmfoundation.github.io/AsmSdk/).

This file is the single plan: the decisions, the architecture and the milestones. It changes as
decisions are made. Evidence (measurements, test reports) lives next to the code that produced
it.

**Status (2026-11-23):** in development; M1 nearly complete (section 7 lists what is left).
Working on Linux x64:
- the server: HTTP/1.1 and HTTP/2 (h2c with prior knowledge, h2spec 146/146) on one port,
  epoll workers, handlers that answer at once or later from any thread;
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

## 3. Architecture

```text
 Surfaces    .NET (ASP.NET Core IServer, HttpClient handler: first) · C ABI (httpasm.h) ·
             NASM macros (httpasm.inc) · Python (later)
                 all bind to the one C ABI of libhttpasm.so
 Drivers     our per-core loops (io_uring; epoll as the fallback)
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
  - Linux 5.15, the WSL2 kernel tests run on here. Newer io_uring features (buffer rings,
    zero-copy send, `MSG_RING`) are probed at startup and used when present.
  - CI's newer kernels run those paths.
- **CPU baseline:**
  - SSE2 in the first code.
  - Faster paths (SSSE3, AVX2, AVX-512) come with run-time dispatch, each kept only when a
    paired measurement shows it pays.

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
  - Today: RFC 9110, 9111, 9112, 9113, 7541, 8446, 9000, 9001, 9002, 9114 and 9204.
  - Each milestone adds its documents: TLS 1.2 (RFC 5246, 9325, ...), X.509 (RFC 5280), the
    extensions.
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

**M1: the shared semantics + HTTP/1.1 + HTTP/2** (in progress):
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
4. *The Linux driver:* per-core epoll loops (done): accept with SO_REUSEPORT, timers as
   deadline lists, idle without polling, back-pressure, graceful stop, the server's and the
   client's calls in the C ABI. **Left:** the io_uring loop, with epoll as its fallback.
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

**Left for M1's exit:** the io_uring loop (step 4).

*Exit:* every RFC 9112, RFC 9113 and RFC 7541 row proven, or deferred with a reason. The RFC
9110 rows M1 needs are proven; the others are deferred with reasons. h2spec 146/146,
request-smuggling cases, and recorded measurements.

**Then, in order:**
- **M2:** crypto in assembly + TLS 1.3 (RFC 8446).
- **M3:** TLS 1.2 + certificates (RFC 5280, X.509/ASN.1/DER).
- **M4:** QUIC + HTTP/3 + QPACK (RFC 9000, 9001, 9002, 9114, 9204), and server push, built
  once for HTTP/2 and HTTP/3 with the stream logic they share (section 4).
- **M5:** the .NET standard interfaces (ASP.NET Core `IServer`, an `HttpClient` handler). The
  handler is the full client: HTTP/2, redirects, credentials, retries, pipelining; M1's C ABI
  client is one blocking HTTP/1.1 connection.
- **M6:** the extensions and roles that "complete" is decided to include.

Other platforms (Windows, macOS, ARM64), Python's ASGI and the benchmarking suite follow once
the protocols are complete.
