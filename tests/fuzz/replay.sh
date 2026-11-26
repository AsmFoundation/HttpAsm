#!/usr/bin/env bash
# =============================================================================
# replay.sh - builds each fuzzer's harness with tests/fuzz/replay.c instead of libFuzzer and runs
# it on the fuzzer's committed seeds and minimized corpus: the fuzzers' invariants as
# deterministic tests. Linux only: tests/run-linux.sh calls it on the Linux side.
#
#   CONFIG Release: against the Release build's objects - a regression run of every input the
#     fuzzers ever kept, with every check, on each test run.
#   CONFIG Coverage: against the Coverage build's objects, with coverage_rt.o, so each replay's
#     exit writes its marks to HTTPASM_COVERAGE_DIR and the blocks the fuzzers reached count
#     in tests/coverage/run.sh's report.
#
# The references the differential fuzzers compare against (tests/tools.sh fetches them) are
# compiled plainly (-O1, no sanitizer) once into OUT/refs/.
#
# Usage: tests/fuzz/replay.sh CONFIG OUT [fuzzer names...]     (default: every fuzzer)
# Exit status: 0 when every replay passed; else the first failure's (a broken invariant aborts
# its replay, which names the input).
# =============================================================================
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="$1"
out="$2"
shift 2
names=("$@")
if [ "${#names[@]}" -eq 0 ]; then
  for f in "$repo"/tests/fuzz/*.c; do
    n="$(basename "$f" .c)"
    [ "$n" = replay ] || names+=("$n")
  done
fi
mkdir -p "$out/refs"
cd "$repo"
tools="$repo/tests/.tools"

# ref_objects NAME DIR SOURCES...: tests/.tools/DIR/SOURCE.c compiled once into OUT/refs/NAME/;
# prints the objects. Extra flags come from REFFLAGS.
ref_objects() {
  local name="$1" dir="$2" src
  shift 2
  mkdir -p "$out/refs/$name"
  for src in "$@"; do
    if [ ! -f "$out/refs/$name/$(basename "$src").o" ]; then
      cc -O1 -g -w ${REFFLAGS:-} -I "$dir" -c "$dir/$src.c" -o "$out/refs/$name/$(basename "$src").o" >&2
    fi
    printf '%s\n' "$out/refs/$name/$(basename "$src").o"
  done
}

mapfile -t core < <(find "src/HttpAsm.Core/obj/$config" -name '*.o' | sort)
[ "${#core[@]}" -gt 0 ] || { echo "replay.sh: no $config objects: build $config first" >&2; exit 2; }
status=0
for name in "${names[@]}"; do
  refs=()
  includes=()
  twin="$name"
  # The library: cpu_abi.o (the tiers) for the codec fuzzers, every object but the SDK's libc
  # stubs for the server's; and coverage_rt.o whenever the build has it (Coverage).
  if [ "$name" = server ]; then
    mapfile -t lib < <(find "src/HttpAsm/obj/$config" -name '*.o' -not -path '*/stubs/*' | sort)
  else
    mapfile -t lib < <(find "src/HttpAsm/obj/$config" \( -name 'cpu_abi.o' -o -name 'coverage_rt.o' \) | sort)
  fi
  case "$name" in
    hpack_nghttp2)
      ng="$out/refs/nghttp2-1.71.0"
      if [ ! -d "$ng/lib" ]; then
        mkdir -p "$ng"
        tar -xJf "$tools/nghttp2-1.71.0.tar.xz" -C "$ng" --strip-components=1
      fi
      mapfile -t refs < <(REFFLAGS="-DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -I $ng/lib/includes" ref_objects nghttp2 "$ng/lib" \
        nghttp2_hd nghttp2_hd_huffman nghttp2_hd_huffman_data nghttp2_buf nghttp2_rcbuf nghttp2_mem nghttp2_helper nghttp2_debug nghttp2_version)
      includes=(-I "$ng/lib/includes")
      twin=hpack
      ;;
    h1_request_diff)
      mapfile -t refs < <(ref_objects llhttp "$tools/llhttp-9.4.4" llhttp api http; ref_objects pico "$tools/picohttpparser-dd573d8" picohttpparser)
      includes=(-I "$tools/llhttp-9.4.4" -I "$tools/picohttpparser-dd573d8")
      twin=h1_request
      export HTTPASM_FUZZ_TRIAGE="$repo/tests/fuzz/h1_request_diff.triage"
      ;;
  esac
  program="$out/replay-$name"
  cc -O1 -g -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -Wl,-z,noexecstack -I src/HttpAsm/include "${includes[@]}" \
    "tests/fuzz/$name.c" tests/fuzz/replay.c "${core[@]}" "${lib[@]}" "${refs[@]}" -lpthread -o "$program"
  inputs=()
  [ -d "tests/fuzz/seeds/$twin" ] && inputs+=("tests/fuzz/seeds/$twin")
  [ -d "tests/fuzz/corpus/$name" ] && inputs+=("tests/fuzz/corpus/$name")
  if [ "${#inputs[@]}" -eq 0 ]; then
    echo "replay.sh: $name has no seeds or corpus" >&2
    continue
  fi
  printf 'replay.sh: %s: ' "$name"
  "$program" "${inputs[@]}" || { code=$?; echo "replay.sh: $name failed ($code)" >&2; [ "$status" -ne 0 ] || status=$code; }
done
exit "$status"
