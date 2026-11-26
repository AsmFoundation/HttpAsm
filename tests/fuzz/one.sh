#!/usr/bin/env bash
# =============================================================================
# one.sh - builds one fuzzer and runs it: tests/fuzz/run.sh's Linux half, run on Linux (natively,
# or in WSL from Windows). run.sh builds the Fuzz configuration and fetches the tools first.
#
#   1. The reference implementations a differential fuzzer compares against (tests/tools.sh
#      fetches them, pinned): compiled once into WORK/refs/, with libFuzzer's coverage, so the
#      fuzzer explores their paths too, and the sanitizers, so their faults surface as well.
#      They are never part of HttpAsm. -w: their own warnings are not ours to fix.
#   2. The fuzzer: tests/fuzz/NAME.c with clang -fsanitize=fuzzer,address,undefined, linked
#      with the core's Fuzz objects (their markers are libFuzzer's extra counters), cpu_abi.o
#      (httpasm_cpu_limit and the constructor applying HTTPASM_CPU) and its references.
#   3. The run: SECONDS long, -timeout=10 (a parser call takes microseconds: 10 s is a hang),
#      the dictionary tests/fuzz/NAME.dict when there is one, the committed seeds and the
#      working corpus WORK/corpus/NAME. A finding lands in WORK/findings/STAMP-NAME-* and is
#      printed in base64, so a CI log alone reproduces it.
#
# Usage: one.sh WORK NAME SECONDS STAMP
# Exit status: the fuzzer's (0: no finding; 77 for a crash, 70 for a hang, as libFuzzer
# reports them), or the build's failure.
# =============================================================================
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$1"
name="$2"
seconds="$3"
stamp="$4"
mkdir -p "$work/corpus/$name" "$work/bin" "$work/findings" "$work/refs"
cd "$repo"

refcflags=(-g -O1 -w -fsanitize=fuzzer-no-link,address,undefined)

# nghttp2_objects: nghttp2 1.71.0's HPACK sources, compiled once; prints the objects. The
# tarball is unpacked here, on Linux, beside its objects.
nghttp2_objects() {
  local dir="$work/refs/nghttp2-1.71.0" src obj
  if [ ! -d "$dir/lib" ]; then
    mkdir -p "$dir"
    tar -xJf "$repo/tests/.tools/nghttp2-1.71.0.tar.xz" -C "$dir" --strip-components=1
  fi
  mkdir -p "$dir/obj"
  for src in nghttp2_hd nghttp2_hd_huffman nghttp2_hd_huffman_data nghttp2_buf nghttp2_rcbuf nghttp2_mem \
             nghttp2_helper nghttp2_debug nghttp2_version; do
    obj="$dir/obj/$src.o"
    if [ ! -f "$obj" ]; then
      # The two HAVE_ macros are what nghttp2's configure would find on Linux: htons and its
      # kin come from <arpa/inet.h>, which nghttp2_net.h includes only when told so.
      clang "${refcflags[@]}" -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -I "$dir/lib/includes" -c "$dir/lib/$src.c" -o "$obj" >&2
    fi
    printf '%s\n' "$obj"
  done
}

# source_objects DIR NAME SOURCES...: the pinned sources tests/.tools/DIR/SOURCE.c compiled once
# into WORK/refs/NAME/; prints the objects.
source_objects() {
  local dir="$repo/tests/.tools/$1" out="$work/refs/$2" src
  shift 2
  mkdir -p "$out"
  for src in "$@"; do
    if [ ! -f "$out/$src.o" ]; then
      clang "${refcflags[@]}" -I "$dir" -c "$dir/$src.c" -o "$out/$src.o" >&2
    fi
    printf '%s\n' "$out/$src.o"
  done
}

# The fuzzer's references: objects to link and the include directories its source needs; and
# the fuzzer whose seeds and dictionary it shares (a differential fuzzer reads its plain
# twin's input format, so the twin's seeds and words serve it unchanged).
refs=()
includes=()
twin="$name"
case "$name" in
  hpack_nghttp2)
    mapfile -t refs < <(nghttp2_objects)
    includes=(-I "$work/refs/nghttp2-1.71.0/lib/includes")
    twin=hpack
    ;;
  h1_request_diff)
    mapfile -t refs < <(source_objects llhttp-9.4.4 llhttp-9.4.4 llhttp api http; source_objects picohttpparser-dd573d8 picohttpparser-dd573d8 picohttpparser)
    includes=(-I "$repo/tests/.tools/llhttp-9.4.4" -I "$repo/tests/.tools/picohttpparser-dd573d8")
    twin=h1_request
    ;;
esac

# A differential fuzzer's triaged differences (tests/fuzz/NAME.triage), read through
# HTTPASM_FUZZ_TRIAGE: each line a class of verdict difference and the RFC's reason it is right.
if [ -f "$repo/tests/fuzz/$name.triage" ]; then export HTTPASM_FUZZ_TRIAGE="$repo/tests/fuzz/$name.triage"; fi

mapfile -t core < <(find src/HttpAsm.Core/obj/Fuzz -name '*.o' | sort)
mapfile -t lib < <(find src/HttpAsm/obj/Fuzz -name 'cpu_abi.o')
clang -g -O1 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -fsanitize=fuzzer,address,undefined \
  -Wl,-z,noexecstack -I src/HttpAsm/include "${includes[@]}" "tests/fuzz/$name.c" "${core[@]}" "${lib[@]}" \
  "${refs[@]}" -o "$work/bin/$name"

seeds=()
if [ -d "$repo/tests/fuzz/seeds/$twin" ]; then seeds=("$repo/tests/fuzz/seeds/$twin"); fi
dict=()
if [ -f "$repo/tests/fuzz/$twin.dict" ]; then dict=("-dict=$repo/tests/fuzz/$twin.dict"); fi

code=0
(cd "$work/bin" && "./$name" -max_len=65536 -max_total_time="$seconds" -timeout=10 -print_final_stats=1 "${dict[@]}" \
  "-artifact_prefix=$work/findings/$stamp-$name-" "$work/corpus/$name" "${seeds[@]}") || code=$?
for f in "$work/findings/$stamp-$name-"*; do
  if [ -f "$f" ]; then
    echo "one.sh: finding $f, $(stat -c %s "$f") octets, in base64:"
    base64 -w 0 "$f"
    echo
  fi
done
# This script runs as a child of WSL's login shell, not as it, so ~/.bash_logout never runs at
# this exit and the status passes through (run.sh's on_linux keeps set -e out of that shell).
exit "$code"
