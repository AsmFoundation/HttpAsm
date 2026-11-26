#!/usr/bin/env bash
# =============================================================================
# bench.sh - HttpAsm's benchmark framework from the command line: builds the runner
# (benchmarks/bench: bench.c and its suites, with the rivals compiled in) against the tree's
# libhttpasm.so, and runs it (benchmarks/README.md: the method, the instruments, how to read a
# verdict). Local only: benchmarks run on the developer's machine, never in CI.
#
#   bench.sh [run] [bench options]       time the selected cases (default: every suite)
#   bench.sh ab COMMIT [bench options]   the same, with COMMIT's libhttpasm.so loaded beside the
#                                        tree's as build COMMIT, interleaved in one process: the
#                                        verdict on a change against the commit before it
#   bench.sh icount [bench options]      exact instructions per call under Intel SDE instead of
#                                        times (the CPU SDE presents follows this machine's)
#   bench.sh mca ROUTINE [MODEL...]      llvm-mca's prediction for each version's loops of
#                                        httpasm_ROUTINE (benchmarks/bench/mca.sh)
#
# The bench options (bench.c's header lists them all): --suite tiers|parsers|rivals|all,
# --filter GLOB over "suite/name/input", --quick, --rounds N, --sample-us N, --json PATH,
# --meta KEY=VALUE, --list. Examples:
#   bench.sh --quick --filter 'tiers/field_value_scan/*'
#   bench.sh ab HEAD~1 --suite parsers
#   bench.sh icount --filter 'parsers/h1_chunked_decode/*'
#   bench.sh mca field_value_scan
#
# How it builds (on Linux: natively, or in WSL from Windows, HTTPASM_RUNNER=wsl|native as for
# tests/run-linux.sh): tests/tools.sh fetches the rivals' pinned sources; they are compiled once
# with -O3 -march=native (their best: picohttpparser's and llhttp's SSE4.2 paths need it) into a
# cache outside the repository; bench.c and the suites with -O2, warnings as errors, against
# libhttpasm.so of CONFIG (Release; HTTPASM_BENCH_CONFIG to change it), which must be built
# first (dotnet build HttpAsm.slnx -c Release). The runner finds that library through its
# RUNPATH; an ab build is a git worktree of COMMIT under benchmarks/.ab/, built with dotnet.
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config="${HTTPASM_BENCH_CONFIG:-Release}"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) runner="${HTTPASM_RUNNER:-wsl}" ;;
  *) runner="${HTTPASM_RUNNER:-native}" ;;
esac
command="run"
case "${1:-}" in
  run|ab|icount|mca) command="$1"; shift ;;
esac

native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
# lpath PATH: the path as the Linux side sees it (K:/source/... is /mnt/k/source/... in WSL).
lpath() {
  local p="$1" drive
  if [ "$runner" != wsl ]; then printf '%s' "$p"; return; fi
  p="$(native_path "$p")"
  drive="$(printf '%s' "${p:0:1}" | tr 'A-Z' 'a-z')"
  printf '/mnt/%s%s' "$drive" "${p:2}"
}
# on_linux SCRIPT: runs a bash script on the Linux side, as one string: no double quotes inside
# (wsl.exe's command line), and no set -e around an explicit exit in WSL's login shell.
on_linux() {
  if [ "$runner" = wsl ]; then
    wsl.exe -d "${HTTPASM_WSL_DISTRO:-Ubuntu}" -e bash -lc "$1"
  else
    bash -c "$1"
  fi
}
# quote ARGS...: the arguments as one single-quoted shell word each, for on_linux's string.
quote() {
  local out="" a
  for a in "$@"; do out="$out '${a//\'/\'\\\'\'}'"; done
  printf '%s' "$out"
}

lib="$here/src/HttpAsm/bin/$config/libc/linux-x64/libhttpasm.so"
[ -f "$lib" ] || { echo "bench.sh: build $config first (dotnet build HttpAsm.slnx -c $config)" >&2; exit 2; }
repo="$(lpath "$here")"

if [ "$command" = mca ]; then
  [ $# -ge 1 ] || { echo "usage: bench.sh mca ROUTINE [MODEL...]" >&2; exit 2; }
  on_linux "bash '$repo/benchmarks/bench/mca.sh' '$(lpath "$lib")'$(quote "$@")"
  exit $?
fi

extra=()
repeat=1
if [ "$command" = ab ]; then
  [ $# -ge 1 ] || { echo "usage: bench.sh ab COMMIT [--repeat N] [bench options]" >&2; exit 2; }
  commit="$(git -C "$here" rev-parse --short "$1")"
  shift
  # --repeat N (default 3): the processes the A/B runs in. Each loads the two builds at fresh
  # random addresses, and identical code at another address can run up to 12% faster or slower
  # in one process (branch-predictor and cache-set aliasing: measured 2026-11-26 against an
  # identical copy, where 2.7% of single-process verdicts were wrong, in random directions), so
  # a verdict on a change counts only when every process gives it (0 wrong in that data).
  repeat=3
  if [ "${1:-}" = --repeat ]; then
    [ $# -ge 2 ] && [ "$2" -ge 1 ] 2>/dev/null || { echo "bench.sh: --repeat needs a count" >&2; exit 2; }
    repeat="$2"
    shift 2
  fi
  tree="$here/benchmarks/.ab/$commit"
  # COMMIT's own build, in a worktree of its own (kept: the next A/B against it starts at once).
  if [ ! -f "$tree/src/HttpAsm/bin/$config/libc/linux-x64/libhttpasm.so" ]; then
    [ -d "$tree" ] || git -C "$here" worktree add --detach "$tree" "$commit" >/dev/null
    echo "bench.sh: building $commit's libhttpasm.so ($config) in $tree" >&2
    dotnet build "$tree/src/HttpAsm/HttpAsm.asmproj" -c "$config" -nologo -v q >&2
  fi
  extra=(--build "$commit=$(lpath "$tree/src/HttpAsm/bin/$config/libc/linux-x64/libhttpasm.so")")
fi
# icount: SDE as tests/tools.sh pins it, unpacked where run-linux.sh unpacks it (WSL: the Linux
# home; natively: tests/.tools/sde), here if no test run has yet. The path goes into the Linux
# side's script unquoted ($s expands there).
icount=""
sde_setup=":"
if [ "$command" = icount ]; then
  sde_archive="$(grep -m1 '^sde_archive=' "$here/tests/tools.sh" | cut -d= -f2)"
  if [ "$runner" = wsl ]; then
    sde_setup="s=\$HOME/.cache/httpasm/sde; [ -x \$s/sde64 ] || { mkdir -p \$s && tar -xJf \$t/$sde_archive -C \$s --strip-components=1; } || exit 1"
  else
    sde_setup="s='$here/tests/.tools/sde'"
  fi
  icount=" --icount \$s/sde64"
fi

bash "$here/tests/tools.sh" >/dev/null
build='$HOME/.cache/httpasm/bench'
[ "$runner" = native ] && build="$here/benchmarks/.build"
output="$(mktemp)"
trap 'rm -f "$output"' EXIT
set +e
on_linux "b=$build; r='$repo'; t=\$r/tests/.tools; lib=\$r/src/HttpAsm/bin/$config/libc/linux-x64
  mkdir -p \$b/rivals \$b/ng
  [ -d \$b/ng/lib ] || tar -xJf \$t/nghttp2-1.71.0.tar.xz -C \$b/ng --strip-components=1
  ng=\$b/ng/lib
  if [ ! -f \$b/rivals/done ]; then
    cc -O3 -march=native -w -c \$t/picohttpparser-dd573d8/picohttpparser.c -o \$b/rivals/pico.o &&
    cc -O3 -march=native -w -I \$t/llhttp-9.4.4 -c \$t/llhttp-9.4.4/llhttp.c -o \$b/rivals/llhttp.o &&
    cc -O3 -march=native -w -I \$t/llhttp-9.4.4 -c \$t/llhttp-9.4.4/api.c -o \$b/rivals/llapi.o &&
    cc -O3 -march=native -w -I \$t/llhttp-9.4.4 -c \$t/llhttp-9.4.4/http.c -o \$b/rivals/llhttp_http.o || exit 1
    for s in nghttp2_hd nghttp2_hd_huffman nghttp2_hd_huffman_data nghttp2_buf nghttp2_rcbuf nghttp2_mem nghttp2_helper nghttp2_debug nghttp2_version; do
      cc -O3 -march=native -w -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -I \$ng/includes -c \$ng/\$s.c -o \$b/rivals/\$s.o || exit 1
    done
    touch \$b/rivals/done
  fi
  cc -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -I \$r/src/HttpAsm/include -I \$t/llhttp-9.4.4 \
    -I \$t/picohttpparser-dd573d8 -I \$ng/includes \$r/benchmarks/bench/bench.c \$r/benchmarks/bench/suite_*.c \
    \$b/rivals/*.o -ldl -Wl,-rpath,\$lib -o \$b/bench || exit 1
  $sde_setup
  for i in \$(seq 1 $repeat); do
    [ $repeat -gt 1 ] && echo && echo == process \$i of $repeat
    \$b/bench$icount$(quote "${extra[@]}" "$@") || exit \$?
  done" | tee "$output"
status=${PIPESTATUS[0]}
set -e
[ "$status" -eq 0 ] || exit "$status"

# The A/B's verdict over the processes: per case and tier, each process's "speedup of current
# over COMMIT" line; the change is proven faster (or slower) only when all of them say so.
if [ "$command" = ab ] && [ "$repeat" -gt 1 ]; then
  echo
  echo "== A/B over $repeat processes: speedup of the tree (current) over $commit, a verdict only when every process gives it"
  awk -v n="$repeat" '
    /^[a-z]+\/[^ ]+\/.*  \(/ { c = $0; sub(/  \(.*/, "", c); next }
    /speedup of current over/ {
      # "speedup of current over COMMIT at TIER: RATIOx [LOW-HIGH] VERDICT"
      tier = $7; sub(/:$/, "", tier); key = c "  " tier
      if (!(key in count)) order[++keys] = key
      count[key]++; ratios[key] = ratios[key] " " $8; verdicts[key] = verdicts[key] " " $NF
      seen[key, $NF]++
    }
    END {
      for (i = 1; i <= keys; i++) {
        k = order[i]
        if (seen[k, "faster"] == n) say = "FASTER (proven)"
        else if (seen[k, "slower"] == n) say = "SLOWER (proven)"
        else if (seen[k, "noise"] == n) say = "no difference"
        else say = "not proven (the processes disagree)"
        printf "  %-56s %-36s %s\n", k, ratios[k], say
      }
    }' "$output"
fi
