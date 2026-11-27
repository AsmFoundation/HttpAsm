#!/usr/bin/env bash
# =============================================================================
# dudect.sh - the statistical timing test of tests/ct/dudect.c (dudect's method: a fixed secret
# against random ones, interleaved, Welch's t over the timings), against the Release
# libhttpasm.so, pinned to one core. Local only, like the benchmarks: timing on a shared CI runner
# is too noisy for a verdict (the owner's rule of 2026-11-26). tests/ct/run.sh is the
# deterministic check CI runs.
#
# Usage: tests/ct/dudect.sh [SCALE] [CPU]   (SCALE multiplies each target's calls, default 1;
#                                            CPU the core to pin to, default 2)
# Needs cc and a built Release (dotnet build HttpAsm.slnx -c Release); on Windows run it in WSL.
# Pin it to a quiet performance core: a core shared with other work, or a hybrid CPU's efficiency
# core, adds noise that only lowers t (it cannot fake a leak, but it can hide one).
# Exit status: dudect's: 0 no target fails, 1 one does (|t| > 10), 2 a setup error or a negative
# control (an early-exit compare, measured first) that did not fail.
# =============================================================================
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lib="$here/src/HttpAsm/bin/Release/libc/linux-x64"
[ -f "$lib/libhttpasm.so" ] || { echo "dudect.sh: $lib/libhttpasm.so is missing: build Release first" >&2; exit 2; }
out="$here/tests/native/bin/ct"
mkdir -p "$out"
cc -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -I "$here/src/HttpAsm/include" "$here/tests/ct/dudect.c" \
  -L "$lib" -l:libhttpasm.so -Wl,-rpath,"$lib" -lm -o "$out/dudect" || exit 2
exec taskset -c "${2:-2}" "$out/dudect" "${1:-1}"
