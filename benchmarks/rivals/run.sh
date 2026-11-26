#!/usr/bin/env bash
# =============================================================================
# run.sh - builds benchmarks/rivals and runs it: HttpAsm's HTTP/1.1 request parser and HPACK
# decoder beside picohttpparser, llhttp and nghttp2, single-threaded, on one core (rivals.c
# says how it measures and how to read the table).
#
#   1. On the host: tests/tools.sh fetches the rivals' pinned sources (the differential
#      fuzzers' references); libhttpasm.so must be built in CONFIG (default Release).
#   2. On Linux (natively, or in WSL from Windows): the rivals are compiled with -O3
#      -march=native (their best: picohttpparser's and llhttp's SSE4.2 paths need it) into a
#      build directory outside the repository, rivals.c with -O2 against libhttpasm.so, and the
#      program runs ROUNDS rounds (default 41), printing a Markdown table.
#
# Usage: benchmarks/rivals/run.sh [rounds] [config]      HTTPASM_RUNNER=wsl|native as elsewhere.
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rounds="${1:-41}"
config="${2:-Release}"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) runner="${HTTPASM_RUNNER:-wsl}" ;;
  *) runner="${HTTPASM_RUNNER:-native}" ;;
esac
[ -f "$here/src/HttpAsm/bin/$config/libc/linux-x64/libhttpasm.so" ] || { echo "run.sh: build $config first" >&2; exit 2; }
bash "$here/tests/tools.sh" >/dev/null

native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
# lpath PATH: the path as the Linux side sees it (K:/source/... is /mnt/k/source/... in WSL).
lpath() {
  local p="$1" drive
  if [ "$runner" != wsl ]; then printf '%s' "$p"; return; fi
  p="$(native_path "$p")"
  drive="$(printf '%s' "${p:0:1}" | tr 'A-Z' 'a-z')"
  printf '/mnt/%s%s' "$drive" "${p:2}"
}
repo="$(lpath "$here")"
build='$HOME/.cache/httpasm/rivals'
[ "$runner" = native ] && build="$here/benchmarks/rivals/.build"
# The Linux side's commands, one string: no double quotes inside (wsl.exe's command line, as in
# tests/fuzz/run.sh), and no set -e around an explicit exit in WSL's login shell.
command="b=$build; r='$repo'; t=\$r/tests/.tools; lib=\$r/src/HttpAsm/bin/$config/libc/linux-x64
  mkdir -p \$b/ng
  [ -d \$b/ng/lib ] || tar -xJf \$t/nghttp2-1.71.0.tar.xz -C \$b/ng --strip-components=1
  ng=\$b/ng/lib
  cc -O3 -march=native -w -c \$t/picohttpparser-dd573d8/picohttpparser.c -o \$b/pico.o &&
  cc -O3 -march=native -w -I \$t/llhttp-9.4.4 -c \$t/llhttp-9.4.4/llhttp.c -o \$b/llhttp.o &&
  cc -O3 -march=native -w -I \$t/llhttp-9.4.4 -c \$t/llhttp-9.4.4/api.c -o \$b/llapi.o &&
  cc -O3 -march=native -w -I \$t/llhttp-9.4.4 -c \$t/llhttp-9.4.4/http.c -o \$b/llhttp_http.o &&
  for s in nghttp2_hd nghttp2_hd_huffman nghttp2_hd_huffman_data nghttp2_buf nghttp2_rcbuf nghttp2_mem nghttp2_helper nghttp2_debug nghttp2_version; do
    cc -O3 -march=native -w -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -I \$ng/includes -c \$ng/\$s.c -o \$b/\$s.o || exit 1
  done &&
  cc -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -I \$r/src/HttpAsm/include -I \$t/llhttp-9.4.4 \
    -I \$t/picohttpparser-dd573d8 -I \$ng/includes \$r/benchmarks/rivals/rivals.c \$b/*.o \
    -L \$lib -l:libhttpasm.so -Wl,-rpath,\$lib -o \$b/rivals &&
  \$b/rivals $rounds"
if [ "$runner" = wsl ]; then
  wsl.exe -d "${HTTPASM_WSL_DISTRO:-Ubuntu}" -e bash -lc "$command"
else
  bash -c "$command"
fi
