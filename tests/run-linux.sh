#!/usr/bin/env bash
# =============================================================================
# run-linux.sh - HttpAsm's tests on Linux x64, from any host.
#
# Usage: tests/run-linux.sh [Debug|Release] [test-app arguments...]   (default Debug)
#        HTTPASM_RUNNER=docker|wsl|native tests/run-linux.sh ...       (default: the first that works)
#
# How: the host builds everything (AsmFoundation.Sdk assembles and links libhttpasm.so for
# linux-x64 on Windows, macOS or Linux alike), then the test app runs from its output folder on
# Linux. The test app is a portable .NET app whose deps.json names
# runtimes/linux-x64/native/libhttpasm.so, so the same folder runs unchanged in either place:
#   native  on a Linux x64 host: the folder itself
#   docker  mcr.microsoft.com/dotnet/aspnet:10.0 (ASP.NET Core: ClientTests runs Kestrel), the
#           folder mounted read-only (Docker Desktop
#           on Windows; its default seccomp profile refuses io_uring, so the driver's tests cover
#           the epoll fallback there)
#   wsl     the WSL distribution $HTTPASM_WSL_DISTRO (default Ubuntu), with the .NET 10 runtime
#           in ~/.dotnet. WSL needs no Docker Desktop, and its kernel allows io_uring.
#
# Why Linux at all: libhttpasm.so is a Linux ELF file. The native tests skip themselves
# elsewhere, and HTTPASM_REQUIRE_LINUX=1 makes such a skip a failure here, so this run can only
# pass by running them.
#
# External tools: tests/tools.sh fetches them (pinned by SHA-256) into tests/.tools/, and each
# runner sees h2spec at HTTPASM_H2SPEC (docker: mounted at /tools), with HTTPASM_REQUIRE_H2SPEC=1:
# Http2Tests.PassesH2spec must run its 146 cases, never skip them.
#
# Exit status: 0 when both runs pass (io_uring, then epoll: run_once below), else the first
# failing run's.
# =============================================================================
set -euo pipefail

config="${1:-Debug}"
shift || true
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

dotnet build "$here/tests/HttpAsm.Tests/HttpAsm.Tests.csproj" -c "$config" -nologo -v q
tools="$(bash "$here/tests/tools.sh")"

out="$here/tests/HttpAsm.Tests/bin/$config/net10.0"
runner="${HTTPASM_RUNNER:-}"
if [ -z "$runner" ]; then
  if [ "$(uname -s)" = "Linux" ]; then
    runner=native
  elif docker info >/dev/null 2>&1; then
    runner=docker
  else
    runner=wsl
  fi
fi

# run_once IO: the test app, once, with the server's I/O as IO asks: "uring" (the default:
# io_uring where the kernel has it; WSL's and a Linux host's kernels do, so a silent fall back
# to epoll fails the run there: HTTPASM_REQUIRE_URING=1; Docker's seccomp refuses io_uring, so
# its run falls back by design) or "epoll" (every server asks for epoll: HTTPASM_TEST_IO=epoll).
# Every test thus proves both backends.
run_once() {
  local io="$1" require_uring=0 test_io=""
  shift
  if [ "$io" = epoll ]; then test_io=epoll; elif [ "$runner" != docker ]; then require_uring=1; fi
  echo "run-linux.sh: the tests with the server on $io" >&2
  case "$runner" in
    native)
      (cd "$out" && HTTPASM_REQUIRE_LINUX=1 HTTPASM_H2SPEC="$tools/h2spec" HTTPASM_REQUIRE_H2SPEC=1 \
        HTTPASM_REQUIRE_URING="$require_uring" HTTPASM_TEST_IO="$test_io" dotnet HttpAsm.Tests.dll "$@")
      ;;
    docker)
      # Docker Desktop on Windows needs a Windows path; Git Bash's /k/... form means nothing to it.
      local dout="$out" dtools="$tools"
      if command -v cygpath >/dev/null 2>&1; then dout="$(cygpath -m "$out")"; dtools="$(cygpath -m "$tools")"; fi
      # MSYS_NO_PATHCONV keeps Git Bash from rewriting /t into a Windows path.
      MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$dout:/t:ro" -w /t -v "$dtools:/tools:ro" \
        -e HTTPASM_REQUIRE_LINUX=1 -e DOTNET_NOLOGO=1 -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
        -e HTTPASM_H2SPEC=/tools/h2spec -e HTTPASM_REQUIRE_H2SPEC=1 \
        -e HTTPASM_REQUIRE_URING="$require_uring" -e HTTPASM_TEST_IO="$test_io" \
        mcr.microsoft.com/dotnet/aspnet:10.0 \
        dotnet HttpAsm.Tests.dll "$@"
      ;;
    wsl)
      # K:/source/... is /mnt/k/source/... inside WSL.
      local wout="$out" wtools="$tools" drive
      if command -v cygpath >/dev/null 2>&1; then wout="$(cygpath -m "$out")"; wtools="$(cygpath -m "$tools")"; fi
      drive="$(printf '%s' "${wout:0:1}" | tr 'A-Z' 'a-z')"
      wout="/mnt/$drive${wout:2}"
      drive="$(printf '%s' "${wtools:0:1}" | tr 'A-Z' 'a-z')"
      wtools="/mnt/$drive${wtools:2}"
      wsl.exe -d "${HTTPASM_WSL_DISTRO:-Ubuntu}" -e bash -lc \
        "cd '$wout' && HTTPASM_REQUIRE_LINUX=1 HTTPASM_H2SPEC='$wtools/h2spec' HTTPASM_REQUIRE_H2SPEC=1 HTTPASM_REQUIRE_URING=$require_uring HTTPASM_TEST_IO=$test_io DOTNET_NOLOGO=1 \$HOME/.dotnet/dotnet HttpAsm.Tests.dll $*"
      ;;
    *)
      echo "run-linux.sh: HTTPASM_RUNNER must be docker, wsl or native" >&2
      exit 2
      ;;
  esac
}

# Both backends; the exit status is the first failing run's (0 when both pass).
status=0
run_once uring "$@" || status=$?
run_once epoll "$@" || { [ "$status" -ne 0 ] || status=$?; }
exit "$status"
