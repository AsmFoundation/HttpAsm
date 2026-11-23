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
#   docker  mcr.microsoft.com/dotnet/runtime:10.0, the folder mounted read-only (Docker Desktop
#           on Windows; its default seccomp profile refuses io_uring, so the driver's tests cover
#           the epoll fallback there)
#   wsl     the WSL distribution $HTTPASM_WSL_DISTRO (default Ubuntu), with the .NET 10 runtime
#           in ~/.dotnet. WSL needs no Docker Desktop, and its kernel allows io_uring.
#
# Why Linux at all: libhttpasm.so is a Linux ELF file. The native tests skip themselves
# elsewhere, and HTTPASM_REQUIRE_LINUX=1 makes such a skip a failure here, so this run can only
# pass by running them.
#
# Exit status: the test app's (0 = every test passed).
# =============================================================================
set -euo pipefail

config="${1:-Debug}"
shift || true
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

dotnet build "$here/tests/HttpAsm.Tests/HttpAsm.Tests.csproj" -c "$config" -nologo -v q

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

case "$runner" in
  native)
    cd "$out"
    HTTPASM_REQUIRE_LINUX=1 dotnet HttpAsm.Tests.dll "$@"
    ;;
  docker)
    # Docker Desktop on Windows needs a Windows path; Git Bash's /k/... form means nothing to it.
    if command -v cygpath >/dev/null 2>&1; then out="$(cygpath -m "$out")"; fi
    # MSYS_NO_PATHCONV keeps Git Bash from rewriting /t into a Windows path.
    MSYS_NO_PATHCONV=1 docker run --rm \
      -v "$out:/t:ro" -w /t \
      -e HTTPASM_REQUIRE_LINUX=1 -e DOTNET_NOLOGO=1 -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
      mcr.microsoft.com/dotnet/runtime:10.0 \
      dotnet HttpAsm.Tests.dll "$@"
    ;;
  wsl)
    # K:/source/... is /mnt/k/source/... inside WSL.
    if command -v cygpath >/dev/null 2>&1; then out="$(cygpath -m "$out")"; fi
    drive="$(printf '%s' "${out:0:1}" | tr 'A-Z' 'a-z')"
    wslout="/mnt/$drive${out:2}"
    wsl.exe -d "${HTTPASM_WSL_DISTRO:-Ubuntu}" -e bash -lc \
      "cd '$wslout' && HTTPASM_REQUIRE_LINUX=1 DOTNET_NOLOGO=1 \$HOME/.dotnet/dotnet HttpAsm.Tests.dll $*"
    ;;
  *)
    echo "run-linux.sh: HTTPASM_RUNNER must be docker, wsl or native" >&2
    exit 2
    ;;
esac
