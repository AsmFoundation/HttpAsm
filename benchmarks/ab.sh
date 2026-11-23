#!/usr/bin/env bash
# =============================================================================
# ab.sh - did a change make HttpAsm cheaper or dearer? Two builds of the Hello sample, measured
# interleaved, with an A/A control: the server CPU time per request of build A, build B, and
# build B again in a second process.
#
# Usage (on Linux, from anywhere; each tree built with: dotnet build samples/Hello -c Release):
#   benchmarks/ab.sh <tree A> <tree B> [rounds, default 5] [seconds per run, default 10]
# Environment: SERVER_CPUS (default 0-3), CLIENT_CPUS (default 8-15), WORKERS (default 4),
# HELLO_IO_A and HELLO_IO_B (each tree's backend: epoll, the default, or uring). Needs wrk and
# h2load (nghttp2-client).
#
# A tree is a checkout whose samples/Hello and src/HttpAsm are built in Release: typically the
# commit before a change (git worktree add --detach ../before <commit>) and the working tree.
# The servers answer "Hello, World!"; each round runs every server once per scenario, in turn,
# so drift hits all three alike:
#   h1            wrk -t8 -c256: HTTP/1.1 keep-alive, one request at a time per connection
#   h1-pipelined  h2load --h1 -c256 -m16: 16 requests in flight per connection
# Per run: requests per second, and the server's CPU time per request (utime + stime from
# /proc, which stays meaningful when the load generator or the machine is the limit).
#
# Reading it: "b2" is the same build as "b" in another process, so the gap between b and b2 is
# the noise. A difference between a and b counts only where it is larger than that gap, and a
# per-round ordering that holds round after round is stronger evidence than one median.
#
# Output: every round, then the medians, on stdout; benchmarks/run.sh is the full comparison
# against nginx and h2o.
# =============================================================================
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: benchmarks/ab.sh <tree A> <tree B> [rounds] [seconds]" >&2
  exit 2
fi
tree_a="$(cd "$1" && pwd)"
tree_b="$(cd "$2" && pwd)"
rounds="${3:-5}"
seconds="${4:-10}"
server_cpus="${SERVER_CPUS:-0-3}"
client_cpus="${CLIENT_CPUS:-8-15}"
workers="${WORKERS:-4}"

for tree in "$tree_a" "$tree_b"; do
  for f in "$tree/samples/Hello/bin/Release/libc/linux-x64/hello" "$tree/src/HttpAsm/bin/Release/libc/linux-x64/libhttpasm.so"; do
    [ -f "$f" ] || { echo "ab.sh: $f is missing: build samples/Hello in Release in that tree" >&2; exit 2; }
  done
done

pids=()
# cleanup: on any exit, stops every server this script started (SIGTERM: a graceful stop), so
# none outlives a failed run.
cleanup() {
  for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

# start TREE PORT IO: one Hello server of that tree's build, in the background; $! names it
# afterwards (taskset execs the server, so the process id is the server's). Called directly,
# not in $(...): a job started in a subshell would not be this shell's to wait for.
start() {
  LD_LIBRARY_PATH="$1/src/HttpAsm/bin/Release/libc/linux-x64" HELLO_PORT="$2" HELLO_WORKERS="$workers" HELLO_IO="$3" \
    taskset -c "$server_cpus" "$1/samples/Hello/bin/Release/libc/linux-x64/hello" >/dev/null 2>&1 &
}
start "$tree_a" 18091 "${HELLO_IO_A:-epoll}"; pid_a=$!; pids+=("$pid_a")
start "$tree_b" 18092 "${HELLO_IO_B:-epoll}"; pid_b=$!; pids+=("$pid_b")
start "$tree_b" 18093 "${HELLO_IO_B:-epoll}"; pid_b2=$!; pids+=("$pid_b2")
for port in 18091 18092 18093; do
  for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.1; done
done

echo "# ab.sh, $(date '+%F %H:%M')"
echo "- a: $tree_a ($(git -C "$tree_a" -c core.autocrlf=input describe --always --dirty 2>/dev/null || echo '?')), HELLO_IO=${HELLO_IO_A:-epoll}"
echo "- b, b2: $tree_b ($(git -C "$tree_b" -c core.autocrlf=input describe --always --dirty 2>/dev/null || echo '?')), HELLO_IO=${HELLO_IO_B:-epoll}"
echo "- $(lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2}'), kernel $(uname -r); $workers workers on CPUs $server_cpus, load on $client_cpus; $rounds rounds of $seconds s"
for entry in "a:$pid_a" "b:$pid_b" "b2:$pid_b2"; do
  IFS=: read -r name pid <<<"$entry"
  echo "- $name: $(ls -l "/proc/$pid/fd" 2>/dev/null | grep -c io_uring || true) io_uring rings"
done

tick="$(getconf CLK_TCK)"
# ticks PID: utime + stime of the process (its threads included), in clock ticks; fields 14
# and 15, counted after the command name, which may hold spaces.
ticks() { sed -E 's/^[0-9]+ \(.*\) //' "/proc/$1/stat" | awk '{print $12 + $13}'; }

# run SCENARIO PORT PID: prints "requests/s cpu-µs-per-request".
run() {
  local before after text rps n
  before="$(ticks "$3")"
  if [ "$1" = h1 ]; then
    text="$(taskset -c "$client_cpus" wrk -t8 -c256 -d"${seconds}s" "http://127.0.0.1:$2/")"
    rps="$(echo "$text" | awk '/Requests\/sec/ {print $2}')"
    n="$(echo "$text" | awk '/requests in/ {print $1}')"
  else
    text="$(taskset -c "$client_cpus" h2load --h1 -t8 -c256 -m16 -D "$seconds" "http://127.0.0.1:$2/")"
    rps="$(echo "$text" | awk '/^finished in/ {print $4}')"
    n="$(echo "$text" | awk '/^requests:/ {print $8}')"
  fi
  after="$(ticks "$3")"
  awk -v r="$rps" -v n="$n" -v d="$((after - before))" -v t="$tick" \
    'BEGIN { printf "%.0f %.2f\n", r, (n > 0 ? d / t * 1e6 / n : 0) }'
}

declare -A results
echo
for r in $(seq "$rounds"); do
  for scenario in h1 h1-pipelined; do
    for entry in "a:18091:$pid_a" "b:18092:$pid_b" "b2:18093:$pid_b2"; do
      IFS=: read -r name port pid <<<"$entry"
      line="$(run "$scenario" "$port" "$pid")"
      results["$scenario|$name"]+="$line;"
      echo "- round $r $scenario $name: $line"
    done
  done
done

# median FIELD "a b;c d;...": the median of field 1 (requests/s) or 2 (µs/request).
median() {
  echo "$2" | tr ';' '\n' | awk -v f="$1" 'NF { print $f }' | sort -g |
    awk '{ v[NR] = $1 } END { print (NR % 2 ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2) }'
}
echo
echo "| scenario | server | requests/s | CPU µs/request |"
echo "|---|---|---:|---:|"
for scenario in h1 h1-pipelined; do
  for name in a b b2; do
    echo "| $scenario | $name | $(median 1 "${results["$scenario|$name"]}") | $(median 2 "${results["$scenario|$name"]}") |"
  done
done
