#!/usr/bin/env bash
# =============================================================================
# run.sh - HttpAsm measured against nginx and h2o, and against its own HTTP/1.1-only build (the
# isolation measurement of docs/DESIGN.md, "Sharing between the HTTP versions").
#
# Usage (on Linux, from the repository root):
#   dotnet build HttpAsm.slnx -c Release && dotnet build src/HttpAsm/HttpAsm.asmproj -c H1Only
#   benchmarks/run.sh [seconds per run, default 10]
# Environment: ROUNDS (default 3), SERVER_CPUS (default 0-3), CLIENT_CPUS (default 8-15),
# WORKERS (default 4). Needs nginx, h2o (with mruby), wrk and h2load (nghttp2-client).
#
# What it measures. Every server answers GET / with 200 "Hello, World!" (text/plain), the
# TechEmpower plaintext shape, from code (nginx: return 200; h2o: an mruby handler; HttpAsm: the
# samples/Hello handler), with WORKERS workers pinned to SERVER_CPUS; the load generators run
# on CLIENT_CPUS, twice as many, so the servers, not the clients, should be the limit. Scenarios:
#   h1            wrk -t8 -c256: HTTP/1.1 keep-alive, one request at a time per connection
#   h1-pipelined  h2load --h1 -c256 -m16: HTTP/1.1, 16 requests in flight per connection
#   h2            h2load -c64 -m32: h2c with prior knowledge, 32 streams per connection
# Two numbers per run: requests per second, and the server's CPU time per request (utime +
# stime of all its processes, from /proc). The second stays meaningful when a run is limited by
# the client or the machine, which throughput alone would hide.
#
# Fairness: each round runs every server once per scenario, interleaved, so drift (thermal,
# the host's other load) hits all of them alike; the report gives each pair's median over the
# rounds, and the lowest and highest CPU time per request any round measured. The machine's
# details go into the report with the numbers.
#
# io_uring against epoll: "httpasm" (and its control and H1-only twin) runs on epoll, the
# library's default; "httpasm-uring" is the same full build asking for io_uring
# (HELLO_IO=uring), in every scenario; the report says which backend each one really ran on.
# Until 2026-11-23 (b932500) io_uring was the default and these names were the other way
# round ("httpasm-epoll"): results/2026-11-23-2008.md is that run.
#
# The noise floor: "httpasm-control" is a second process of the very same full build (an A/A
# control) in the HTTP/1.1 scenarios. Whatever separates it from "httpasm" is noise, so the
# isolation result (full build vs HTTP/1.1-only build) only counts where it exceeds that gap.
#
# Output: benchmarks/results/<date>-<hhmm>.md (the table and the environment), also printed.
# =============================================================================
set -euo pipefail

seconds="${1:-10}"
rounds="${ROUNDS:-3}"
server_cpus="${SERVER_CPUS:-0-3}"
client_cpus="${CLIENT_CPUS:-8-15}"
workers="${WORKERS:-4}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The version measured, taken now: the binaries are what the tree held when they were built, and
# a file edited while the run goes on must not mark the report "-dirty" after the fact.
# core.autocrlf=input: a checkout made on Windows (core.autocrlf=true writes CRLF) and measured
# from WSL would otherwise read as modified in every file and mark a clean tree "-dirty"; input
# only normalizes CRLF for the comparison (every file is LF in the index) and writes nothing.
measured="$(git -C "$repo" -c core.autocrlf=input describe --always --dirty)"
work="$(mktemp -d)"
mkdir -p "$repo/benchmarks/results"
report="$repo/benchmarks/results/$(date +%F-%H%M).md"

hello="$repo/samples/Hello/bin/Release/libc/linux-x64/hello"
full_lib="$repo/src/HttpAsm/bin/Release/libc/linux-x64"
h1only_lib="$repo/src/HttpAsm/bin/H1Only/libc/linux-x64"
for f in "$hello" "$full_lib/libhttpasm.so" "$h1only_lib/libhttpasm.so"; do
  [ -f "$f" ] || { echo "run.sh: $f is missing: build Release and H1Only first (see Usage)" >&2; exit 2; }
done

pids=()
# cleanup: on any exit, stops every server this script started (SIGTERM: HttpAsm and nginx stop
# gracefully) and removes the scratch directory, so no server outlives a failed run.
cleanup() {
  for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "${work:?}"
}
trap cleanup EXIT

# ---- the servers ---------------------------------------------------------------
LD_LIBRARY_PATH="$full_lib" HELLO_PORT=18081 HELLO_WORKERS="$workers" taskset -c "$server_cpus" "$hello" >"$work/full.log" 2>&1 &
pids+=($!); pid_full=$!
LD_LIBRARY_PATH="$h1only_lib" HELLO_PORT=18082 HELLO_WORKERS="$workers" taskset -c "$server_cpus" "$hello" >"$work/h1only.log" 2>&1 &
pids+=($!); pid_h1only=$!
# The A/A control: the full build again, in a process of its own (see "The noise floor").
LD_LIBRARY_PATH="$full_lib" HELLO_PORT=18086 HELLO_WORKERS="$workers" taskset -c "$server_cpus" "$hello" >"$work/control.log" 2>&1 &
pids+=($!); pid_control=$!
# The full build asking for io_uring, for the comparison with epoll.
LD_LIBRARY_PATH="$full_lib" HELLO_PORT=18087 HELLO_WORKERS="$workers" HELLO_IO=uring taskset -c "$server_cpus" "$hello" >"$work/uring.log" 2>&1 &
pids+=($!); pid_uring=$!

mkdir -p "$work/nginx/logs"
cat >"$work/nginx/nginx.conf" <<EOF
worker_processes $workers;
pid $work/nginx/nginx.pid;
error_log $work/nginx/logs/error.log warn;
events { worker_connections 8192; }
http {
  access_log off;
  keepalive_requests 1000000;
  server { listen 18083; location / { default_type text/plain; return 200 "Hello, World!"; } }
  server { listen 18084 http2; http2_max_concurrent_streams 128;
           location / { default_type text/plain; return 200 "Hello, World!"; } }
}
EOF
taskset -c "$server_cpus" nginx -p "$work/nginx" -c "$work/nginx/nginx.conf" -g "daemon off;" >"$work/nginx.log" 2>&1 &
pids+=($!); pid_nginx=$!

cat >"$work/h2o.conf" <<EOF
listen: 18085
num-threads: $workers
pid-file: $work/h2o.pid
error-log: $work/h2o.err
http2-max-concurrent-requests-per-connection: 128
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            [200, {"content-type" => "text/plain"}, ["Hello, World!"]]
          end
EOF
taskset -c "$server_cpus" h2o -c "$work/h2o.conf" >"$work/h2o.log" 2>&1 &
pids+=($!); pid_h2o=$!

for port in 18081 18082 18083 18084 18085 18086 18087; do
  for _ in $(seq 100); do
    if [ "$port" = 18084 ]; then curl -s --http2-prior-knowledge -o /dev/null "http://127.0.0.1:$port/" && break
    else curl -s -o /dev/null "http://127.0.0.1:$port/" && break; fi
    sleep 0.1
  done
done

# cpu_ticks PID: utime + stime of the process and its children (nginx's workers), in ticks.
cpu_ticks() {
  local total=0 p
  for p in "$1" $(pgrep -P "$1" || true); do
    if [ -r "/proc/$p/stat" ]; then
      # Fields 14 and 15, counted after the command name (which may hold spaces).
      total=$((total + $(sed -E 's/^[0-9]+ \(.*\) //' "/proc/$p/stat" | awk '{print $12 + $13}')))
      # Threads' times are in the process's; a forked worker's are in its own stat.
    fi
  done
  echo "$total"
}
tick="$(getconf CLK_TCK)"

# run SCENARIO PORT PID: prints "requests/s cpu-µs-per-request".
run() {
  local scenario="$1" port="$2" pid="$3" before after rps requests text
  before="$(cpu_ticks "$pid")"
  case "$scenario" in
    h1)
      text="$(taskset -c "$client_cpus" wrk -t8 -c256 -d"${seconds}s" "http://127.0.0.1:$port/")"
      rps="$(echo "$text" | awk '/Requests\/sec/ {print $2}')"
      requests="$(echo "$text" | awk '/requests in/ {print $1}')" ;;
    h1-pipelined)
      text="$(taskset -c "$client_cpus" h2load --h1 -t8 -c256 -m16 -D "$seconds" "http://127.0.0.1:$port/")"
      rps="$(echo "$text" | awk '/^finished in/ {print $4}')"
      requests="$(echo "$text" | awk '/^requests:/ {print $8}')" ;;
    h2)
      text="$(taskset -c "$client_cpus" h2load -t8 -c64 -m32 -D "$seconds" "http://127.0.0.1:$port/")"
      rps="$(echo "$text" | awk '/^finished in/ {print $4}')"
      requests="$(echo "$text" | awk '/^requests:/ {print $8}')" ;;
  esac
  after="$(cpu_ticks "$pid")"
  awk -v r="$rps" -v n="$requests" -v d="$((after - before))" -v t="$tick" \
    'BEGIN { printf "%.0f %.2f\n", r, (n > 0 ? d / t * 1e6 / n : 0) }'
}

declare -A results
servers=("httpasm:18081:$pid_full" "httpasm-control:18086:$pid_control" "httpasm-h1only:18082:$pid_h1only" "httpasm-uring:18087:$pid_uring" "nginx:18083:$pid_nginx" "h2o:18085:$pid_h2o")
for round in $(seq "$rounds"); do
  for scenario in h1 h1-pipelined h2; do
    for entry in "${servers[@]}"; do
      IFS=: read -r name port pid <<<"$entry"
      # HTTP/2 has no HTTP/1.1-only counterpart, so neither the isolation pair nor its control runs there.
      [ "$scenario" = h2 ] && { [ "$name" = httpasm-h1only ] || [ "$name" = httpasm-control ]; } && continue
      [ "$scenario" = h2 ] && [ "$name" = nginx ] && port=18084     # nginx 1.24: h2c on its own port
      line="$(run "$scenario" "$port" "$pid")"
      results["$scenario|$name"]+="$line;"
      echo "round $round  $scenario  $name  $line" >&2
    done
  done
done

# median FIELD "a b;c d;...": the median of field 1 (req/s) or 2 (µs/request) over the rounds.
median() {
  echo "$2" | tr ';' '\n' | awk -v f="$1" 'NF { print $f }' | sort -g | awk '{ v[NR] = $1 } END { print (NR % 2 ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2) }'
}

# range FIELD "a b;c d;...": "lowest-highest" of a field over the rounds; the spread a median hides,
# and what a difference between two servers has to exceed before it means anything.
range() {
  echo "$2" | tr ';' '\n' | awk -v f="$1" 'NF { print $f }' | sort -g | awk 'NR == 1 { lo = $1 } { hi = $1 } END { print lo "-" hi }'
}

{
  echo "# HttpAsm benchmark, $(date '+%F %H:%M')"
  echo
  echo "- Machine: $(lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2}'), $(nproc) logical CPUs; kernel $(uname -r)"
  echo "- Servers: $workers workers on CPUs $server_cpus; load generators on CPUs $client_cpus"
  # --dirty: a run on uncommitted changes says so, instead of naming a commit it did not measure.
  echo "- Versions: HttpAsm $measured, $(nginx -v 2>&1 | sed 's/.*: //'), $(h2o --version | head -1), $(wrk -v 2>&1 | head -1 | awk '{print "wrk " $2}'), h2load $(h2load --version | awk '{print $2}')"
  echo "- $rounds rounds of ${seconds} s per server and scenario, interleaved; medians, and the CPU range over the rounds"
  echo "- httpasm-control is a second process of the same full build: the A/A noise floor"
  # Which backend each HttpAsm server really used: a ring is a descriptor the kernel names
  # anon_inode:[io_uring] (each worker holds one); a server without one waited on epoll.
  for entry in "httpasm:$pid_full" "httpasm-uring:$pid_uring"; do
    IFS=: read -r name pid <<<"$entry"
    if ls -l "/proc/$pid/fd" 2>/dev/null | grep -q 'io_uring'; then io=io_uring; else io=epoll; fi
    echo "- $name ran on $io"
  done
  echo
  echo "| scenario | server | requests/s | CPU µs/request | CPU range | vs nginx (req/s) |"
  echo "|---|---|---:|---:|---:|---:|"
  for scenario in h1 h1-pipelined h2; do
    base="$(median 1 "${results["$scenario|nginx"]}")"
    for entry in "${servers[@]}"; do
      IFS=: read -r name _ _ <<<"$entry"
      [ -n "${results["$scenario|$name"]:-}" ] || continue
      rps="$(median 1 "${results["$scenario|$name"]}")"
      cpu="$(median 2 "${results["$scenario|$name"]}")"
      echo "| $scenario | $name | $rps | $cpu | $(range 2 "${results["$scenario|$name"]}") | $(awk -v a="$rps" -v b="$base" 'BEGIN { printf "%.2fx", a / b }') |"
    done
  done
  echo
  echo "Every round (requests/s, CPU µs/request):"
  echo
  for key in $(printf '%s\n' "${!results[@]}" | sort); do
    echo "- $key: $(echo "${results[$key]}" | sed 's/;$//; s/;/; /g')"
  done
} | tee "$report"
echo "report: $report" >&2
