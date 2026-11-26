#!/usr/bin/env bash
# =============================================================================
# mca.sh - llvm-mca's static prediction for each version's loops of a routine of libhttpasm.so
# (benchmarks/bench.sh mca ROUTINE runs it on the Linux side; benchmarks/README.md says how far
# its numbers were found to hold against measurements).
#
#   mca.sh LIBRARY ROUTINE [MODEL...]
#     LIBRARY  the built libhttpasm.so (its symbol table names every version: ROUTINE.v1, .v3, ...)
#     ROUTINE  the routine: an exported one without its httpasm_ prefix (field_value_scan), or a
#              library-internal symbol as it is (ha_...)
#     MODEL    llvm-mca CPU models (default: alderlake, this machine's P-core design; a model
#              with AVX-512 - sapphirerapids, znver4 - only for a CPU that has it, by the
#              owner's rule: no AVX-512 is analyzed where it cannot run)
#
# For each version: its code is disassembled (objdump, Intel syntax) from its symbol to the next
# version's or the routine's end; every backward jump closes a loop (its target to it); each
# loop goes to llvm-mca, run for 200 iterations, which gives the cycles one iteration takes in
# steady state as simulated (the figure to compare: it tracked measurements, see below), the
# throughput bound (Block RThroughput, which can miss a change the simulation sees), the
# instructions per cycle, and the units the model loads the most (the likely bottleneck; a
# unit named for two ports, ADLPPort01, sums both). It is a model of the core alone - no
# caches, no frequency, no memory - so it guides a loop's design and never proves anything:
# only a measurement does.
# =============================================================================
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: mca.sh LIBRARY ROUTINE [MODEL...]" >&2; exit 2; }
so="$1"
routine="$2"
shift 2
models=("$@")
[ ${#models[@]} -gt 0 ] || models=(alderlake)
case "$routine" in
  ha_*|httpasm_*) symbol="$routine" ;;
  *) symbol="httpasm_$routine" ;;
esac
command -v llvm-mca >/dev/null || { echo "mca.sh: llvm-mca not found (apt install llvm)" >&2; exit 2; }

# The versions and the routine's end, in address order: "ADDRESS NAME" lines.
symbols="$(nm -n "$so" | awk -v s="$symbol" '$3 ~ ("^" s "\\.(v[0-9]+|end)$") {print $1, $3}')"
[ -n "$symbols" ] || { echo "mca.sh: no versions of $symbol in $so (ROUTINE.vN symbols)" >&2; exit 1; }

echo "$symbols" | while read -r address name; do
  case "$name" in *.end) continue ;; esac
  next="$(echo "$symbols" | awk -v a="$address" 'found {print $1; exit} $1 == a {found = 1}')"
  dis="$(mktemp)"
  objdump -d --no-show-raw-insn -M intel --start-address="0x$address" --stop-address="0x$next" "$so" > "$dis"
  # Each loop: a backward jump inside the version, from its target to the jump itself.
  loops="$(awk '$1 ~ /^[0-9a-f]+:$/ && $2 ~ /^j/ && $3 ~ /^[0-9a-f]+$/ {
             at = $1; sub(":", "", at);
             if (strtonum("0x" $3) < strtonum("0x" at)) print $3, at }' "$dis")"
  if [ -z "$loops" ]; then
    echo "== $name: no loop"
    rm -f "$dis"
    continue
  fi
  echo "$loops" | while read -r from to; do
    body="$(mktemp)"
    # The loop's instructions; a jump's target becomes the label .Lloop: objdump writes it as a
    # bare address, which LLVM's assembler refuses ("unknown token in expression") and llvm-mca
    # then simulates the loop without its branches (it did: 12 of v3's 14 instructions, before
    # 2026-11-26's fix). llvm-mca never follows a branch, so the label only has to exist.
    { echo ".Lloop:"
      awk -v a="$from" -v b="$to" '$1 ~ /^[0-9a-f]+:$/ { x = $1; sub(":", "", x); x = strtonum("0x" x);
            if (x >= strtonum("0x" a) && x <= strtonum("0x" b)) { $1 = ""; sub(/ *<[^>]*>/, ""); sub(/ *#.*/, ""); print } }' "$dis" \
        | sed -E 's/^ +//; s/^(j[a-z]+) +[0-9a-f]+$/\1 .Lloop/'; } > "$body"
    echo "== $name: loop $from..$to ($(( $(wc -l < "$body") - 1 )) instructions)"
    tail -n +2 "$body" | sed 's/^/     /'
    for model in "${models[@]}"; do
      out="$(mktemp)"
      if ! { echo ".intel_syntax noprefix"; cat "$body"; } | llvm-mca -mcpu="$model" -iterations=200 > "$out" 2>&1; then
        echo "   $model: llvm-mca refused it ($(head -1 "$out"))"
        rm -f "$out"
        continue
      fi
      throughput="$(awk '/Block RThroughput:/ {print $3}' "$out")"
      ipc="$(awk '/^IPC:/ {print $2}' "$out")"
      # The simulated cycles an iteration (Total Cycles over the 200 iterations): the figure
      # that tracked measurements (2026-11-26: v3 over v1 predicted 1.95x per octet, measured
      # 1.99-2.10x; one extra uop predicted +9.7%, measured +10.7-12.6%), where the throughput
      # bound alone stayed at 2.0 for both of the last two.
      cycles="$(awk '/^Total Cycles:/ {printf "%.2f", $3 / 200}' "$out")"
      # The units the model loads the most: "Resource pressure per iteration" lists the cycles
      # each unit is busy per iteration, in the order of the "Resources:" legend.
      busiest="$(awk '/^Resources:/ {r = 1; next}
                      r && /^\[[0-9.]+\]/ { name[n++] = $NF; next }
                      r && NF == 0 && n > 0 { r = 0 }
                      /^Resource pressure per iteration:/ { p = 1; next }
                      p == 1 && /^\[/ { p = 2; next }
                      p == 2 { for (i = 1; i <= NF; i++) if ($i != "-") printf "%s %s\n", $i, name[i - 1]; exit }' "$out" \
                 | sort -rn | head -3 | awk '{printf "%s%s %s", (NR > 1 ? ", " : ""), $2, $1}')"
      echo "   $model: $cycles cycles an iteration simulated (throughput bound $throughput), IPC $ipc; busiest units: $busiest"
      rm -f "$out"
    done
    rm -f "$body"
  done
  rm -f "$dis"
done
