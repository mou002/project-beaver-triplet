#!/bin/bash
# Build + run the two-process LAST-ROUND union-leak attack -> FULL AES-128 key.
# Needs: ost_lr_common.h, ost_lr_honest.c, ost_lr_attacker.c, aes_leak.h in this dir.
#
#   ./ost_lr_benchmark.sh                  # real Flush+Reload
#   OST_ORACLE=1 ./ost_lr_benchmark.sh     # exact-leak logic check (no hardware)
#   OST_THRFRAC=0.3 ./ost_lr_benchmark.sh  # tune the F+R cutoff
#   OST_THRESHOLD=180 ./ost_lr_benchmark.sh # pin a known-good cutoff (reproducible)
set -e
cd "$(dirname "$0")"

M="${1:-100}"

echo "== compiling =="
gcc -O2 -march=native ost_lr_honest.c   -o ost_lr_honest   -lrt
gcc -O2 -march=native ost_lr_attacker.c -o ost_lr_attacker -lrt

echo "== running (M=$M experiments/N, OST_ORACLE=${OST_ORACLE:-0}) =="
rm -f /dev/shm/ost_lastround_shm

taskset -c 0 ./ost_lr_honest &
VIC=$!
sleep 0.3

# Only pass tuning vars through if the caller actually set them (an empty value
# would otherwise look "set" to the attacker and pin a bogus threshold).
ENVV="OST_ORACLE=${OST_ORACLE:-0}"
[ -n "${OST_THRFRAC:-}" ]   && ENVV="$ENVV OST_THRFRAC=$OST_THRFRAC"
[ -n "${OST_THRESHOLD:-}" ] && ENVV="$ENVV OST_THRESHOLD=$OST_THRESHOLD"
[ -n "${OST_DEBUG:-}" ]     && ENVV="$ENVV OST_DEBUG=$OST_DEBUG"
env $ENVV taskset -c 1 ./ost_lr_attacker "$M"

kill "$VIC" 2>/dev/null || true
wait "$VIC" 2>/dev/null || true
rm -f /dev/shm/ost_lastround_shm
echo "== done =="
