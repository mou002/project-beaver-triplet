#!/bin/bash
# Combined Beaver attack, single operating point.
#   AES side  : controlled-channel model -> Black Swans with `votes` (replay) -> b
#   EC side   : single-shot passive       -> OT choice                         -> a
#   combine with public openings (GF(2^8) XOR)                                 -> x,y
# Needs: beaver_common.h, beaver_honest.c, beaver_attacker.c, aes_leak.h,
#        blackswans.h, ecc_real.h in this dir.
#
#   ./beaver_benchmark.sh [trials] [votes] [ntraces]   # real F+R
#   BEAVER_ORACLE=1 ./beaver_benchmark.sh              # exact-leak logic check
set -e
cd "$(dirname "$0")"
TRIALS="${1:-100}"
VOTES="${2:-20}"
NTRACES="${3:-5}"
ORA="${BEAVER_ORACLE:-0}"

pkill -f '[b]eaver_honest' 2>/dev/null || true
rm -f /dev/shm/beaver_full_attack_shm
sleep 0.2

echo "== compiling (NTRACES=$NTRACES) =="
gcc -O2 -march=native beaver_honest.c -o beaver_honest -lrt
gcc -O2 -march=native -DNTRACES=$NTRACES beaver_attacker.c -o beaver_attacker -lrt

echo "== running (trials=$TRIALS, votes=$VOTES, traces=$NTRACES, mode=$([ "$ORA" = 0 ] && echo F+R || echo ORACLE)) =="
taskset -c 0 ./beaver_honest &
VIC=$!
sleep 0.3
BEAVER_ORACLE="$ORA" BEAVER_HEADER=1 taskset -c 1 ./beaver_attacker "$TRIALS" "$VOTES"
kill "$VIC" 2>/dev/null || true
wait "$VIC" 2>/dev/null || true
rm -f /dev/shm/beaver_full_attack_shm
echo "== done =="
