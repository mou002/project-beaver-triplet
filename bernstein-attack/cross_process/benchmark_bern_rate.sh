#!/bin/bash
# benchmark_bern_rate.sh -- SUCCESS RATE vs trace count for the full cross-process
# attack. Unlike the single-pass sweep, this runs each N multiple times (fresh random
# key each trial) and reports the fraction of full-key recoveries -- averaging out the
# machine-window (contention) noise so the trace-count dependence is actually visible.
# This mirrors the paper's "% of trials at N" methodology.
#
# Usage: ./benchmark_bern_rate.sh [TRIALS] [stride] [evictKB] [MAXREPS2] [REPS1]
# Defaults: TRIALS=4 stride=8256 evictKB=1024 MAXREPS2=20 REPS1=2
# Focus on the LOW-N regime, where the trace-count threshold actually lives (above
# ~2M it is window-limited, not trace-limited):
N_LIST=(500000 1000000 2000000 4000000)

set -u
TRIALS="${1:-4}"
STRIDE="${2:-8256}"
EVICTKB="${3:-1024}"
MAXR="${4:-20}"
REPS1="${5:-2}"

gcc -O2 -march=native victim_bern.c       -o victim_bern       -lrt     || { echo "victim build failed"; exit 1; }
gcc -O2 -march=native attacker_bern_full.c -o attacker_bern_full -lrt -lm || { echo "attacker build failed"; exit 1; }

CORES=$(nproc)
if   [ "$CORES" -ge 3 ]; then VIC_CPU=0; ATT_CPU=2
elif [ "$CORES" -eq 2 ]; then VIC_CPU=0; ATT_CPU=1
else echo "ERROR: need >=2 cores"; exit 1; fi

echo "cores=$CORES victim->CPU$VIC_CPU attacker->CPU$ATT_CPU stride=$STRIDE evict=${EVICTKB}KB REPS1=$REPS1 MAXREPS2=$MAXR TRIALS=$TRIALS"
echo "random key each trial; success = FULL 16/16 (both rounds)"
echo "=================================================================="
printf "%-12s | %-14s | %-12s | %-s\n" "N (traces)" "full recovered" "rate" "avg time"
echo "------------------------------------------------------------------"

for N in "${N_LIST[@]}"; do
  REC=0; SUM_T=0
  for ((t=1;t<=TRIALS;t++)); do
    rm -f /dev/shm/bern_xproc_shm 2>/dev/null
    taskset -c "$VIC_CPU" ./victim_bern "$STRIDE" >/tmp/brate_vic.log 2>&1 &   # random key
    VIC=$!
    sleep 0.3
    T0=$(date +%s)
    taskset -c "$ATT_CPU" ./attacker_bern_full "$N" "$N" "$MAXR" "$EVICTKB" "$REPS1" >/tmp/brate_att.log 2>&1
    T1=$(date +%s); SUM_T=$((SUM_T+T1-T0))
    kill "$VIC" 2>/dev/null; wait "$VIC" 2>/dev/null
    rm -f /dev/shm/bern_xproc_shm 2>/dev/null
    FULL=$(grep -E '^top [0-9]+/16  low [0-9]+/16  FULL [0-9]+/16' /tmp/brate_att.log | tail -1 | grep -oE 'FULL [0-9]+' | grep -oE '[0-9]+')
    [ "${FULL:-0}" = "16" ] && REC=$((REC+1))
    printf "    N=%-10s trial %d/%d: FULL=%s\n" "$N" "$t" "$TRIALS" "${FULL:-?}"
  done
  RATE=$(awk "BEGIN{printf \"%.0f%%\", 100*$REC/$TRIALS}")
  AVG=$((SUM_T/TRIALS))
  printf "%-12s | %-14s | %-12s | %ss\n" "$N" "$REC/$TRIALS" "$RATE" "$AVG"
done
echo "=================================================================="
echo "(rate rises with N until the channel is reliable; residual misses are bad windows)"
