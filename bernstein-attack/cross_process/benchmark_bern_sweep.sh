#!/bin/bash
# benchmark_bern_sweep.sh -- recovery vs TRACE COUNT for the full cross-process Bernstein
# attack (the analogue of the paper's N in {3,5,10,20,50} curve, but for the real-AES
# total-time attack). Holds the KEY fixed and sweeps N (= N1 = round-1 traces = N2 =
# round-2 batch size), so the only variable is the number of traces. Reports top / low /
# FULL bytes and wall-time per N -- showing where each phase (round-1 top, round-2 low)
# crosses into full recovery.
#
# Usage: ./benchmark_bern_sweep.sh [stride] [evictKB] [MAXREPS2] [REPS1]
# Defaults: stride=8256 evictKB=1024 MAXREPS2=20 REPS1=2
# Sweep list (edit N_LIST to taste):
N_LIST=(1000000 2000000 4000000 8000000 16000000)

set -u
STRIDE="${1:-8256}"
EVICTKB="${2:-1024}"
MAXR="${3:-20}"
REPS1="${4:-2}"
KEY="0f1e2d3c4b5a69788796a5b4c3d2e1f0"   # fixed across the whole sweep

gcc -O2 -march=native victim_bern.c       -o victim_bern       -lrt     || { echo "victim build failed"; exit 1; }
gcc -O2 -march=native attacker_bern_full.c -o attacker_bern_full -lrt -lm || { echo "attacker build failed"; exit 1; }

CORES=$(nproc)
if   [ "$CORES" -ge 3 ]; then VIC_CPU=0; ATT_CPU=2
elif [ "$CORES" -eq 2 ]; then VIC_CPU=0; ATT_CPU=1
else echo "ERROR: need >=2 cores"; exit 1; fi

echo "cores=$CORES victim->CPU$VIC_CPU attacker->CPU$ATT_CPU stride=$STRIDE evict=${EVICTKB}KB REPS1=$REPS1 MAXREPS2=$MAXR"
echo "fixed key: $KEY  (sweeping N = N1 = N2; total victim traces ~= 2*N1 + live*N2)"
echo "=========================================================================================="
printf "%-12s | %-8s | %-8s | %-10s | %-7s | %-s\n" "N (traces)" "top/16" "low/16" "FULL/16" "time" "live/dead  result"
echo "------------------------------------------------------------------------------------------"

for N in "${N_LIST[@]}"; do
  rm -f /dev/shm/bern_xproc_shm 2>/dev/null
  taskset -c "$VIC_CPU" ./victim_bern "$STRIDE" "$KEY" >/tmp/bsweep_vic.log 2>&1 &
  VIC=$!
  sleep 0.3
  T0=$(date +%s)
  taskset -c "$ATT_CPU" ./attacker_bern_full "$N" "$N" "$MAXR" "$EVICTKB" "$REPS1" >/tmp/bsweep_att.log 2>&1
  T1=$(date +%s); DT=$((T1-T0))
  kill "$VIC" 2>/dev/null; wait "$VIC" 2>/dev/null
  rm -f /dev/shm/bern_xproc_shm 2>/dev/null

  LINE=$(grep -E '^top [0-9]+/16  low [0-9]+/16  FULL [0-9]+/16' /tmp/bsweep_att.log | tail -1)
  TOP=$(echo "$LINE"|grep -oE 'top [0-9]+'|grep -oE '[0-9]+')
  LOW=$(echo "$LINE"|grep -oE 'low [0-9]+'|grep -oE '[0-9]+')
  FULL=$(echo "$LINE"|grep -oE 'FULL [0-9]+'|grep -oE '[0-9]+')
  LD=$(grep -oE 'round-2: [0-9]+ live / [0-9]+ dead' /tmp/bsweep_att.log | tail -1 | grep -oE '[0-9]+ live / [0-9]+ dead')
  RES=""; [ "${FULL:-0}" = "16" ] && RES="*** FULL ***"
  printf "%-12s | %-8s | %-8s | %-10s | %-7s | %-s\n" "$N" "${TOP:-?}" "${LOW:-?}" "${FULL:-?}" "${DT}s" "${LD:-?}  $RES"
done
echo "=========================================================================================="
echo "(top is round-1; low is round-2. Whichever is below 16 at a given N is the limiting phase.)"
