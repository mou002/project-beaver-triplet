#!/bin/bash
# benchmark_bern_full.sh -- multi-key benchmark of the FULL cross-process Bernstein
# attack (round-1 + round-2 -> complete AES-128 key). For each key it launches a fresh
# victim with a RANDOM secret key on one core and the full attacker on another, then
# tabulates top / low / FULL bytes recovered. This is the cross-process counterpart of
# the self-attack multi-key validation.
#
# Usage: ./benchmark_bern_full.sh [NKEYS] [stride] [N1] [N2] [MAXREPS2] [evictKB]
# Defaults (fast cross-process params validated to recover the full key):
#   NKEYS=5 stride=8256 N1=10M N2=4M MAXREPS2=20 evictKB=1024
# Tune the round-2 liveness threshold with the environment var BERN_ZLIVE (default 12);
# it is passed through to the attacker.

set -u
NKEYS="${1:-5}"
STRIDE="${2:-8256}"
N1="${3:-10000000}"
N2="${4:-4000000}"
MAXR="${5:-20}"
EVICTKB="${6:-1024}"
REPS1="${7:-2}"

gcc -O2 -march=native victim_bern.c          -o victim_bern          -lrt     || { echo "victim build failed"; exit 1; }
gcc -O2 -march=native attacker_bern_full.c    -o attacker_bern_full   -lrt -lm || { echo "attacker build failed"; exit 1; }

CORES=$(nproc)
if   [ "$CORES" -ge 3 ]; then VIC_CPU=0; ATT_CPU=2
elif [ "$CORES" -eq 2 ]; then VIC_CPU=0; ATT_CPU=1
else echo "ERROR: need >=2 cores (victim and attacker run simultaneously)"; exit 1; fi

echo "cores=$CORES victim->CPU$VIC_CPU attacker->CPU$ATT_CPU stride=$STRIDE N1=$N1 N2=$N2 MAXREPS2=$MAXR evict=${EVICTKB}KB ZLIVE=${BERN_ZLIVE:-12}"
echo "=================================================================================="
printf "%-6s | %-8s | %-8s | %-10s | %-7s | %-s\n" "key#" "top/16" "low/16" "FULL/16" "time" "live/dead  result"
echo "----------------------------------------------------------------------------------"

RECOVERED=0; TOTAL_T=0
for ((k=1;k<=NKEYS;k++)); do
  rm -f /dev/shm/bern_xproc_shm 2>/dev/null
  taskset -c "$VIC_CPU" ./victim_bern "$STRIDE" >/tmp/bfull_vic.log 2>&1 &   # random key each run
  VIC=$!
  sleep 0.3
  T0=$(date +%s)
  taskset -c "$ATT_CPU" ./attacker_bern_full "$N1" "$N2" "$MAXR" "$EVICTKB" "$REPS1" >/tmp/bfull_att.log 2>&1
  T1=$(date +%s); DT=$((T1-T0)); TOTAL_T=$((TOTAL_T+DT))
  kill "$VIC" 2>/dev/null; wait "$VIC" 2>/dev/null
  rm -f /dev/shm/bern_xproc_shm 2>/dev/null

  LINE=$(grep -E '^top [0-9]+/16  low [0-9]+/16  FULL [0-9]+/16' /tmp/bfull_att.log | tail -1)
  TOP=$(echo "$LINE" | grep -oE 'top [0-9]+'  | grep -oE '[0-9]+')
  LOW=$(echo "$LINE" | grep -oE 'low [0-9]+'  | grep -oE '[0-9]+')
  FULL=$(echo "$LINE" | grep -oE 'FULL [0-9]+'| grep -oE '[0-9]+')
  LD=$(grep -oE 'round-2: [0-9]+ live / [0-9]+ dead' /tmp/bfull_att.log | tail -1 | grep -oE '[0-9]+ live / [0-9]+ dead')
  RES=""; [ "${FULL:-0}" = "16" ] && { RES="*** FULL ***"; RECOVERED=$((RECOVERED+1)); }
  printf "%-6s | %-8s | %-8s | %-10s | %-7s | %-s\n" "$k" "${TOP:-?}" "${LOW:-?}" "${FULL:-?}" "${DT}s" "${LD:-?}  $RES"
done
echo "=================================================================================="
echo "full keys recovered (cross-process): $RECOVERED/$NKEYS   (avg $((TOTAL_T/NKEYS))s/key)"
