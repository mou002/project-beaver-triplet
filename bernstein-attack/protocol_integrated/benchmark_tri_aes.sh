#!/bin/bash
# benchmark_tri_aes.sh -- multi-key benchmark of the PROTOCOL-INTEGRATED attack:
# the honest Beaver-triplet party runs a real AES-128 PRG on protocol triggers, and the
# active attacker party recovers its full key via cross-process Bernstein timing. For
# each key: fresh honest party with a random secret PRG key on one core, attacker on
# another, tabulate top / low / FULL bytes + wall-time. Same methodology as the
# standalone cross-process benchmark, but through the protocol's PRG vector.
#
# Usage: ./benchmark_tri_aes.sh [NKEYS] [stride] [N1] [N2] [MAXREPS2] [evictKB] [REPS1]
# Defaults: NKEYS=5 stride=8256 N1=10M N2=4M MAXREPS2=20 evictKB=1024 REPS1=2
# BERN_ZLIVE / BERN_DEADBAIL / BERN_LIVEBAIL pass through to the attacker.

set -u
NKEYS="${1:-5}"
STRIDE="${2:-8256}"
N1="${3:-10000000}"
N2="${4:-4000000}"
MAXR="${5:-20}"
EVICTKB="${6:-1024}"
REPS1="${7:-2}"

gcc -O2 -march=native honest_tri_aes.c   -o honest_tri_aes   -lrt     || { echo "honest build failed"; exit 1; }
gcc -O2 -march=native attacker_tri_aes.c -o attacker_tri_aes -lrt -lm || { echo "attacker build failed"; exit 1; }

CORES=$(nproc)
if   [ "$CORES" -ge 3 ]; then HON_CPU=0; ATT_CPU=2
elif [ "$CORES" -eq 2 ]; then HON_CPU=0; ATT_CPU=1
else echo "ERROR: need >=2 cores (honest party and attacker run simultaneously)"; exit 1; fi

echo "cores=$CORES honest->CPU$HON_CPU attacker->CPU$ATT_CPU stride=$STRIDE N1=$N1 N2=$N2 MAXREPS2=$MAXR evict=${EVICTKB}KB REPS1=$REPS1 ZLIVE=${BERN_ZLIVE:-12}"
echo "protocol PRG = real AES-128 ; attacker = active party recovering the key via Bernstein timing"
echo "=================================================================================="
printf "%-6s | %-8s | %-8s | %-10s | %-7s | %-s\n" "key#" "top/16" "low/16" "FULL/16" "time" "live/dead  result"
echo "----------------------------------------------------------------------------------"

RECOVERED=0; TOTAL_T=0
for ((k=1;k<=NKEYS;k++)); do
  rm -f /dev/shm/beaver_tri_aes_shm 2>/dev/null
  taskset -c "$HON_CPU" ./honest_tri_aes "$STRIDE" >/tmp/taes_hon.log 2>&1 &   # random PRG key
  HON=$!
  sleep 0.3
  T0=$(date +%s)
  taskset -c "$ATT_CPU" ./attacker_tri_aes "$N1" "$N2" "$MAXR" "$EVICTKB" "$REPS1" >/tmp/taes_att.log 2>&1
  T1=$(date +%s); DT=$((T1-T0)); TOTAL_T=$((TOTAL_T+DT))
  kill "$HON" 2>/dev/null; wait "$HON" 2>/dev/null
  rm -f /dev/shm/beaver_tri_aes_shm 2>/dev/null

  LINE=$(grep -E '^top [0-9]+/16  low [0-9]+/16  FULL [0-9]+/16' /tmp/taes_att.log | tail -1)
  TOP=$(echo "$LINE"|grep -oE 'top [0-9]+'|grep -oE '[0-9]+')
  LOW=$(echo "$LINE"|grep -oE 'low [0-9]+'|grep -oE '[0-9]+')
  FULL=$(echo "$LINE"|grep -oE 'FULL [0-9]+'|grep -oE '[0-9]+')
  LD=$(grep -oE 'round-2: [0-9]+ live / [0-9]+ dead' /tmp/taes_att.log | tail -1 | grep -oE '[0-9]+ live / [0-9]+ dead')
  RES=""; [ "${FULL:-0}" = "16" ] && { RES="*** FULL ***"; RECOVERED=$((RECOVERED+1)); }
  printf "%-6s | %-8s | %-8s | %-10s | %-7s | %-s\n" "$k" "${TOP:-?}" "${LOW:-?}" "${FULL:-?}" "${DT}s" "${LD:-?}  $RES"
done
echo "=================================================================================="
echo "full PRG keys recovered (in-protocol, cross-process): $RECOVERED/$NKEYS   (avg $((TOTAL_T/NKEYS))s/key)"
