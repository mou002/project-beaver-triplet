#!/bin/bash

gcc -O2 -march=native honest.c -o honest_node -lrt
gcc -O2 -march=native attacker.c -o attacker_p1 -lrt

TRIALS=100
SAMPLE_SIZES=(3 5 10 20 50)

# ------------------------------------------------------------------
# Diagnostic mode: `./benchmark.sh diag [TRIALS]`
# Runs the attacker ONCE at the smallest sample size (N=3) with a
# larger trial count, instead of sweeping all five N values. The
# w=2/w=4 chain-length diagnostics are single-shot measurements that
# do not depend on N at all -- only the PRG/y attack does -- so
# sweeping N for this purpose just multiplies wait time for no extra
# information. Defaults to 1000 trials if not given.
# ------------------------------------------------------------------
if [ "$1" == "diag" ]; then
    DIAG_TRIALS=${2:-1000}
    CORES=$(nproc)
    echo "Running chain-length diagnostic only: N=3, TRIALS=$DIAG_TRIALS (cores detected: $CORES)"

    if [ $CORES -lt 3 ]; then
        echo "WARNING: fewer than 3 cores detected. The attacker and honest nodes will" >&2
        echo "share cores, which can badly degrade the busy-wait synchronization this" >&2
        echo "benchmark relies on -- this is very likely why earlier runs were slow." >&2
    fi

    if [ $CORES -ge 3 ]; then
        taskset -c 0 ./honest_node 2 &
        PID_P2=$!
        taskset -c 1 ./honest_node 3 &
        PID_P3=$!
        sleep 0.01
        taskset -c 2 ./attacker_p1 $DIAG_TRIALS 3
    elif [ $CORES -eq 2 ]; then
        taskset -c 0 ./honest_node 2 &
        PID_P2=$!
        taskset -c 0 ./honest_node 3 &
        PID_P3=$!
        sleep 0.01
        taskset -c 1 ./attacker_p1 $DIAG_TRIALS 3
    else
        ./honest_node 2 &
        PID_P2=$!
        ./honest_node 3 &
        PID_P3=$!
        sleep 0.01
        ./attacker_p1 $DIAG_TRIALS 3
    fi

    kill -9 $PID_P2 2>/dev/null
    kill -9 $PID_P3 2>/dev/null
    wait $PID_P2 2>/dev/null
    wait $PID_P3 2>/dev/null
    rm -f /dev/shm/beaver_tri_attack_shm 2>/dev/null
    exit 0
fi

echo "======================================================================================================"
echo " 3-PARTY BEAVER TRIPLET TRI-ATTACK BENCHMARK (Optimised Persistent Processes)"
echo "======================================================================================================"
printf "%-10s | %-8s | %-16s | %-16s | %-24s\n" "Samples(N)" "Trials" "Input (y) Breach" "Input (x) Breach" "Total Protocol Breach"
echo "------------------------------------------------------------------------------------------------------"

# Detect number of available cores
CORES=$(nproc)

for SAMPLES in "${SAMPLE_SIZES[@]}"; do
    if [ $CORES -ge 3 ]; then
        # 3+ cores: isolate nodes on cores 0,1 and attacker on core 2
        taskset -c 0 ./honest_node 2 &
        PID_P2=$!
        taskset -c 1 ./honest_node 3 &
        PID_P3=$!
        sleep 0.01
        taskset -c 2 ./attacker_p1 $TRIALS $SAMPLES
    elif [ $CORES -eq 2 ]; then
        # 2 cores: put both nodes on core 0, attacker on core 1
        taskset -c 0 ./honest_node 2 &
        PID_P2=$!
        taskset -c 0 ./honest_node 3 &
        PID_P3=$!
        sleep 0.01
        taskset -c 1 ./attacker_p1 $TRIALS $SAMPLES
    else
        # 1 core (or unknown): no taskset (or pin all to core 0 if desired)
        ./honest_node 2 &
        PID_P2=$!
        ./honest_node 3 &
        PID_P3=$!
        sleep 0.01
        ./attacker_p1 $TRIALS $SAMPLES
    fi

    kill -9 $PID_P2 2>/dev/null
    kill -9 $PID_P3 2>/dev/null
    wait $PID_P2 2>/dev/null
    wait $PID_P3 2>/dev/null
    rm -f /dev/shm/beaver_tri_attack_shm 2>/dev/null
done
