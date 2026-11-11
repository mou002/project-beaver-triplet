# Bernstein cache-timing attack on an AES-128 PRG (Beaver-triplet side-channel project)

A passive, timing-based cache side-channel attack that recovers the **full 128-bit key**
of a software (T-table) AES-128 PRG. It is the *total-encryption-time* (Bernstein) vector,
complementary to the Flush+Reload vector in the paper: instead of probing which cache lines
were touched, it only measures how long each encryption takes.

The code is organized in three layers, from simplest to most realistic:

```
self_attack/          one process times its own AES (proof of the method)
cross_process/        two separate processes, co-resident (the realistic channel)
protocol_integrated/  the AES-PRG runs inside the Beaver-triplet protocol structure
```

## How the attack works

AES software implementations index 1 KB T-tables (= 16 cache lines of 16 entries).
With the cache evicted before each encryption, total encryption time depends on which
lines were hit/missed, and the round-1 index is `plaintext_byte XOR key_byte`. The
**cache line = top 4 bits** of that index, so timing leaks `(plaintext XOR key)` at
line granularity. The attack is statistical: time millions of encryptions, build the
average time per plaintext-byte value, and the key emerges.

- **Round 1** recovers the **top nibble** of each of the 16 key bytes, by correlating a
  reference timing profile (known key) against an attack profile (secret key).
- **Round 2** recovers the **low nibbles** from the *second* AES round, where the S-box
  diffuses low-nibble information into the line-selecting bits. A "confound subtraction"
  (bin residuals by the known round-1 line nibbles, subtract per-bin means) isolates the
  round-2 signal; the low nibbles are then searched one MixColumns lane (4 bytes) at a time.
- Full byte = top nibble (round 1) || low nibble (round 2).

### Robustness machinery
- **stride calibration** — the T-tables are laid out with a per-line spacing (`stride`) so
  the hardware prefetcher doesn't blur which line was accessed. The right stride is
  machine-specific, so it is calibrated at the start of each run.
- **round-1 voting** — average several attack profiles to harden the top-nibble recovery.
- **round-2 z-scored voting** — each measurement batch gets a key-independent confidence
  score `z` (how far the best low-nibble hypothesis stands out); high-z batches dominate,
  noisy batches are discarded.
- **dead-window retry / early-bail** — on a shared host, contention creates windows where
  the signal vanishes (all lanes low-z); these are detected and retried, or bailed out of.
- **z-guided repair** — if round-1 missed one top nibble, its lane shows low z; the lane's
  top-nibble candidates are brute-forced and the one that restores high z is kept.

## Build & run

All files are plain C; build with `gcc -O2 -march=native ... -lm` (add `-lrt` for the
cross-process / protocol files). The cross-process and protocol parts need **≥2 cores**
and the two processes pinned to **different cores** (the busy-wait sync needs both running).

### self_attack
```
gcc -O2 -march=native self_attack/bernstein_retry.c -o bernstein_retry -lm
BERN_KEY=0f1e2d3c4b5a69788796a5b4c3d2e1f0 ./bernstein_retry 3 288000000 2 32000000 12 2 32 48000000
# args: NKEYS N1 REPS1 N2 MAXREPS2 WARM evictKB calN   (stride auto-calibrated)
```

### cross_process
```
gcc -O2 -march=native cross_process/victim_bern.c        -o victim_bern        -lrt
gcc -O2 -march=native cross_process/attacker_bern_full.c -o attacker_bern_full -lrt -lm
taskset -c 0 ./victim_bern 8256 &
taskset -c 1 ./attacker_bern_full 10000000 4000000 20 1024 2
# attacker args: N1 N2 MAXREPS2 evictKB REPS1
```
Benchmarks: `benchmark_bern_full.sh` (multi-key), `benchmark_bern_sweep.sh` (recovery vs
trace count), `benchmark_bern_rate.sh` (success rate vs trace count).

### protocol_integrated
The honest Beaver-triplet party runs the AES-128 PRG on a protocol trigger; the active
attacker party recovers the key by timing it.
```
gcc -O2 -march=native protocol_integrated/honest_tri_aes.c   -o honest_tri_aes   -lrt
gcc -O2 -march=native protocol_integrated/attacker_tri_aes.c -o attacker_tri_aes -lrt -lm
taskset -c 0 ./honest_tri_aes 8256 &
taskset -c 1 ./attacker_tri_aes 10000000 4000000 20 1024 2
```
Benchmark: `benchmark_tri_aes.sh` (multi-key, in-protocol).

## Results (on a shared 2-core AWS instance)
- Full key recovered reliably in a clean measurement window at ~10^6–10^7 traces
  (well under the 2^48 rekeying limit).
- Multi-key: ~3–4 of 5 random keys fully recovered; the misses are **machine contention**
  (dead windows), not the key or the method — the attack flags low-confidence runs rather
  than returning a wrong key.

## Scope / honest caveats
- Requires a **software T-table AES**. Hardware AES (**AES-NI**) has no table lookups and
  no cache channel — the attack does not apply.
- Full recovery uses a **prefetcher-neutralized strided layout**; against stock **contiguous**
  tables, round-1 degrades (partial recovery).
- The ~10^6–10^7 traces must fall within **one key/reseed interval**.
- The reference profile uses a known key; realistically it is built on the attacker's own
  identical co-resident hardware. The `keysel` flag stands in for that and does not affect
  whether the attack works.

*Note:* `true_key` in shared memory and the `top/low/FULL X/16` scoring are **validation
only** — the recovery never uses the key; it is read only to score the guess.
