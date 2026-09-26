#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <string.h>
#include <sched.h>
#include "common.h"

// ------------------------------------------------------------------
// Measurement-quality hardening (does not change what's being attacked,
// only reduces self-inflicted OS-level noise around the timing window).
// Best-effort: may silently fail without elevated privileges, which is
// fine -- the attack still runs, just with whatever baseline jitter the
// OS gives it.
//
// NOTE: SCHED_FIFO was tried here and deliberately removed. This
// architecture is multiple processes busy-spinning on shared flags
// (`while (!x) _mm_pause();`); a SCHED_FIFO process at max priority
// will not yield to any SCHED_OTHER process until it blocks on its
// own, which livelocks the whole handshake whenever the attacker and
// an honest node end up sharing a core -- which benchmark.sh does
// deliberately on 1- and 2-core machines, and which can happen by
// accident even on 3+-core machines. Confirmed by reproducing the
// hang and then reproducing success with SCHED_FIFO removed. Not
// worth the risk for a jitter-reduction that mlockall mostly covers
// anyway.
// ------------------------------------------------------------------
static void harden_measurement_environment(void) {
    mlockall(MCL_CURRENT | MCL_FUTURE); // avoid page faults mid-measurement; ignore failure
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

// ------------------------------------------------------------------
// Calibration (once). Uses the MEDIAN of hit/miss timings rather than
// the mean -- a mean is dragged around by occasional outlier spikes
// (an interrupt, a context switch, a page fault), while the median is
// robust to exactly that kind of noise and gives a cleaner separation
// point between the two distributions.
// ------------------------------------------------------------------
static uint64_t calibrate_threshold(void) {
    const int ITER = 1000;
    volatile uint8_t *probe = (volatile uint8_t*)aligned_alloc(64, 64);
    volatile uint8_t *evict = (volatile uint8_t*)aligned_alloc(64, 8 * 1024 * 1024);
    uint64_t *hit_times = (uint64_t*)malloc(sizeof(uint64_t) * ITER);
    uint64_t *miss_times = (uint64_t*)malloc(sizeof(uint64_t) * ITER);

    for (int i = 0; i < ITER; i++) {
        volatile uint8_t dummy = *probe;
        (void)dummy;
        _mm_lfence();
        unsigned int aux;
        uint64_t start = __rdtscp(&aux);
        _mm_lfence();
        dummy = *probe;
        _mm_lfence();
        uint64_t end = __rdtscp(&aux);
        _mm_lfence();
        hit_times[i] = end - start;
    }

    for (int i = 0; i < ITER; i++) {
        for (size_t j = 0; j < 8 * 1024 * 1024; j += 64) {
            volatile uint8_t v = evict[j];
            (void)v;
        }
        _mm_mfence();
        _mm_lfence();
        unsigned int aux;
        uint64_t start = __rdtscp(&aux);
        _mm_lfence();
        volatile uint8_t dummy = *probe;
        (void)dummy;
        _mm_lfence();
        uint64_t end = __rdtscp(&aux);
        _mm_lfence();
        miss_times[i] = end - start;
    }

    qsort(hit_times, ITER, sizeof(uint64_t), cmp_u64);
    qsort(miss_times, ITER, sizeof(uint64_t), cmp_u64);
    uint64_t median_hit = hit_times[ITER / 2];
    uint64_t median_miss = miss_times[ITER / 2];
    uint64_t threshold = (median_hit + median_miss) / 2;

    free((void*)probe);
    free((void*)evict);
    free(hit_times);
    free(miss_times);
    return threshold;
}


// ------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------
static void shuffle_16(int *arr) {
    for (int i = 15; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}


// Flush+Reload both 16-entry public windowed tables and recover the
// full 8-bit scalar from a SINGLE flush/trigger/probe round: the honest
// node's lookup touches exactly one line in ec_table_lo and exactly one
// line in ec_table_hi, so identifying those two lines directly reveals
// both nibbles of the scalar in one shot. Probing 32 lines total (vs.
// 256 for a single w=8 table) keeps the flush-to-probe window short
// enough for the signal to survive.
static uint8_t recover_scalar_via_window_leak(
        TriAttackSharedState* state, uint64_t threshold,
        volatile uint8_t* trigger_flag) {

    // Interleave both tables into one 32-slot probing sequence so the
    // scan is one continuous pass, not two separate batches.
    int slot_table[32];
    int slot_index[32];
    for (int i = 0; i < 16; i++) { slot_table[i] = 0; slot_index[i] = i; }
    for (int i = 0; i < 16; i++) { slot_table[16 + i] = 1; slot_index[16 + i] = i; }
    // Fisher-Yates shuffle applied jointly to both parallel arrays
    for (int i = 31; i > 0; i--) {
        int j = rand() % (i + 1);
        int tt = slot_table[i]; slot_table[i] = slot_table[j]; slot_table[j] = tt;
        int ti = slot_index[i]; slot_index[i] = slot_index[j]; slot_index[j] = ti;
    }

    for (int i = 0; i < 16; i++) {
        _mm_clflush((const void*)&state->ec_table_lo[i]);
        _mm_clflush((const void*)&state->ec_table_hi[i]);
    }
    _mm_mfence();

    *trigger_flag = 1;
    while (*trigger_flag) _mm_pause();

    int best_lo = -1; uint64_t best_lo_t = UINT64_MAX;
    int best_hi = -1; uint64_t best_hi_t = UINT64_MAX;
    for (int s = 0; s < 32; s++) {
        int idx = slot_index[s];
        uint64_t t;
        if (slot_table[s] == 0) {
            t = measure_access_time((volatile uint8_t*)&state->ec_table_lo[idx]);
            if (t < threshold && t < best_lo_t) { best_lo_t = t; best_lo = idx; }
        } else {
            t = measure_access_time((volatile uint8_t*)&state->ec_table_hi[idx]);
            if (t < threshold && t < best_hi_t) { best_hi_t = t; best_hi = idx; }
        }
    }

    uint8_t lo = (best_lo >= 0) ? (uint8_t)best_lo : (uint8_t)(rand() % 16);
    uint8_t hi = (best_hi >= 0) ? (uint8_t)best_hi : (uint8_t)(rand() % 16);
    return (uint8_t)((hi << 4) | lo);
}

// Diagnostic-only w=2 counterpart: same principle, but the scalar is
// split into FOUR 2-bit digits across four 4-entry tables (16 lines
// total, same as w=4's 32-line scan halved). Used only to measure how
// chain length (4 chained digit-lookups here vs. 2 for w=4) affects
// single-shot Flush+Reload resolvability; does not feed into
// x_success/Synthesis.
static uint8_t recover_scalar_via_w2_window_leak(
        TriAttackSharedState* state, uint64_t threshold,
        volatile uint8_t* trigger_flag) {

    int slot_table[16];
    int slot_index[16];
    for (int t = 0; t < 4; t++) {
        for (int i = 0; i < 4; i++) {
            slot_table[t*4 + i] = t;
            slot_index[t*4 + i] = i;
        }
    }
    for (int i = 15; i > 0; i--) {
        int j = rand() % (i + 1);
        int tt = slot_table[i]; slot_table[i] = slot_table[j]; slot_table[j] = tt;
        int ti = slot_index[i]; slot_index[i] = slot_index[j]; slot_index[j] = ti;
    }

    for (int i = 0; i < 4; i++) {
        _mm_clflush((const void*)&state->ec_table0[i]);
        _mm_clflush((const void*)&state->ec_table1[i]);
        _mm_clflush((const void*)&state->ec_table2[i]);
        _mm_clflush((const void*)&state->ec_table3[i]);
    }
    _mm_mfence();

    *trigger_flag = 1;
    while (*trigger_flag) _mm_pause();

    int best[4] = {-1,-1,-1,-1};
    uint64_t best_t[4] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
    for (int s = 0; s < 16; s++) {
        int tbl = slot_table[s];
        int idx = slot_index[s];
        volatile uint8_t* ptr;
        switch (tbl) {
            case 0: ptr = (volatile uint8_t*)&state->ec_table0[idx]; break;
            case 1: ptr = (volatile uint8_t*)&state->ec_table1[idx]; break;
            case 2: ptr = (volatile uint8_t*)&state->ec_table2[idx]; break;
            default: ptr = (volatile uint8_t*)&state->ec_table3[idx]; break;
        }
        uint64_t t = measure_access_time(ptr);
        if (t < threshold && t < best_t[tbl]) { best_t[tbl] = t; best[tbl] = idx; }
    }

    uint8_t d0 = (best[0] >= 0) ? (uint8_t)best[0] : (uint8_t)(rand() % 4);
    uint8_t d1 = (best[1] >= 0) ? (uint8_t)best[1] : (uint8_t)(rand() % 4);
    uint8_t d2 = (best[2] >= 0) ? (uint8_t)best[2] : (uint8_t)(rand() % 4);
    uint8_t d3 = (best[3] >= 0) ? (uint8_t)best[3] : (uint8_t)(rand() % 4);
    return (uint8_t)(d0 | (d1 << 2) | (d2 << 4) | (d3 << 6));
}

// Diagnostic accumulators: per-bit Hamming accuracy AND exact-match rate
// across all trials. For a windowed (one-hot) leak, exact-match is the
// more natural metric -- either the right line was found (all 8 bits
// correct at once) or the wrong one was (bits then agree with the truth
// only by chance, ~50% on average). Keeping both lets us see that
// pattern directly.
static long g_bits_compared = 0;
static long g_bits_correct = 0;
static long g_exact_total = 0;
static long g_exact_correct = 0;
static long g_nibble_total = 0;
static long g_nibble_correct = 0;

static void tally_bit_accuracy(uint8_t recovered, uint8_t actual) {
    for (int i = 0; i < 8; i++) {
        g_bits_compared++;
        if (((recovered >> i) & 1) == ((actual >> i) & 1)) g_bits_correct++;
    }
    g_exact_total++;
    if (recovered == actual) g_exact_correct++;

    uint8_t r_lo = recovered & 0x0F, r_hi = (recovered >> 4) & 0x0F;
    uint8_t a_lo = actual & 0x0F, a_hi = (actual >> 4) & 0x0F;
    g_nibble_total += 2;
    if (r_lo == a_lo) g_nibble_correct++;
    if (r_hi == a_hi) g_nibble_correct++;
}

// Diagnostic accumulators for the w=2 (4-chain) variant.
static long g_w2_digit_total = 0;
static long g_w2_digit_correct = 0;
static long g_w2_exact_total = 0;
static long g_w2_exact_correct = 0;

static void tally_w2_accuracy(uint8_t recovered, uint8_t actual) {
    for (int shift = 0; shift < 8; shift += 2) {
        uint8_t r_d = (recovered >> shift) & 0x3;
        uint8_t a_d = (actual >> shift) & 0x3;
        g_w2_digit_total++;
        if (r_d == a_d) g_w2_digit_correct++;
    }
    g_w2_exact_total++;
    if (recovered == actual) g_w2_exact_correct++;
}

static uint8_t rev_T1[16][20];
static int rev_T1_count[16];

static void build_rev_T1(TriAttackSharedState* state) {
    for (int l = 0; l < 16; l++) rev_T1_count[l] = 0;
    for (int r1 = 0; r1 < 256; r1++) {
        uint8_t r2 = (uint8_t)(state->T0[r1] & 0xFF);
        int line = r2 >> 4;
        rev_T1[line][rev_T1_count[line]++] = (uint8_t)r1;
    }
}

// ------------------------------------------------------------------
// Main
// ------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_trials> <samples_per_trial>\n", argv[0]);
        return 1;
    }
    int total_trials = atoi(argv[1]);
    int samples = atoi(argv[2]);

    int shm_fd = shm_open(SHM_TRI_NAME, O_RDWR, 0666);
    if (shm_fd == -1) { perror("shm_open"); return 2; }
    TriAttackSharedState* state = (TriAttackSharedState*)mmap(
        NULL, sizeof(TriAttackSharedState), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0
    );
    if (state == MAP_FAILED) { perror("mmap"); return 2; }

    while (!state->p2_ready || !state->p3_ready) _mm_pause();

    harden_measurement_environment();

    // TLB warm-up: touch every ec_table_lo/ec_table_hi line once here,
    // before any trial. Public information, so it leaks nothing; it
    // just ensures page-table entries are resident so a page-walk
    // isn't mixed into the cache hit/miss timing signal during trials.
    for (int i = 0; i < 16; i++) {
        volatile uint8_t warm_lo = *(volatile uint8_t*)&state->ec_table_lo[i];
        volatile uint8_t warm_hi = *(volatile uint8_t*)&state->ec_table_hi[i];
        (void)warm_lo; (void)warm_hi;
    }
    for (int i = 0; i < 4; i++) {
        volatile uint8_t w0 = *(volatile uint8_t*)&state->ec_table0[i];
        volatile uint8_t w1 = *(volatile uint8_t*)&state->ec_table1[i];
        volatile uint8_t w2 = *(volatile uint8_t*)&state->ec_table2[i];
        volatile uint8_t w3 = *(volatile uint8_t*)&state->ec_table3[i];
        (void)w0; (void)w1; (void)w2; (void)w3;
    }

    uint64_t threshold = calibrate_threshold();
    srand(time(NULL));
    build_rev_T1(state);

    int y_success = 0, x_success = 0, total_success = 0;

    // Progress indicator on stderr (doesn't interfere with the stdout
    // results table). Updates at most ~20 times total, not every trial,
    // so it doesn't itself add overhead to the timing-sensitive loop.
    int progress_step = total_trials / 20;
    if (progress_step < 1) progress_step = 1;
    time_t progress_start = time(NULL);

    for (int trial = 0; trial < total_trials; trial++) {
        if (trial % progress_step == 0 || trial == total_trials - 1) {
            double frac = (double)(trial + 1) / (double)total_trials;
            long elapsed = (long)(time(NULL) - progress_start);
            char eta_buf[32];
            if (frac > 0.001) {
                long eta = (long)(elapsed / frac - elapsed);
                snprintf(eta_buf, sizeof(eta_buf), "%lds", eta);
            } else {
                snprintf(eta_buf, sizeof(eta_buf), "?");
            }
            fprintf(stderr, "\r[N=%d] trial %d/%d (%.0f%%) elapsed=%lds eta=%s   ",
                    samples, trial + 1, total_trials, frac * 100.0, elapsed, eta_buf);
            fflush(stderr);
        }
        // ---- new trial: clear acknowledgment flags ----
        state->p2_done_ack = 0;
        state->p3_done_ack = 0;

        // Generate random inputs. a2/a3 are now full 8-bit scalars --
        // the ladder leak recovers all 8 bits, not just a 4-bit line index.
        uint8_t a2 = rand() % 256;
        uint8_t b2 = rand() % 256;
        uint8_t k2 = rand() % 256;
        uint8_t a3 = rand() % 256;
        uint8_t b3 = rand() % 256;
        uint8_t k3 = rand() % 256;
        uint8_t secret_x = rand() % 256;
        uint8_t secret_y = rand() % 256;

        state->a2 = a2; state->b2 = b2; state->k2 = k2;
        state->a3 = a3; state->b3 = b3; state->k3 = k3;
        state->secret_x = secret_x; state->secret_y = secret_y;

        state->trial_ready = 1;

        // --- ATTACK 1A: P2 ---
        uint32_t scores_p2[256] = {0};
        uint32_t cap_M1_p2_step0 = 0;

        for (int s = 0; s < samples; s++) {
            int order[16];
            for (int i = 0; i < 16; i++) order[i] = i;
            shuffle_16(order);

            for (int i = 0; i < 16; i++) {
                _mm_clflush((const void*)((uint8_t*)state->T0 + i * 64));
                _mm_clflush((const void*)((uint8_t*)state->T1 + i * 64));
            }
            _mm_mfence();

            state->ctr_prg_p2 = (uint8_t)s;
            state->trigger_prg_p2 = 1;
            while (state->trigger_prg_p2) _mm_pause();

            if (s == 0) cap_M1_p2_step0 = state->wire_M1_p2;

            for (int idx = 0; idx < 16; idx++) {
                int l = order[idx];
                if (measure_access_time((volatile uint8_t*)state->T0 + l * 64) < threshold) {
                    int base = l * 16;
                    for (int off = 0; off < 16; off++) {
                        uint8_t cand_k = (base + off) ^ s;
                        scores_p2[cand_k]++;
                    }
                }
            }

            for (int idx = 0; idx < 16; idx++) {
                int l = order[idx];
                if (measure_access_time((volatile uint8_t*)state->T1 + l * 64) < threshold) {
                    for (int i = 0; i < rev_T1_count[l]; i++) {
                        uint8_t r1_idx = rev_T1[l][i];
                        uint8_t cand_k = s ^ r1_idx;
                        scores_p2[cand_k]++;
                    }
                }
            }
        }

        int best_k2 = 0;
        uint32_t max_s2 = 0;
        for (int k = 0; k < 256; k++) {
            if (scores_p2[k] > max_s2) {
                max_s2 = scores_p2[k];
                best_k2 = k;
            }
        }
        uint8_t r0_p2 = state->T1[(uint8_t)(state->T0[0 ^ best_k2] & 0xFF)];
        uint8_t rec_b2 = (uint8_t)(cap_M1_p2_step0 ^ r0_p2);

        // --- ATTACK 1B: P3 ---
        uint32_t scores_p3[256] = {0};
        uint32_t cap_M1_p3_step0 = 0;

        for (int s = 0; s < samples; s++) {
            int order[16];
            for (int i = 0; i < 16; i++) order[i] = i;
            shuffle_16(order);

            for (int i = 0; i < 16; i++) {
                _mm_clflush((const void*)((uint8_t*)state->T0 + i * 64));
                _mm_clflush((const void*)((uint8_t*)state->T1 + i * 64));
            }
            _mm_mfence();

            state->ctr_prg_p3 = (uint8_t)s;
            state->trigger_prg_p3 = 1;
            while (state->trigger_prg_p3) _mm_pause();

            if (s == 0) cap_M1_p3_step0 = state->wire_M1_p3;

            for (int idx = 0; idx < 16; idx++) {
                int l = order[idx];
                if (measure_access_time((volatile uint8_t*)state->T0 + l * 64) < threshold) {
                    int base = l * 16;
                    for (int off = 0; off < 16; off++) {
                        uint8_t cand_k = (base + off) ^ s;
                        scores_p3[cand_k]++;
                    }
                }
            }

            for (int idx = 0; idx < 16; idx++) {
                int l = order[idx];
                if (measure_access_time((volatile uint8_t*)state->T1 + l * 64) < threshold) {
                    for (int i = 0; i < rev_T1_count[l]; i++) {
                        uint8_t r1_idx = rev_T1[l][i];
                        uint8_t cand_k = s ^ r1_idx;
                        scores_p3[cand_k]++;
                    }
                }
            }
        }

        int best_k3 = 0;
        uint32_t max_s3 = 0;
        for (int k = 0; k < 256; k++) {
            if (scores_p3[k] > max_s3) {
                max_s3 = scores_p3[k];
                best_k3 = k;
            }
        }
        uint8_t r0_p3 = state->T1[(uint8_t)(state->T0[0 ^ best_k3] & 0xFF)];
        uint8_t rec_b3 = (uint8_t)(cap_M1_p3_step0 ^ r0_p3);

        // --- ATTACK 2: EC windowed (w=8) scalar-mult table leak ---
        // Single-shot per party -- one lookup, one flush/trigger/probe,
        // matching a real one-session Base-OT fixed-base multiplication.
        uint8_t rec_a2 = recover_scalar_via_window_leak(state, threshold, &state->trigger_base_ot_p2);
        uint8_t rec_a3 = recover_scalar_via_window_leak(state, threshold, &state->trigger_base_ot_p3);
        tally_bit_accuracy(rec_a2, a2);
        tally_bit_accuracy(rec_a3, a3);

        // --- ATTACK 2b (diagnostic-only): w=2 chain-length comparison ---
        // Does not feed into x_success/Synthesis below.
        uint8_t rec_a2_w2 = recover_scalar_via_w2_window_leak(state, threshold, &state->trigger_base_ot_w2_p2);
        uint8_t rec_a3_w2 = recover_scalar_via_w2_window_leak(state, threshold, &state->trigger_base_ot_w2_p3);
        tally_w2_accuracy(rec_a2_w2, a2);
        tally_w2_accuracy(rec_a3_w2, a3);

        // --- Synthesis ---
        uint8_t a1_share = 0x11, b1_share = 0x22;
        uint8_t delta_x = (uint8_t)(secret_x - (a1_share + a2 + a3));
        uint8_t delta_y = (uint8_t)(secret_y - (b1_share + b2 + b3));
        uint8_t reconstructed_x = (uint8_t)(delta_x + a1_share + rec_a2 + rec_a3);
        uint8_t reconstructed_y = (uint8_t)(delta_y + b1_share + rec_b2 + rec_b3);

        int y_ok = (reconstructed_y == secret_y);
        int x_ok = (reconstructed_x == secret_x);
        int triplets_ok = (rec_b2 == b2) && (rec_b3 == b3);

        if (y_ok && x_ok && triplets_ok) {
            y_success++; x_success++; total_success++;
        } else if (y_ok && triplets_ok) {
            y_success++;
        } else if (x_ok) {
            x_success++;
        }

        // ---- Signal trial done and wait for both nodes ----
        state->trial_done = 1;

        // Wait for both nodes to acknowledge they finished processing
        while (!state->p2_done_ack || !state->p3_done_ack) _mm_pause();

        // Reset for next trial
        state->trial_ready = 0;
        state->trial_done = 0;
    }
    fprintf(stderr, "\n");

    // Terminate nodes
    state->exit_flag = 1;

    // ---- Print a single table row matching the benchmark header ----
    printf("%-10d | %-8d | %-15.2f%% | %-15.2f%% | %-24.2f%%\n",
           samples, total_trials,
           (double)y_success / total_trials * 100.0,
           (double)x_success / total_trials * 100.0,
           (double)total_success / total_trials * 100.0);

    // ---- Diagnostic: single-shot leak quality on the w=4 windowed tables ----
    double bit_acc = g_bits_compared ? (100.0 * (double)g_bits_correct / (double)g_bits_compared) : 0.0;
    double exact_acc = g_exact_total ? (100.0 * (double)g_exact_correct / (double)g_exact_total) : 0.0;
    double nibble_acc = g_nibble_total ? (100.0 * (double)g_nibble_correct / (double)g_nibble_total) : 0.0;
    printf("    -> single-shot per-bit accuracy:    %.2f%% (chance = 50.00%%, n=%ld bits)\n",
           bit_acc, g_bits_compared);
    printf("    -> single-shot per-nibble accuracy: %.2f%% (chance = 6.25%%, n=%ld nibbles)\n",
           nibble_acc, g_nibble_total);
    printf("    -> single-shot exact-byte accuracy: %.2f%% (chance = %.4f%%, n=%ld lookups)\n",
           exact_acc, 100.0 / 256.0, g_exact_total);

    // ---- Diagnostic: w=2 (4-chain) variant, for chain-length comparison ----
    double w2_digit_acc = g_w2_digit_total ? (100.0 * (double)g_w2_digit_correct / (double)g_w2_digit_total) : 0.0;
    double w2_exact_acc = g_w2_exact_total ? (100.0 * (double)g_w2_exact_correct / (double)g_w2_exact_total) : 0.0;
    printf("    -> [w=2, 4-chain] single-shot per-digit accuracy:  %.2f%% (chance = 25.00%%, n=%ld digits)\n",
           w2_digit_acc, g_w2_digit_total);
    printf("    -> [w=2, 4-chain] single-shot exact-byte accuracy: %.2f%% (chance = %.4f%%, n=%ld lookups)\n",
           w2_exact_acc, 100.0 / 256.0, g_w2_exact_total);

    munmap(state, sizeof(TriAttackSharedState));
    close(shm_fd);
    return 0;
}
