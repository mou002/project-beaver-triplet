#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "common.h"

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
};

// Real w=4 windowed (digit-based) fixed-base scalar multiplication: the
// scalar is split into two 4-bit digits, each resolved by ONE lookup
// into its own 16-entry table, then combined by a point addition.
// Non-constant-time / vulnerable because both table indices are
// directly the secret digits.
static ECPoint windowed_scalar_mult(TriAttackSharedState* state, uint8_t scalar) {
    uint8_t lo = scalar & 0x0F;
    uint8_t hi = (scalar >> 4) & 0x0F;
    ECPoint p_lo = state->ec_table_lo[lo];
    ECPoint p_hi = state->ec_table_hi[hi];
    return ec_point_add(p_lo, p_hi);
}

// Diagnostic-only w=2 variant: the scalar is split into four 2-bit
// digits (weights 1,4,16,64), each resolved by a lookup into its own
// 4-entry table, combined by three point additions. Used only to
// measure how chain length (4 chained lookups here vs. 2 for w=4)
// affects single-shot Flush+Reload resolvability; its result is
// discarded just like the w=4 path.
static ECPoint windowed_scalar_mult_w2(TriAttackSharedState* state, uint8_t scalar) {
    uint8_t d0 = scalar & 0x3;
    uint8_t d1 = (scalar >> 2) & 0x3;
    uint8_t d2 = (scalar >> 4) & 0x3;
    uint8_t d3 = (scalar >> 6) & 0x3;
    ECPoint r01 = ec_point_add(state->ec_table0[d0], state->ec_table1[d1]);
    ECPoint r23 = ec_point_add(state->ec_table2[d2], state->ec_table3[d3]);
    return ec_point_add(r01, r23);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <peer_id (2|3)>\n", argv[0]);
        return 1;
    }
    int peer_id = atoi(argv[1]);
    if (peer_id != 2 && peer_id != 3) {
        fprintf(stderr, "peer_id must be 2 or 3\n");
        return 1;
    }

    int shm_fd;
    TriAttackSharedState* state;

    if (peer_id == 2) {
        shm_unlink(SHM_TRI_NAME);
        shm_fd = shm_open(SHM_TRI_NAME, O_CREAT | O_RDWR, 0666);
        if (shm_fd == -1) { perror("shm_open (creator)"); return 1; }
        if (ftruncate(shm_fd, sizeof(TriAttackSharedState)) == -1) { perror("ftruncate"); return 1; }
        state = (TriAttackSharedState*)mmap(NULL, sizeof(TriAttackSharedState),
                                           PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (state == MAP_FAILED) { perror("mmap"); return 1; }

        for (uint32_t i = 0; i < 256; i++) {
            state->T0[i] = ((i * 16777619U) ^ 0x5A5A5A5AU);
            state->T1[i] = ((SBOX[i] * 2654435761U) ^ 0x3C3C3C3CU);
        }

        // Precompute the (public) w=4 windowed tables:
        //   ec_table_lo[i] = i*G       for i = 0..15
        //   ec_table_hi[i] = i*(16*G)  for i = 0..15
        // Neither depends on any secret scalar -- both parties reuse
        // these, exactly like a real fixed-base precomputed-table
        // implementation would.
        ECPoint G; G.x = 0; G.y = 2; G.is_inf = 0;
        ECPoint cur = ec_infinity();
        for (int i = 0; i < 16; i++) {
            state->ec_table_lo[i] = cur; // cur == i*G at this point
            cur = ec_point_add(cur, G);
        }
        ECPoint G16 = ec_point_add(state->ec_table_lo[15], G); // 16*G
        cur = ec_infinity();
        for (int i = 0; i < 16; i++) {
            state->ec_table_hi[i] = cur; // cur == i*16*G at this point
            cur = ec_point_add(cur, G16);
        }

        // Precompute the (public) w=2 windowed tables (diagnostic-only):
        //   ec_table0[i] = i*G       for i = 0..3
        //   ec_table1[i] = i*(4*G)   for i = 0..3
        //   ec_table2[i] = i*(16*G)  for i = 0..3
        //   ec_table3[i] = i*(64*G)  for i = 0..3
        ECPoint G4  = ec_point_double(ec_point_double(G));    // 4*G
        ECPoint G16b = ec_point_double(ec_point_double(G4));  // 16*G
        ECPoint G64 = ec_point_double(ec_point_double(G16b)); // 64*G
        cur = ec_infinity();
        for (int i = 0; i < 4; i++) { state->ec_table0[i] = cur; cur = ec_point_add(cur, G); }
        cur = ec_infinity();
        for (int i = 0; i < 4; i++) { state->ec_table1[i] = cur; cur = ec_point_add(cur, G4); }
        cur = ec_infinity();
        for (int i = 0; i < 4; i++) { state->ec_table2[i] = cur; cur = ec_point_add(cur, G16b); }
        cur = ec_infinity();
        for (int i = 0; i < 4; i++) { state->ec_table3[i] = cur; cur = ec_point_add(cur, G64); }

        state->p2_ready = 1;
        state->p3_ready = 0;
        state->trial_ready = 0;
        state->trial_done = 0;
        state->exit_flag = 0;
        state->p2_done_ack = 0;
        state->p3_done_ack = 0;
        state->trigger_prg_p2 = 0;
        state->trigger_prg_p3 = 0;
        state->trigger_base_ot_p2 = 0;
        state->trigger_base_ot_p3 = 0;
        state->trigger_base_ot_w2_p2 = 0;
        state->trigger_base_ot_w2_p3 = 0;
        state->stop_flag = 0;
    } else {
        int retries = 0;
        const int max_retries = 1000;
        const useconds_t retry_delay_us = 1000;
        shm_fd = -1;
        while (retries < max_retries) {
            shm_fd = shm_open(SHM_TRI_NAME, O_RDWR, 0666);
            if (shm_fd != -1) break;
            usleep(retry_delay_us);
            retries++;
        }
        if (shm_fd == -1) { perror("shm_open (joiner)"); return 1; }
        state = (TriAttackSharedState*)mmap(NULL, sizeof(TriAttackSharedState),
                                           PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (state == MAP_FAILED) { perror("mmap"); return 1; }
        state->p3_ready = 1;
    }

    // Main loop
    while (!state->exit_flag) {
        // Wait for attacker to start a trial
        while (!state->trial_ready && !state->exit_flag) _mm_pause();
        if (state->exit_flag) break;

        uint8_t a, b, k;
        if (peer_id == 2) {
            a = state->a2;
            b = state->b2;
            k = state->k2;
        } else {
            a = state->a3;
            b = state->b3;
            k = state->k3;
        }

        // Process triggers until attacker sets trial_done
        while (!state->trial_done && !state->exit_flag) {
            if (peer_id == 2) {
                if (state->trigger_prg_p2) {
                    uint8_t r1_idx = state->ctr_prg_p2 ^ k;
                    uint32_t r1_val = state->T0[r1_idx];
                    uint8_t r2_idx = (uint8_t)(r1_val & 0xFF);
                    uint32_t r_j = state->T1[r2_idx];
                    state->wire_M1_p2 = r_j ^ b;
                    state->trigger_prg_p2 = 0;
                }
                if (state->trigger_base_ot_p2) {
                    ECPoint result = windowed_scalar_mult(state, a);
                    (void)result; // a real OT step would use this point; unused here
                    state->trigger_base_ot_p2 = 0;
                }
                if (state->trigger_base_ot_w2_p2) {
                    ECPoint result = windowed_scalar_mult_w2(state, a);
                    (void)result;
                    state->trigger_base_ot_w2_p2 = 0;
                }
            } else {
                if (state->trigger_prg_p3) {
                    uint8_t r1_idx = state->ctr_prg_p3 ^ k;
                    uint32_t r1_val = state->T0[r1_idx];
                    uint8_t r2_idx = (uint8_t)(r1_val & 0xFF);
                    uint32_t r_j = state->T1[r2_idx];
                    state->wire_M1_p3 = r_j ^ b;
                    state->trigger_prg_p3 = 0;
                }
                if (state->trigger_base_ot_p3) {
                    ECPoint result = windowed_scalar_mult(state, a);
                    (void)result;
                    state->trigger_base_ot_p3 = 0;
                }
                if (state->trigger_base_ot_w2_p3) {
                    ECPoint result = windowed_scalar_mult_w2(state, a);
                    (void)result;
                    state->trigger_base_ot_w2_p3 = 0;
                }
            }
            _mm_pause();
        }

        // ---- CRITICAL: set per‑node done acknowledgment ----
        if (peer_id == 2) {
            state->p2_done_ack = 1;
        } else {
            state->p3_done_ack = 1;
        }

        // Wait for attacker to clear trial_done (signals start of next trial)
        while (state->trial_done && !state->exit_flag) _mm_pause();
    }

    munmap(state, sizeof(TriAttackSharedState));
    close(shm_fd);
    return 0;
}
