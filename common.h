#ifndef COMMON_TRI_ATTACK_H
#define COMMON_TRI_ATTACK_H

#include <stdint.h>
#include <stddef.h>
#include <x86intrin.h>

#define SHM_TRI_NAME "/beaver_tri_attack_shm"

// ------------------------------------------------------------------
// Toy elliptic curve: y^2 = x^3 + A*x + B (mod P)
// Small prime field so the arithmetic is real (extended-Euclid modular
// inverse, real point addition/doubling formulas) but easy to hand-check.
// This is NOT cryptographically strong -- it's sized for a benchmark,
// not for security. The point is to give the cache-timing attack a
// realistic *shape* of leak (naive double-and-add scalar multiplication),
// not a working curve.
// ------------------------------------------------------------------
#define EC_P 233u  // prime modulus
#define EC_A 1u
#define EC_B 4u    // curve params: y^2 = x^3 + x + 4 (mod 233)
// Base point G = (0, 4^0.5=2): 2^2 = 4 = 0^3 + 0 + 4 (mod 233). OK.
// G has order 257 (prime, verified computationally), which is > 256 --
// unlike an earlier choice of curve (p=97), where G had order only 5,
// so a -> a*G was NOT injective over the full 8-bit scalar range and
// collapsed many distinct choice shares onto the same point. With
// order(G) = 257 > 255, a -> a*G is guaranteed injective for every
// a in 0..255, matching the prime-order-group assumption used to
// describe the real Simplest OT protocol (Section 1.3 of the paper).

typedef struct {
    uint32_t x;
    uint32_t y;
    uint8_t  is_inf;
    uint8_t  _pad[64 - sizeof(uint32_t) * 2 - sizeof(uint8_t)];
} __attribute__((aligned(64))) ECPoint; // one point == exactly one cache line

// ---- modular arithmetic mod EC_P ----
static inline uint32_t fmod_add(uint32_t a, uint32_t b) { return (a + b) % EC_P; }
static inline uint32_t fmod_sub(uint32_t a, uint32_t b) { return (a + EC_P - (b % EC_P)) % EC_P; }
static inline uint32_t fmod_mul(uint32_t a, uint32_t b) { return (uint32_t)(((uint64_t)a * (uint64_t)b) % EC_P); }

// extended Euclidean algorithm; EC_P is prime so any nonzero a is invertible
static inline uint32_t fmod_inv(uint32_t a) {
    int64_t t = 0, newt = 1;
    int64_t r = EC_P, newr = a % EC_P;
    while (newr != 0) {
        int64_t q = r / newr;
        int64_t tmp_t = t - q * newt; t = newt; newt = tmp_t;
        int64_t tmp_r = r - q * newr; r = newr; newr = tmp_r;
    }
    if (r > 1) return 0; // not invertible (shouldn't happen here)
    if (t < 0) t += EC_P;
    return (uint32_t)t;
}

static inline ECPoint ec_infinity(void) {
    ECPoint inf; inf.x = 0; inf.y = 0; inf.is_inf = 1;
    for (size_t i = 0; i < sizeof(inf._pad); i++) inf._pad[i] = 0;
    return inf;
}

static inline ECPoint ec_point_double(ECPoint P) {
    if (P.is_inf || P.y == 0) return ec_infinity();
    uint32_t num = fmod_add(fmod_mul(3, fmod_mul(P.x, P.x)), EC_A);
    uint32_t den = fmod_inv(fmod_mul(2, P.y));
    uint32_t lambda = fmod_mul(num, den);
    uint32_t x3 = fmod_sub(fmod_mul(lambda, lambda), fmod_mul(2, P.x));
    uint32_t y3 = fmod_sub(fmod_mul(lambda, fmod_sub(P.x, x3)), P.y);
    ECPoint R; R.x = x3; R.y = y3; R.is_inf = 0;
    return R;
}

static inline ECPoint ec_point_add(ECPoint P, ECPoint Q) {
    if (P.is_inf) return Q;
    if (Q.is_inf) return P;
    if (P.x == Q.x) {
        if ((P.y + Q.y) % EC_P == 0) return ec_infinity();
        return ec_point_double(P);
    }
    uint32_t num = fmod_sub(Q.y, P.y);
    uint32_t den = fmod_inv(fmod_sub(Q.x, P.x));
    uint32_t lambda = fmod_mul(num, den);
    uint32_t x3 = fmod_sub(fmod_sub(fmod_mul(lambda, lambda), P.x), Q.x);
    uint32_t y3 = fmod_sub(fmod_mul(lambda, fmod_sub(P.x, x3)), P.y);
    ECPoint R; R.x = x3; R.y = y3; R.is_inf = 0;
    return R;
}

typedef struct {
    uint32_t T0[256] __attribute__((aligned(64)));
    uint32_t T1[256] __attribute__((aligned(64)));

    // Public precomputed w=4 windowed tables for fixed-base scalar
    // multiplication. The scalar is split into two 4-bit digits
    // (lo = scalar & 0xF, hi = scalar >> 4), each resolved by one
    // lookup into its own 16-entry table, then combined by one point
    // addition: scalar*G = ec_table_hi[hi] + ec_table_lo[lo], since
    // ec_table_hi[i] = i*(16*G) and ec_table_lo[i] = i*G. This is
    // standard digit-based fixed-window scalar multiplication (real
    // libraries chain many such small-window lookups for a full-size
    // scalar); w=4 was chosen over a single w=8 table specifically
    // because a 256-entry table takes too long to flush+rescan for a
    // Flush+Reload attacker to resolve reliably (see below).
    ECPoint ec_table_lo[16] __attribute__((aligned(64)));
    ECPoint ec_table_hi[16] __attribute__((aligned(64)));

    // Public precomputed w=2 windowed tables: a diagnostic-only variant
    // used to measure the effect of chain length (number of chained
    // digit-lookups per scalar multiplication) on single-shot
    // Flush+Reload resolvability, independent of the primary w=4
    // attack above. The scalar is split into four 2-bit digits
    // (d0..d3, weights 1,4,16,64), each resolved by a lookup into its
    // own 4-entry table, combined by three point additions. This does
    // not feed into x_success/Synthesis -- it is a separate, purely
    // additive measurement.
    ECPoint ec_table0[4] __attribute__((aligned(64)));
    ECPoint ec_table1[4] __attribute__((aligned(64)));
    ECPoint ec_table2[4] __attribute__((aligned(64)));
    ECPoint ec_table3[4] __attribute__((aligned(64)));
    uint8_t pad0[64];

    // Persistent control flags
    volatile uint8_t p2_ready;
    volatile uint8_t p3_ready;
    volatile uint8_t trial_ready;
    volatile uint8_t trial_done;
    volatile uint8_t exit_flag;

    // PER‑NODE ACKNOWLEDGMENT FLAGS (fixes the race)
    volatile uint8_t p2_done_ack;
    volatile uint8_t p3_done_ack;

    // Trial inputs (written by attacker)
    uint8_t a2, b2, k2;
    uint8_t a3, b3, k3;
    uint8_t secret_x, secret_y;

    // P2 triggers
    volatile uint8_t trigger_prg_p2 __attribute__((aligned(64)));
    volatile uint8_t ctr_prg_p2 __attribute__((aligned(64)));
    volatile uint32_t wire_M1_p2 __attribute__((aligned(64)));
    volatile uint8_t trigger_base_ot_p2 __attribute__((aligned(64)));
    volatile uint8_t trigger_base_ot_w2_p2 __attribute__((aligned(64)));

    // P3 triggers
    volatile uint8_t trigger_prg_p3 __attribute__((aligned(64)));
    volatile uint8_t ctr_prg_p3 __attribute__((aligned(64)));
    volatile uint32_t wire_M1_p3 __attribute__((aligned(64)));
    volatile uint8_t trigger_base_ot_p3 __attribute__((aligned(64)));
    volatile uint8_t trigger_base_ot_w2_p3 __attribute__((aligned(64)));

    volatile uint8_t stop_flag __attribute__((aligned(64)));
} __attribute__((aligned(64))) TriAttackSharedState;

static inline uint64_t measure_access_time(volatile uint8_t* ptr) {
    unsigned int aux;
    _mm_lfence();
    uint64_t start = __rdtscp(&aux);
    _mm_lfence();
    volatile uint8_t value = *ptr;
    _mm_lfence();
    uint64_t end = __rdtscp(&aux);
    _mm_lfence();
    (void)value;
    return end - start;
}

#endif
