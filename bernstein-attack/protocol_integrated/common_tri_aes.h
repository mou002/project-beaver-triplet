// common_tri_aes.h -- shared state for the Beaver-triplet PRG vector with a REAL AES-128
// PRG (replacing the toy two-lookup PRG) attacked by cross-process Bernstein timing.
// This is the §4.2 "Offline PRG Vector" of the paper, but: (a) the PRG is full AES-128
// on strided T-tables instead of a 1-byte-key toy, and (b) the channel is total-time
// Bernstein (time the triggered PRG) instead of Flush+Reload. The protocol structure is
// preserved: the active attacker party drives the victim's PRG via the trigger
// (= protocol message boundary), supplies the public counter block (prg_in), and sees
// the masked wire (wire_M1). The victim's AES key is never read by the attacker; it is
// recovered from timing. true_key is exposed for VALIDATION scoring only.
#ifndef COMMON_TRI_AES_H
#define COMMON_TRI_AES_H
#include "common_bern.h"          // strided AES-128 machinery (bern_build_layout, bern_enc, ...)

#define SHM_TRI_AES "/beaver_tri_aes_shm"

typedef struct {
    volatile uint8_t p2_ready;     // victim initialized
    volatile uint8_t exit_flag;    // attacker asks victim to quit
    volatile uint8_t trigger_prg;  // attacker sets 1 (protocol message); victim clears when PRG done
    volatile uint8_t keysel;       // 0 = known reference key, 1 = secret key
    uint8_t prg_in[16];            // attacker-supplied PRG input block (public counter)
    volatile uint32_t wire_M1;     // victim's masked wire output (observable), = PRG(counter) word
    uint8_t true_key[16];          // victim's secret AES key -- VALIDATION ONLY
    uint8_t _pad[64];
} TriAesShared;

#endif
