#ifndef BLACKSWANS_H
#define BLACKSWANS_H
// ------------------------------------------------------------------
// C port of the Black Swans differential cryptanalysis (attack.py +
// ttable.py), so recovery needs only gcc -- no Python on the target.
// Verified to reproduce the Python recovery (100/100 on the oracle).
//
// Consumes >= 3 leaked traces of consecutive AES-CTR counter encryptions,
// each trace L[5][16] holding the top nibble (byte & 0xF0) of state bytes
// in rounds 0..4, column-major. Recovers the AES key and the trace-0
// counter of the middle trace's run.
// ------------------------------------------------------------------
#include <stdint.h>
#include <string.h>
#include "aes_leak.h"   // AES_SBOX, AES_RCON, aes_gmul, key expansion, encrypt trace

// ---- derived tables (built once via bs_init) ----
static uint8_t BS_T[4][256][4];     // T0..T3 : one state byte -> 4-byte column contrib
static uint8_t BS_INV_SBOX[256];
static int BS_COLIN[4][4];          // COLUMN_INPUTS[c][pos]
static const uint8_t BS_CTR_DIFFS[8] = {0x01,0x03,0x07,0x0F,0x1F,0x3F,0x7F,0xFF};
static int bs_ready = 0;

static void bs_init(void) {
    if (bs_ready) return;
    static const uint8_t coeffs[4][4] = {{2,1,1,3},{3,2,1,1},{1,3,2,1},{1,1,3,2}};
    for (int pos = 0; pos < 4; pos++)
        for (int x = 0; x < 256; x++) {
            uint8_t s = AES_SBOX[x];
            for (int i = 0; i < 4; i++) BS_T[pos][x][i] = aes_gmul(s, coeffs[pos][i]);
        }
    for (int i = 0; i < 256; i++) BS_INV_SBOX[AES_SBOX[i]] = (uint8_t)i;
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) BS_COLIN[c][r] = 4 * ((c + r) % 4) + r;
    bs_ready = 1;
}

static inline uint8_t bs_u(uint8_t x) { return x & 0xF0; }

// P(state): unkeyed SubBytes->ShiftRows->MixColumns via T-tables.
static void bs_P(const uint8_t s[16], uint8_t out[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t col[4] = {0,0,0,0};
        for (int pos = 0; pos < 4; pos++) {
            const uint8_t *contrib = BS_T[pos][s[BS_COLIN[c][pos]]];
            for (int i = 0; i < 4; i++) col[i] ^= contrib[i];
        }
        for (int r = 0; r < 4; r++) out[4*c + r] = col[r];
    }
}

static void bs_inv_P(const uint8_t s[16], uint8_t out[16]) {
    uint8_t tmp[16];
    for (int c = 0; c < 4; c++) {
        const uint8_t *col = &s[4*c];
        tmp[4*c+0] = aes_gmul(col[0],14)^aes_gmul(col[1],11)^aes_gmul(col[2],13)^aes_gmul(col[3],9);
        tmp[4*c+1] = aes_gmul(col[0],9)^aes_gmul(col[1],14)^aes_gmul(col[2],11)^aes_gmul(col[3],13);
        tmp[4*c+2] = aes_gmul(col[0],13)^aes_gmul(col[1],9)^aes_gmul(col[2],14)^aes_gmul(col[3],11);
        tmp[4*c+3] = aes_gmul(col[0],11)^aes_gmul(col[1],13)^aes_gmul(col[2],9)^aes_gmul(col[3],14);
    }
    uint8_t shifted[16];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++) shifted[4*c + r] = tmp[4*((c - r + 4)%4) + r];
    for (int i = 0; i < 16; i++) out[i] = BS_INV_SBOX[shifted[i]];
}

// any round key (round_index 0..10) -> master key (round key 0).
static void bs_invert_key_schedule(const uint8_t rk[16], int round_index, uint8_t master[16]) {
    uint8_t w[4][4];
    for (int c = 0; c < 4; c++) for (int j = 0; j < 4; j++) w[c][j] = rk[4*c + j];
    for (int r = round_index; r > 0; r--) {
        uint8_t prev[4][4];
        for (int j = 0; j < 4; j++) {
            prev[3][j] = w[3][j] ^ w[2][j];
            prev[2][j] = w[2][j] ^ w[1][j];
            prev[1][j] = w[1][j] ^ w[0][j];
        }
        uint8_t t[4];
        t[0]=prev[3][1]; t[1]=prev[3][2]; t[2]=prev[3][3]; t[3]=prev[3][0]; // RotWord
        for (int j = 0; j < 4; j++) t[j] = AES_SBOX[t[j]];                  // SubWord
        t[0] ^= AES_RCON[r-1];
        for (int j = 0; j < 4; j++) prev[0][j] = w[0][j] ^ t[j];
        memcpy(w, prev, 16);
    }
    for (int c = 0; c < 4; c++) for (int j = 0; j < 4; j++) master[4*c + j] = w[c][j];
}

// ---- candidate container types ----
typedef struct { uint8_t g; uint8_t D1L[16]; uint8_t D1R[16]; } BsA3;
typedef struct { uint8_t s1[4]; uint8_t D2L[16]; uint8_t D2R[16]; } BsA4;
typedef struct { uint8_t state[16]; uint8_t DL[16]; uint8_t DR[16]; } BsSt;

#define BS_A3_MAX   8192
#define BS_A4_MAX   8192
#define BS_ST_MAX   8192
#define BS_COL_MAX  4096
#define BS_KEY_MAX  8192

// Algorithm 3: recover round-0 byte 15 of the middle trace + round-1 diffs.
static int bs_alg3(uint8_t L0_15, const uint8_t LD_L1[16], const uint8_t LD_R1[16],
                   BsA3 *out) {
    int n = 0;
    for (int di = 0; di < 8; di++) {
        uint8_t diffL = BS_CTR_DIFFS[di];
        for (int dj = 0; dj < 8; dj++) {
            uint8_t diffR = BS_CTR_DIFFS[dj];
            for (int nib = 0; nib < 16; nib++) {
                uint8_t g = L0_15 | nib;
                uint8_t dL[4], dR[4]; int ok = 1;
                for (int i = 0; i < 4; i++) {
                    dL[i] = BS_T[3][g][i] ^ BS_T[3][g ^ diffL][i];
                    if (dL[i] == 0 || bs_u(dL[i]) != LD_L1[i]) { ok = 0; break; }
                }
                if (!ok) continue;
                for (int i = 0; i < 4; i++) {
                    dR[i] = BS_T[3][g][i] ^ BS_T[3][g ^ diffR][i];
                    if (dR[i] == 0 || bs_u(dR[i]) != LD_R1[i]) { ok = 0; break; }
                }
                if (!ok) continue;
                if (n < BS_A3_MAX) {
                    memset(&out[n], 0, sizeof(BsA3));
                    out[n].g = g;
                    for (int i = 0; i < 4; i++) { out[n].D1L[i] = dL[i]; out[n].D1R[i] = dR[i]; }
                    n++;
                }
            }
        }
    }
    return n;
}

// one round-1 byte, filtered by both differentials
typedef struct { uint8_t g; uint8_t dL[4]; uint8_t dR[4]; } BsByte;
static int bs_byte_cands(int k, uint8_t L1_k, uint8_t DLk, uint8_t DRk,
                         const uint8_t targL[4], const uint8_t targR[4], BsByte *out) {
    int n = 0;
    for (int nib = 0; nib < 16; nib++) {
        uint8_t g = L1_k | nib; uint8_t dL[4], dR[4]; int ok = 1;
        for (int i = 0; i < 4; i++) {
            dL[i] = BS_T[k][g][i] ^ BS_T[k][g ^ DLk][i];
            if (dL[i] == 0 || bs_u(dL[i]) != targL[i]) { ok = 0; break; }
        }
        if (!ok) continue;
        for (int i = 0; i < 4; i++) {
            dR[i] = BS_T[k][g][i] ^ BS_T[k][g ^ DRk][i];
            if (dR[i] == 0 || bs_u(dR[i]) != targR[i]) { ok = 0; break; }
        }
        if (!ok) continue;
        out[n].g = g;
        for (int i = 0; i < 4; i++) { out[n].dL[i] = dL[i]; out[n].dR[i] = dR[i]; }
        n++;
    }
    return n;
}

// Algorithm 4: round-1 bytes 0..3 -> full round-2 differentials.
static int bs_alg4(const uint8_t La1[16], const uint8_t D1L[16], const uint8_t D1R[16],
                   const uint8_t LD_L2[16], const uint8_t LD_R2[16], BsA4 *out) {
    BsByte cand[4][16]; int cnt[4]; int col[4];
    for (int k = 0; k < 4; k++) {
        int c = ((-k) % 4 + 4) % 4; col[k] = c;
        uint8_t targL[4], targR[4];
        for (int r = 0; r < 4; r++) { targL[r] = LD_L2[4*c+r]; targR[r] = LD_R2[4*c+r]; }
        cnt[k] = bs_byte_cands(k, La1[k], D1L[k], D1R[k], targL, targR, cand[k]);
        if (cnt[k] == 0) return 0;
    }
    int n = 0;
    for (int i0 = 0; i0 < cnt[0]; i0++)
    for (int i1 = 0; i1 < cnt[1]; i1++)
    for (int i2 = 0; i2 < cnt[2]; i2++)
    for (int i3 = 0; i3 < cnt[3]; i3++) {
        if (n >= BS_A4_MAX) return n;
        int ii[4] = {i0,i1,i2,i3};
        memset(&out[n], 0, sizeof(BsA4));
        for (int k = 0; k < 4; k++) {
            BsByte *b = &cand[k][ii[k]]; int c = col[k];
            out[n].s1[k] = b->g;
            for (int r = 0; r < 4; r++) { out[n].D2L[4*c+r] = b->dL[r]; out[n].D2R[4*c+r] = b->dR[r]; }
        }
        n++;
    }
    return n;
}

// half-partial for a pair of positions
typedef struct { int idx0, idx1; uint8_t g0, g1; uint8_t contrib[4]; } BsHalf;
static void bs_half(const int idxs[4], int pa, int pb, const uint8_t Lr[16],
                    const uint8_t Delta[16], BsHalf out[256]) {
    int n = 0;
    for (int c0 = 0; c0 < 16; c0++)
    for (int c1 = 0; c1 < 16; c1++) {
        int idxA = idxs[pa], idxB = idxs[pb];
        uint8_t gA = Lr[idxA] | c0, gB = Lr[idxB] | c1;
        uint8_t contrib[4] = {0,0,0,0};
        const uint8_t *a0 = BS_T[pa][gA], *a1 = BS_T[pa][gA ^ Delta[idxA]];
        const uint8_t *b0 = BS_T[pb][gB], *b1 = BS_T[pb][gB ^ Delta[idxB]];
        for (int i = 0; i < 4; i++) contrib[i] = a0[i]^a1[i]^b0[i]^b1[i];
        out[n].idx0 = idxA; out[n].idx1 = idxB; out[n].g0 = gA; out[n].g1 = gB;
        for (int i = 0; i < 4; i++) out[n].contrib[i] = contrib[i];
        n++;
    }
}

typedef struct { uint8_t gbytes[16]; uint8_t dL[4]; uint8_t dR[4]; } BsCol;
static int bs_alg5_col(int c, const uint8_t Lr[16], const uint8_t DL[16], const uint8_t DR[16],
                       const uint8_t targL[4], const uint8_t targR[4], BsCol *out) {
    int idxs[4]; for (int r = 0; r < 4; r++) idxs[r] = BS_COLIN[c][r];
    static BsHalf A[256], B[256];
    bs_half(idxs, 0, 1, Lr, DL, A);
    bs_half(idxs, 2, 3, Lr, DL, B);
    int n = 0;
    for (int ia = 0; ia < 256; ia++) {
        uint8_t need[4];
        for (int i = 0; i < 4; i++) need[i] = targL[i] ^ bs_u(A[ia].contrib[i]);
        for (int ib = 0; ib < 256; ib++) {
            int match = 1;
            for (int i = 0; i < 4; i++) if (bs_u(B[ib].contrib[i]) != need[i]) { match = 0; break; }
            if (!match) continue;
            uint8_t gbytes[16]; memset(gbytes, 0, 16);
            gbytes[A[ia].idx0] = A[ia].g0; gbytes[A[ia].idx1] = A[ia].g1;
            gbytes[B[ib].idx0] = B[ib].g0; gbytes[B[ib].idx1] = B[ib].g1;
            uint8_t dL[4], dR[4] = {0,0,0,0};
            for (int i = 0; i < 4; i++) dL[i] = A[ia].contrib[i] ^ B[ib].contrib[i];
            for (int pos = 0; pos < 4; pos++) {
                int idx = idxs[pos]; uint8_t g = gbytes[idx];
                const uint8_t *ca = BS_T[pos][g], *cb = BS_T[pos][g ^ DR[idx]];
                for (int i = 0; i < 4; i++) dR[i] ^= ca[i]^cb[i];
            }
            int ok = 1;
            for (int i = 0; i < 4; i++) if (bs_u(dR[i]) != targR[i]) { ok = 0; break; }
            if (!ok) continue;
            if (n < BS_COL_MAX) {
                memcpy(out[n].gbytes, gbytes, 16);
                for (int i = 0; i < 4; i++) { out[n].dL[i] = dL[i]; out[n].dR[i] = dR[i]; }
                n++;
            }
        }
    }
    return n;
}

// Algorithm 5: full round-r state + full round-(r+1) differentials.
static int bs_alg5_state(const uint8_t Lr[16], const uint8_t DL[16], const uint8_t DR[16],
                         const uint8_t LDLn[16], const uint8_t LDRn[16], BsSt *out) {
    static BsCol cc[4][BS_COL_MAX]; int cn[4];
    for (int c = 0; c < 4; c++) {
        uint8_t targL[4], targR[4];
        for (int r = 0; r < 4; r++) { targL[r] = LDLn[4*c+r]; targR[r] = LDRn[4*c+r]; }
        cn[c] = bs_alg5_col(c, Lr, DL, DR, targL, targR, cc[c]);
        if (cn[c] == 0) return 0;
    }
    int n = 0;
    for (int i0 = 0; i0 < cn[0]; i0++)
    for (int i1 = 0; i1 < cn[1]; i1++)
    for (int i2 = 0; i2 < cn[2]; i2++)
    for (int i3 = 0; i3 < cn[3]; i3++) {
        if (n >= BS_ST_MAX) return n;
        int ii[4] = {i0,i1,i2,i3};
        memset(&out[n], 0, sizeof(BsSt));
        for (int c = 0; c < 4; c++) {
            BsCol *b = &cc[c][ii[c]];
            for (int r = 0; r < 4; r++) {
                int idx = BS_COLIN[c][r];
                out[n].state[idx] = b->gbytes[idx];
                out[n].DL[4*c+r] = b->dL[r];
                out[n].DR[4*c+r] = b->dR[r];
            }
        }
        n++;
    }
    return n;
}

typedef struct { uint8_t key[16]; uint8_t S2[16]; uint8_t S3[16]; } BsCand;

static void bs_leak_diff(const uint8_t A[5][16], const uint8_t B[5][16], uint8_t out[5][16]) {
    for (int j = 0; j < 5; j++) for (int k = 0; k < 16; k++) out[j][k] = A[j][k] ^ B[j][k];
}

// recover distinct {key,S2,S3} candidates from the middle trace of a triple.
static int bs_recover_triple(const uint8_t L0[5][16], const uint8_t L1[5][16],
                             const uint8_t L2[5][16], BsCand *cands, int cap) {
    bs_init();
    uint8_t LDL[5][16], LDR[5][16];
    bs_leak_diff(L0, L1, LDL);
    bs_leak_diff(L1, L2, LDR);

    static BsA3 a3[BS_A3_MAX];
    int na3 = bs_alg3(L1[0][15], LDL[1], LDR[1], a3);

    static uint8_t seen[BS_KEY_MAX][16]; int nseen = 0;
    int nc = 0;
    static BsA4 a4[BS_A4_MAX];
    static BsSt s2s[BS_ST_MAX], s3s[BS_ST_MAX];

    for (int i3 = 0; i3 < na3; i3++) {
        int n4 = bs_alg4(L1[1], a3[i3].D1L, a3[i3].D1R, LDL[2], LDR[2], a4);
        for (int i4 = 0; i4 < n4; i4++) {
            int n2 = bs_alg5_state(L1[2], a4[i4].D2L, a4[i4].D2R, LDL[3], LDR[3], s2s);
            for (int j2 = 0; j2 < n2; j2++) {
                int n3 = bs_alg5_state(L1[3], s2s[j2].DL, s2s[j2].DR, LDL[4], LDR[4], s3s);
                for (int j3 = 0; j3 < n3; j3++) {
                    uint8_t PS2[16], K3[16], master[16];
                    bs_P(s2s[j2].state, PS2);
                    for (int i = 0; i < 16; i++) K3[i] = PS2[i] ^ s3s[j3].state[i];
                    bs_invert_key_schedule(K3, 3, master);
                    int dup = 0;
                    for (int s = 0; s < nseen; s++) if (memcmp(seen[s], master, 16) == 0) { dup = 1; break; }
                    if (dup) continue;
                    if (nseen < BS_KEY_MAX) memcpy(seen[nseen++], master, 16);
                    if (nc < cap) {
                        memcpy(cands[nc].key, master, 16);
                        memcpy(cands[nc].S2, s2s[j2].state, 16);
                        memcpy(cands[nc].S3, s3s[j3].state, 16);
                        nc++;
                    }
                }
            }
        }
    }
    return nc;
}

// 16-byte big-endian add / subtract of a small non-negative integer (mod 2^128).
static void bs_be_add(uint8_t v[16], long add) {
    long c = add;
    for (int b = 15; b >= 0; b--) {
        long t = (long)v[b] + (c & 0xFF);
        v[b] = (uint8_t)(t & 0xFF);
        c = (c >> 8) + (t >> 8);
        if (c == 0) break;
    }
}
static void bs_be_sub(uint8_t v[16], long sub) {
    long borrow = sub;
    for (int b = 15; b >= 0 && borrow; b--) {
        long cur = v[b] - (borrow & 0xFF);
        long nextborrow = borrow >> 8;
        if (cur < 0) { cur += 256; nextborrow += 1; }
        v[b] = (uint8_t)cur; borrow = nextborrow;
    }
}

// verify a candidate: re-encrypt the recovered counter run and compare top
// nibbles of rounds 0..4 against every trace (<= tolerance mismatches).
static int bs_verify(const BsCand *c, const uint8_t leaks[][5][16], int ntraces,
                     int mid_index, int tolerance, uint8_t pt_mid_out[16]) {
    uint8_t rk[11][16];
    aes128_key_expansion(c->key, rk);
    // pt_mid = inv two rounds from S2
    uint8_t x[16], S1[16], S0[16], pt_mid[16];
    for (int i = 0; i < 16; i++) x[i] = c->S2[i] ^ rk[2][i];
    bs_inv_P(x, S1);
    for (int i = 0; i < 16; i++) x[i] = S1[i] ^ rk[1][i];
    bs_inv_P(x, S0);
    for (int i = 0; i < 16; i++) pt_mid[i] = S0[i] ^ rk[0][i];

    uint8_t base[16]; memcpy(base, pt_mid, 16);
    bs_be_sub(base, mid_index);              // counter of trace 0

    int mism = 0;
    for (int t = 0; t < ntraces; t++) {
        uint8_t ctr[16]; memcpy(ctr, base, 16); bs_be_add(ctr, t);
        uint8_t states[11][16], ct[16];
        aes128_encrypt_trace(ctr, rk, states, ct);
        for (int j = 0; j < 5; j++)
            for (int k = 0; k < 16; k++)
                if (bs_u(states[j][k]) != leaks[t][j][k]) {
                    if (++mism > tolerance) return 0;
                }
    }
    memcpy(pt_mid_out, pt_mid, 16);
    return 1;
}

// recover_state (strict, tolerance t): single central triple, verify against all.
static int bs_recover_state_tol(const uint8_t leaks[][5][16], int ntraces, int tol,
                                uint8_t key_out[16], uint8_t ctr0_out[16]) {
    if (ntraces < 3) return 0;
    bs_init();
    int mid = ntraces / 2;
    static BsCand cands[BS_KEY_MAX];
    int nc = bs_recover_triple(leaks[mid-1], leaks[mid], leaks[mid+1], cands, BS_KEY_MAX);
    for (int i = 0; i < nc; i++) {
        uint8_t pt_mid[16];
        if (bs_verify(&cands[i], leaks, ntraces, mid, tol, pt_mid)) {
            uint8_t base[16]; memcpy(base, pt_mid, 16); bs_be_sub(base, mid);
            memcpy(key_out, cands[i].key, 16);
            memcpy(ctr0_out, base, 16);
            return 1;
        }
    }
    return 0;
}

// noise-free convenience wrapper (tolerance 0).
static int bs_recover_state(const uint8_t leaks[][5][16], int ntraces,
                            uint8_t key_out[16], uint8_t ctr0_out[16]) {
    return bs_recover_state_tol(leaks, ntraces, 0, key_out, ctr0_out);
}

// Robust recovery over a NOISY channel: run strict recovery on every
// consecutive triple (each candidate verified against all traces with
// tolerance `tol`), and take the plurality vote over surviving keys. This is
// the C form of attack.py::recover_state_robust -- the concrete "more traces
// eliminate noisy measurements" mechanism. Returns 1 with the winning key +
// its trace-0 counter.
static int bs_recover_robust(const uint8_t leaks[][5][16], int ntraces, int tol,
                             uint8_t key_out[16], uint8_t ctr0_out[16]) {
    if (ntraces < 3) return 0;
    bs_init();
    static uint8_t vkey[BS_KEY_MAX][16];
    static uint8_t vctr[BS_KEY_MAX][16];
    static int vcount[BS_KEY_MAX];
    int nv = 0;
    static BsCand cands[BS_KEY_MAX];

    for (int mid = 1; mid < ntraces - 1; mid++) {
        int nc = bs_recover_triple(leaks[mid-1], leaks[mid], leaks[mid+1], cands, BS_KEY_MAX);
        for (int i = 0; i < nc; i++) {
            uint8_t pt_mid[16];
            if (bs_verify(&cands[i], leaks, ntraces, mid, tol, pt_mid)) {
                uint8_t base[16]; memcpy(base, pt_mid, 16); bs_be_sub(base, mid);
                int f = -1;
                for (int v = 0; v < nv; v++) if (memcmp(vkey[v], cands[i].key, 16) == 0) { f = v; break; }
                if (f < 0 && nv < BS_KEY_MAX) { f = nv++; memcpy(vkey[f], cands[i].key, 16); memcpy(vctr[f], base, 16); vcount[f] = 0; }
                if (f >= 0) vcount[f]++;
                break;   // one vote per clean triple
            }
        }
    }
    if (nv == 0) return 0;
    int best = 0;
    for (int v = 1; v < nv; v++) if (vcount[v] > vcount[best]) best = v;
    memcpy(key_out, vkey[best], 16);
    memcpy(ctr0_out, vctr[best], 16);
    return 1;
}

#endif
