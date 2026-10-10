#ifndef AES_LEAK_H
#define AES_LEAK_H
// ------------------------------------------------------------------
// AES-128 with a per-round state trace, matching the exact convention
// of aes_core.py::encrypt_traced so the C-collected leak lines up
// byte-for-byte with the Black Swans cryptanalysis in attack.py:
//
//   states[0]      = plaintext XOR K0
//   states[j]      = SubBytes->ShiftRows->MixColumns->AddRoundKey(Kj)   (j=1..9)
//   states[10]     = final round (no MixColumns)              (unused by attack)
//
// State is column-major: byte at row r, col c is state[4*c + r].
// The differential cryptanalysis consumes the top nibble (byte & 0xF0)
// of states[0..4]. This core only PRODUCES the true state trace; the
// leak (top nibbles) is measured separately via Flush+Reload on a
// dedicated 16-line probe table (see common.h / honest.c).
// ------------------------------------------------------------------
#include <stdint.h>
#include <string.h>

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t AES_RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static inline uint8_t aes_xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}
static inline uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// NR+1 = 11 round keys, each 16 bytes column-major (matches key_expansion in aes_core.py).
static inline void aes128_key_expansion(const uint8_t key[16], uint8_t rk[11][16]) {
    uint8_t words[44][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) words[i][j] = key[4*i + j];
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        for (int j = 0; j < 4; j++) temp[j] = words[i-1][j];
        if (i % 4 == 0) {
            uint8_t t = temp[0];                 // RotWord
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            for (int j = 0; j < 4; j++) temp[j] = AES_SBOX[temp[j]];  // SubWord
            temp[0] ^= AES_RCON[i/4 - 1];
        }
        for (int j = 0; j < 4; j++) words[i][j] = words[i-4][j] ^ temp[j];
    }
    for (int r = 0; r < 11; r++)
        for (int c = 0; c < 4; c++)
            for (int j = 0; j < 4; j++) rk[r][4*c + j] = words[r*4 + c][j];
}

static inline void aes_sub_bytes(uint8_t s[16])  { for (int i=0;i<16;i++) s[i]=AES_SBOX[s[i]]; }
static inline void aes_shift_rows(uint8_t s[16]) {
    uint8_t o[16];
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) o[4*c+r] = s[4*((c+r)%4)+r];
    memcpy(s,o,16);
}
static inline void aes_mix_columns(uint8_t s[16]) {
    uint8_t o[16];
    for (int c=0;c<4;c++){
        uint8_t *col = &s[4*c];
        o[4*c+0] = aes_gmul(col[0],2)^aes_gmul(col[1],3)^col[2]^col[3];
        o[4*c+1] = col[0]^aes_gmul(col[1],2)^aes_gmul(col[2],3)^col[3];
        o[4*c+2] = col[0]^col[1]^aes_gmul(col[2],2)^aes_gmul(col[3],3);
        o[4*c+3] = aes_gmul(col[0],3)^col[1]^col[2]^aes_gmul(col[3],2);
    }
    memcpy(s,o,16);
}
static inline void aes_add_round_key(uint8_t s[16], const uint8_t rk[16]) {
    for (int i=0;i<16;i++) s[i]^=rk[i];
}

// Produce the per-round state trace states[11][16] for one block, matching
// aes_core.py::encrypt_traced exactly. Returns ciphertext in ct[16].
static inline void aes128_encrypt_trace(const uint8_t pt[16], const uint8_t rk[11][16],
                                        uint8_t states[11][16], uint8_t ct[16]) {
    uint8_t s[16];
    memcpy(s, pt, 16);
    aes_add_round_key(s, rk[0]);
    memcpy(states[0], s, 16);                 // S_0 = pt ^ K0
    for (int r = 1; r < 10; r++) {
        aes_sub_bytes(s);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, rk[r]);
        memcpy(states[r], s, 16);             // S_r = input to round r+1
    }
    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_add_round_key(s, rk[10]);
    memcpy(states[10], s, 16);
    memcpy(ct, s, 16);
}

#endif
