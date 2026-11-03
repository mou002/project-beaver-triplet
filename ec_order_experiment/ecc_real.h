#ifndef ECC_REAL_H
#define ECC_REAL_H
// ------------------------------------------------------------------
// Real NIST P-256 (secp256r1) — production curve, self-contained,
// gcc-only (uses __int128). Field arithmetic in Montgomery form (CIOS).
// Non-constant-time windowed fixed-base scalar multiplication: the secret
// scalar's 4-bit windows directly index public precomputed tables, so each
// window is a cache-leak target exactly like the toy curve, but over a full
// 256-bit scalar and a production field.
// ------------------------------------------------------------------
#include <stdint.h>
#include <string.h>

#define P256_N0INV 0x0000000000000001ULL
static const uint64_t P256_P[4]    = {0xffffffffffffffffULL,0x00000000ffffffffULL,0x0000000000000000ULL,0xffffffff00000001ULL};
static const uint64_t P256_R2[4]   = {0x0000000000000003ULL,0xfffffffbffffffffULL,0xfffffffffffffffeULL,0x00000004fffffffdULL};
static const uint64_t P256_ONE_M[4]= {0x0000000000000001ULL,0xffffffff00000000ULL,0xffffffffffffffffULL,0x00000000fffffffeULL};
static const uint64_t P256_B[4]    = {0x3bce3c3e27d2604bULL,0x651d06b0cc53b0f6ULL,0xb3ebbd55769886bcULL,0x5ac635d8aa3a93e7ULL};
static const uint64_t P256_GX[4]   = {0xf4a13945d898c296ULL,0x77037d812deb33a0ULL,0xf8bce6e563a440f2ULL,0x6b17d1f2e12c4247ULL};
static const uint64_t P256_GY[4]   = {0xcbb6406837bf51f5ULL,0x2bce33576b315eceULL,0x8ee7eb4a7c0f9e16ULL,0x4fe342e2fe1a7f9bULL};

typedef uint64_t fe[4];

static int fe_geq_p(const uint64_t a[4]) {           // a >= p ?
    for (int i = 3; i >= 0; i--) { if (a[i] > P256_P[i]) return 1; if (a[i] < P256_P[i]) return 0; }
    return 1;
}
static void fe_sub_p(uint64_t a[4]) {                 // a -= p (assumes a>=p)
    unsigned __int128 br = 0;
    for (int i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128)a[i] - P256_P[i] - br;
        a[i] = (uint64_t)s; br = (s >> 64) & 1; }
}
static void fe_add(fe r, const fe a, const fe b) {
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; i++) { c += (unsigned __int128)a[i] + b[i]; r[i] = (uint64_t)c; c >>= 64; }
    if (c || fe_geq_p(r)) fe_sub_p(r);
}
static void fe_sub(fe r, const fe a, const fe b) {
    unsigned __int128 br = 0; uint64_t t[4];
    for (int i = 0; i < 4; i++) { unsigned __int128 s = (unsigned __int128)a[i] - b[i] - br;
        t[i] = (uint64_t)s; br = (s >> 64) & 1; }
    if (br) {                                         // negative -> add p back
        unsigned __int128 c = 0;
        for (int i = 0; i < 4; i++) { c += (unsigned __int128)t[i] + P256_P[i]; t[i] = (uint64_t)c; c >>= 64; }
    }
    memcpy(r, t, 32);
}

// CIOS Montgomery multiplication: r = a*b*R^-1 mod p.
static void mont_mul(fe r, const fe a, const fe b) {
    uint64_t t[6] = {0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        unsigned __int128 C = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 s = (unsigned __int128)a[j]*b[i] + t[j] + C;
            t[j] = (uint64_t)s; C = s >> 64;
        }
        unsigned __int128 s = (unsigned __int128)t[4] + C; t[4] = (uint64_t)s; t[5] = (uint64_t)(s >> 64);
        uint64_t m = t[0] * P256_N0INV;
        C = 0;
        { unsigned __int128 q = (unsigned __int128)m*P256_P[0] + t[0]; C = q >> 64; }
        for (int j = 1; j < 4; j++) {
            unsigned __int128 q = (unsigned __int128)m*P256_P[j] + t[j] + C;
            t[j-1] = (uint64_t)q; C = q >> 64;
        }
        unsigned __int128 q = (unsigned __int128)t[4] + C; t[3] = (uint64_t)q;
        t[4] = t[5] + (uint64_t)(q >> 64);
    }
    r[0]=t[0]; r[1]=t[1]; r[2]=t[2]; r[3]=t[3];
    if (t[4] || fe_geq_p(r)) fe_sub_p(r);
}

static void to_mont(fe r, const fe a)   { mont_mul(r, a, P256_R2); }
static void from_mont(fe r, const fe a) { fe one = {1,0,0,0}; mont_mul(r, a, one); }

// inverse in Montgomery form: a^(p-2). Exponent = p-2.
static void fe_inv(fe r, const fe a) {
    uint64_t e[4]; memcpy(e, P256_P, 32);
    // e = p - 2
    unsigned __int128 br = 2;
    for (int i = 0; i < 4 && br; i++) { unsigned __int128 s = (unsigned __int128)e[i] - (uint64_t)br; e[i]=(uint64_t)s; br = (s>>64)&1; }
    fe acc; memcpy(acc, P256_ONE_M, 32);
    fe base; memcpy(base, a, 32);
    for (int i = 0; i < 256; i++) {
        if ((e[i/64] >> (i%64)) & 1) mont_mul(acc, acc, base);
        mont_mul(base, base, base);
    }
    memcpy(r, acc, 32);
}

// Affine point; coords in Montgomery form. inf=1 is point at infinity.
typedef struct { fe x, y; int inf; } ECPt;

static void ec_set_inf(ECPt* P){ P->inf = 1; memset(P->x,0,32); memset(P->y,0,32); }

static void ec_double(ECPt* R, const ECPt* P) {
    if (P->inf) { *R = *P; return; }
    // lambda = (3x^2 + a)/(2y), a = -3
    fe x2, num, den, lam, t, x3, y3, three={3,0,0,0}, thm;
    to_mont(thm, three);
    mont_mul(x2, P->x, P->x);
    mont_mul(num, x2, thm);                 // 3x^2
    fe amont; uint64_t a_norm[4]; // a = p-3 in normal form
    memcpy(a_norm, P256_P, 32);
    { unsigned __int128 br=3; for(int i=0;i<4&&br;i++){ unsigned __int128 s=(unsigned __int128)a_norm[i]-(uint64_t)br; a_norm[i]=(uint64_t)s; br=(s>>64)&1; } }
    to_mont(amont, a_norm);
    fe_add(num, num, amont);                // 3x^2 + a
    fe_add(den, P->y, P->y);                // 2y
    fe_inv(den, den);
    mont_mul(lam, num, den);
    mont_mul(x3, lam, lam);                 // lam^2
    fe_sub(x3, x3, P->x); fe_sub(x3, x3, P->x);   // - 2x
    fe_sub(t, P->x, x3);
    mont_mul(y3, lam, t);
    fe_sub(y3, y3, P->y);
    memcpy(R->x, x3, 32); memcpy(R->y, y3, 32); R->inf = 0;
    (void)amont;
}

static void ec_add(ECPt* R, const ECPt* P, const ECPt* Q) {
    if (P->inf) { *R = *Q; return; }
    if (Q->inf) { *R = *P; return; }
    if (memcmp(P->x, Q->x, 32) == 0) {
        fe sy; fe_add(sy, P->y, Q->y);
        if (memcmp(sy, (uint64_t[4]){0,0,0,0}, 32) == 0) { ec_set_inf(R); return; }
        ec_double(R, P); return;
    }
    fe num, den, lam, x3, y3, t;
    fe_sub(num, Q->y, P->y);
    fe_sub(den, Q->x, P->x);
    fe_inv(den, den);
    mont_mul(lam, num, den);
    mont_mul(x3, lam, lam);
    fe_sub(x3, x3, P->x); fe_sub(x3, x3, Q->x);
    fe_sub(t, P->x, x3);
    mont_mul(y3, lam, t);
    fe_sub(y3, y3, P->y);
    memcpy(R->x, x3, 32); memcpy(R->y, y3, 32); R->inf = 0;
}

static void ec_generator(ECPt* G) { to_mont(G->x, P256_GX); to_mont(G->y, P256_GY); G->inf = 0; }

// simple double-and-add (for validation); scalar is 4 x uint64, little-endian.
static void ec_scalar_mult(ECPt* R, const uint64_t k[4], const ECPt* P) {
    ECPt acc; ec_set_inf(&acc);
    for (int i = 255; i >= 0; i--) {
        ec_double(&acc, &acc);
        if ((k[i/64] >> (i%64)) & 1) ec_add(&acc, &acc, P);
    }
    *R = acc;
}

// export affine coords to normal-form big-endian hex-ready limbs (little-endian u64)
static void ec_affine_normal(const ECPt* P, uint64_t x[4], uint64_t y[4]) {
    from_mont(x, P->x); from_mont(y, P->y);
}

#endif
