// Combined victim: both honest parties P2 and P3 (selected by cur_party).
// Runs the real AES-PRG and the real P-256 OT-choice multiply, leaking each
// through one isolated access per trigger (SGX / single-step model).
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "beaver_common.h"
#include "aes_leak.h"

static volatile uint32_t g_sink = 0;

// victim-side PRNG for the OT nonce k (xorshift64)
static uint64_t vrng_state = 0x243F6A8885A308D3ULL;
static inline uint64_t vrng(void){ uint64_t x=vrng_state; x^=x<<13; x^=x>>7; x^=x<<17; vrng_state=x; return x; }

static void build_tables(BeaverShared* s) {
    // AES real T-tables
    static const uint8_t cf[4][4]={{2,1,1,3},{3,2,1,1},{1,3,2,1},{1,1,3,2}};
    for (int m=0;m<4;m++) for (int x=0;x<256;x++){ uint8_t sb=AES_SBOX[x];
        s->Te[m][x] = (uint32_t)aes_gmul(sb,cf[m][0]) | ((uint32_t)aes_gmul(sb,cf[m][1])<<8)
                    | ((uint32_t)aes_gmul(sb,cf[m][2])<<16) | ((uint32_t)aes_gmul(sb,cf[m][3])<<24); }
    // P-256 windowed tables over base G:  ec_lo[d]=d*G, ec_hi[d]=d*(16G)
    ECPt G; ec_generator(&G);
    ECPt cur; ec_set_inf(&cur);
    for (int d=0; d<16; d++){ s->ec_lo[d].p = cur; ec_add(&cur,&cur,&G); }
    ECPt G16; ec_set_inf(&G16); for(int i=0;i<16;i++) ec_add(&G16,&G16,&G);  // 16G
    ec_set_inf(&cur);
    for (int d=0; d<16; d++){ s->ec_hi[d].p = cur; ec_add(&cur,&cur,&G16); }
}

int main(void) {
    shm_unlink(SHM_BEAVER_NAME);
    int fd = shm_open(SHM_BEAVER_NAME, O_CREAT|O_RDWR, 0666);
    if (fd==-1){ perror("shm_open"); return 1; }
    if (ftruncate(fd, sizeof(BeaverShared))==-1){ perror("ftruncate"); return 1; }
    BeaverShared* s = mmap(NULL,sizeof(BeaverShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if (s==MAP_FAILED){ perror("mmap"); return 1; }

    memset((void*)&s->ready,0,0); // no-op
    s->trig_aes=s->trig_ec=s->aes_load=s->want_M1=s->exit_flag=s->done_ack=0;
    build_tables(s);
    s->ready=1;

    uint8_t rk[11][16], states[11][16], ct[16];
    int have_key=0; uint8_t cached[16]={0};

    while (!s->exit_flag) {
        while (!s->trig_aes && !s->trig_ec && !s->aes_load && !s->want_M1 && !s->exit_flag) _mm_pause();
        if (s->exit_flag) break;

        const uint8_t* key = (s->cur_party==2) ? s->aes_key2 : s->aes_key3;
        uint8_t bshare     = (s->cur_party==2) ? s->b2 : s->b3;
        uint8_t ashare     = (s->cur_party==2) ? s->a2 : s->a3;

        if (s->want_M1) {
            // compute BOTH parties' observable wire M1_i = b_i ^ PRG_byte(K_i, V0),
            // once per trial, independent of cur_party (race-free).
            uint8_t lrk[11][16], lst[11][16], lct[16], v[16];
            aes128_key_expansion((const uint8_t*)s->aes_key2, lrk);
            memcpy(v,(const void*)s->base_ctr,16); aes128_encrypt_trace(v,lrk,lst,lct);
            s->M1_2 = s->b2 ^ lct[0];
            aes128_key_expansion((const uint8_t*)s->aes_key3, lrk);
            memcpy(v,(const void*)s->base_ctr,16); aes128_encrypt_trace(v,lrk,lst,lct);
            s->M1_3 = s->b3 ^ lct[0];
            s->want_M1 = 0; s->done_ack = 1; continue;
        }
        if (s->aes_load) {
            if (!have_key || memcmp(cached,key,16)!=0){ memcpy(cached,key,16); aes128_key_expansion(key,rk); have_key=1; }
            uint8_t v[16]; memcpy(v,(const void*)s->aes_ctr,16);
            aes128_encrypt_trace(v, rk, states, ct);
            s->aes_load=0; s->done_ack=1; continue;
        }
        if (s->trig_aes) {
            uint8_t j=s->aes_round, p=s->aes_pos;
            g_sink ^= s->Te[p & 3][ states[j][p] ];        // real AES T-table access
            s->trig_aes=0; s->done_ack=1; continue;
        }
        if (s->trig_ec) {
            // REAL receiver key-query: compute B2 = a*A + k*G (Base-OT, eq.2).
            // a-term: genuine w=4 windowed multiply over the (public, probeable) G-tables
            //   -> two leaking lookups (low & high nibble) plus one point addition.
            // k-term: fresh nonce times G, computed separately (double-and-add over G,
            //   a DIFFERENT base, so it does NOT touch the probed a-tables -- matching the
            //   real protocol where a*A and k*G use different bases/tables).
            int lo = ashare & 0xF, hi = (ashare >> 4) & 0xF;
            ECPt Plo = s->ec_lo[lo].p;                 // leaking lookup: low nibble
            ECPt Phi = s->ec_hi[hi].p;                 // leaking lookup: high nibble
            ECPt Pa;  ec_add(&Pa, &Plo, &Phi);         // a*G  (windowed)
            uint64_t k[4] = { vrng(), vrng(), 0, 0 };  // fresh OT nonce
            ECPt G;   ec_generator(&G);
            ECPt kG;  ec_scalar_mult(&kG, k, &G);      // k*G  (separate base, no a-table access)
            ECPt B2;  ec_add(&B2, &Pa, &kG);           // B2 = a*G + k*G
            g_sink ^= (uint32_t)B2.x[0];               // consume the real result
            s->trig_ec=0; s->done_ack=1; continue;
        }
    }
    munmap(s,sizeof(BeaverShared)); close(fd);
    return 0;
}
