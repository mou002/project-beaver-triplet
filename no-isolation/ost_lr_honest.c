// Victim: real AES-128 encryption whose LAST round reads the SHARED Te4 table.
// Rounds 0..9 use a plain reference AES (correctness only). The final round is
// done with explicit Te4 lookups into shared memory so the attacker can Flush+
// Reload them:  for each ciphertext position, access Te4[idx] where idx is the
// post-ShiftRows S-box input, and emit ct[pos] = SBOX[idx] ^ K10[pos].
//
// No isolation needed: Te4 is touched only here, in round 10.
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "ost_lr_common.h"
#include "aes_leak.h"          // AES_SBOX, aes128_key_expansion, aes_* round ops, trace ref

static volatile uint32_t g_sink = 0;

static void build_Te4(OstLrShared* s){
    for (int x=0;x<256;x++) s->Te4[x] = (uint32_t)AES_SBOX[x];  // contiguous: line=x>>4, 16/line
}

// state9 = output of round 9 (input to round 10), per aes128_encrypt_trace convention.
// Compute rounds 0..9 the plain way, then do the last round via the shared Te4.
static void encrypt_leak(OstLrShared* s, const uint8_t rk[11][16]){
    uint8_t st[16];
    memcpy(st, (const void*)s->pt, 16);
    aes_add_round_key(st, rk[0]);
    for (int r=1;r<10;r++){ aes_sub_bytes(st); aes_shift_rows(st); aes_mix_columns(st); aes_add_round_key(st, rk[r]); }
    // st == states[9]. Last round: ShiftRows selects the byte, Te4 does SubBytes.
    aes_shift_rows(st);                       // now st[pos] is the Te4 index for position pos
    uint8_t ct[16];
    for (int pos=0; pos<16; pos++){
        uint8_t idx = st[pos];
        uint32_t v = s->Te4[idx];             // REAL shared-memory last-round access
        g_sink ^= v;
        ct[pos] = (uint8_t)v ^ rk[10][pos];
    }
    memcpy((void*)s->ct, ct, 16);
}

int main(void){
    shm_unlink(SHM_OST_LR_NAME);
    int fd = shm_open(SHM_OST_LR_NAME, O_CREAT|O_RDWR, 0666);
    if (fd==-1){ perror("shm_open"); return 1; }
    if (ftruncate(fd, sizeof(OstLrShared))==-1){ perror("ftruncate"); return 1; }
    OstLrShared* s = mmap(NULL,sizeof(OstLrShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if (s==MAP_FAILED){ perror("mmap"); return 1; }

    s->trig=0; s->done_ack=0; s->exit_flag=0; s->selftest_ok=0;
    build_Te4(s);

    // Self-test: our T-table last round must reproduce the reference ciphertext.
    {
        uint8_t k[16],pt[16]; for(int i=0;i<16;i++){k[i]=i*17+1;pt[i]=i*3+7;}
        uint8_t rk[11][16]; aes128_key_expansion(k, rk);
        uint8_t states[11][16], ref[16];
        aes128_encrypt_trace(pt, rk, states, ref);
        memcpy((void*)s->key,k,16); memcpy((void*)s->pt,pt,16);
        encrypt_leak(s, rk);
        s->selftest_ok = (memcmp((const void*)s->ct, ref, 16)==0) ? 1 : 0;
    }
    s->ready=1;

    while (!s->exit_flag){
        while (!s->trig && !s->exit_flag) _mm_pause();
        if (s->exit_flag) break;
        uint8_t k[16]; memcpy(k,(const void*)s->key,16);
        uint8_t rk[11][16]; aes128_key_expansion(k, rk);
        encrypt_leak(s, rk);
        s->trig=0; s->done_ack=1;
    }
    munmap(s,sizeof(OstLrShared)); close(fd);
    return 0;
}
