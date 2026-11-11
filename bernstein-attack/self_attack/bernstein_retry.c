// bernstein_retry.c -- self-cal + z-repair + DEAD-WINDOW RETRY + robust cutoff.
//
// Adds to repair: round-2 now discards "dead" measurement windows (all lanes low-z =
// external contention) and keeps re-collecting until it gets clean (live) batches, up
// to a total-batch budget (the MAXREPS2 arg). Only live batches are voted. All
// discard/accept decisions use z and vote-stability only -- KEY-FREE, exactly what a
// real keyless attacker would do. Cutoff is set from a median of several min probes so
// one noisy instant can't poison a whole key's round-2.
//   BERN_ZLIVE=<float>  liveness threshold on best lane-z (default 12).
// NOTE: MAXREPS2 is now the TOTAL batch budget (live+dead); give it room on a noisy
// box (e.g. 30) so retry can outlast a contention burst.
// ---------------------------------------------------------------------------------
// bernstein_repair.c -- self-calibrating recovery + z-GUIDED REPAIR of round-1.
//
// Adds to selfcal: if round-1 misses a top nibble, its lane shows a low round-2 z.
// A repair pass grabs a good-window batch, finds low-z lanes, and tries each of their
// bytes' 2nd/3rd round-1 top-nibble choices, keeping whichever makes the lane's z jump
// to clean-lane level (a near-miss nibble is round-1's 2nd choice, so ~8 run_lane calls
// per bad lane suffice). Non-destructive: a lane is only changed if a candidate clearly
// beats the original z. Prints per-lane z throughout so the mechanism is visible.
// ---------------------------------------------------------------------------------
// bernstein_selfcal.c -- self-calibrating full passive AES key recovery.
//
// WHY: the prefetcher-neutralizing table stride is INSTANCE-SPECIFIC. A stride tuned
// on one AWS box (e.g. 4160) can leave specific byte positions unresolved on another
// box's cache/prefetcher geometry (we saw bytes 9 & 11 die at 4160 on a different
// instance). Since instances change between sessions, the stride must be calibrated
// per run, not hardcoded.
//
// HOW: at startup, sweep candidate strides on a KNOWN calibration key (this is
// attacker-side hardware tuning -- the good stride is a property of the machine, not
// of any secret, exactly like round-1's known zero-key reference profile). For each
// stride, run one round-1 pass at a modest calN and score how many of the 16 top
// nibbles it resolves. Pick the best stride, then run the full adaptive attack
// (round-1 nibble-sum + confidence-weighted adaptive round-2) at that stride over
// NKEYS random keys.
//
// Build: gcc -O2 -march=native bernstein_selfcal.c -o bernstein_selfcal -lm
// Run:   [BERN_CPU=1] [BERN_STRIDES=4160,4288,...] \
//          ./bernstein_selfcal <NKEYS> <N1> <REPS1> <N2> <MAXREPS2> <WARM> <evictKB> <calN>
// Defaults: NKEYS=3 N1=288M REPS1=2 N2=32M MAXREPS2=12 WARM=2 evict=32KB calN=48M
// Default candidate strides: 4160 4288 4352 4608 8256 12352  (override via BERN_STRIDES)
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sched.h>
#include <x86intrin.h>
static const uint8_t SBOX[256] = {
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
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const uint8_t RCON[11]={0,1,2,4,8,16,32,64,128,0x1b,0x36};
static uint32_t Te0[256],Te1[256],Te2[256],Te3[256],Te4[256];
static uint32_t* TEarr[5]={Te0,Te1,Te2,Te3,Te4};
static inline uint8_t xt(uint8_t a){return (uint8_t)((a<<1)^((a>>7)*0x1b));}
static inline uint8_t gfmul(uint8_t s,int c){return c==2?xt(s):(c==3?(uint8_t)(xt(s)^s):s);}
static void build_tables(void){for(int x=0;x<256;x++){uint8_t s=SBOX[x],s2=xt(s),s3=s2^s;
 Te0[x]=((uint32_t)s2<<24)|((uint32_t)s<<16)|((uint32_t)s<<8)|s3;Te1[x]=(Te0[x]>>8)|(Te0[x]<<24);
 Te2[x]=(Te0[x]>>16)|(Te0[x]<<16);Te3[x]=(Te0[x]>>24)|(Te0[x]<<8);
 Te4[x]=((uint32_t)s<<24)|((uint32_t)s<<16)|((uint32_t)s<<8)|s;}}
#define GETU32(p) (((uint32_t)(p)[0]<<24)|((uint32_t)(p)[1]<<16)|((uint32_t)(p)[2]<<8)|(p)[3])
static void key_expand(const uint8_t key[16],uint32_t rk[44]){for(int i=0;i<4;i++)rk[i]=GETU32(key+4*i);
 for(int i=4;i<44;i++){uint32_t t=rk[i-1];if(i%4==0){t=(t<<8)|(t>>24);t=((uint32_t)SBOX[t>>24]<<24)|((uint32_t)SBOX[(t>>16)&0xff]<<16)|((uint32_t)SBOX[(t>>8)&0xff]<<8)|SBOX[t&0xff];t^=((uint32_t)RCON[i/4]<<24);}rk[i]=rk[i-4]^t;}}

static long STRIDE=4160;
static uint8_t* SB[5]={0,0,0,0,0};
static void free_layout(void){ for(int t=0;t<5;t++){ if(SB[t]){ free(SB[t]); SB[t]=NULL; } } }
static void build_layout(void){ free_layout();
 for(int t=0;t<5;t++){ if(posix_memalign((void**)&SB[t],4096,(size_t)16*STRIDE+64)){exit(1);} memset(SB[t],0,(size_t)16*STRIDE+64);
  for(int x=0;x<256;x++) *(uint32_t*)(SB[t]+(size_t)(x>>4)*STRIDE+(size_t)(x&15)*4)=TEarr[t][x]; } }
static inline uint32_t Ls(int t,unsigned x){ return *(const uint32_t*)(SB[t]+(size_t)((x>>4)&0xf)*STRIDE+(size_t)(x&15)*4); }
static volatile uint32_t g_sink;
static inline void enc(const uint8_t in[16],const uint32_t rk[44]){
 uint32_t s0=GETU32(in)^rk[0],s1=GETU32(in+4)^rk[1],s2=GETU32(in+8)^rk[2],s3=GETU32(in+12)^rk[3],t0,t1,t2,t3;
 for(int r=1;r<10;r++){t0=Ls(0,s0>>24)^Ls(1,(s1>>16)&0xff)^Ls(2,(s2>>8)&0xff)^Ls(3,s3&0xff)^rk[4*r];
  t1=Ls(0,s1>>24)^Ls(1,(s2>>16)&0xff)^Ls(2,(s3>>8)&0xff)^Ls(3,s0&0xff)^rk[4*r+1];
  t2=Ls(0,s2>>24)^Ls(1,(s3>>16)&0xff)^Ls(2,(s0>>8)&0xff)^Ls(3,s1&0xff)^rk[4*r+2];
  t3=Ls(0,s3>>24)^Ls(1,(s0>>16)&0xff)^Ls(2,(s1>>8)&0xff)^Ls(3,s2&0xff)^rk[4*r+3];s0=t0;s1=t1;s2=t2;s3=t3;}
 t0=(Ls(4,s0>>24)&0xff000000)^(Ls(4,(s1>>16)&0xff)&0xff0000)^(Ls(4,(s2>>8)&0xff)&0xff00)^(Ls(4,s3&0xff)&0xff)^rk[40];g_sink^=t0;}
static size_t EVSZ=32*1024; static uint8_t* evbuf;
static inline void evict(void){ for(size_t o=0;o<EVSZ;o+=64) g_sink^=evbuf[o]; }
static inline uint64_t timed(const uint8_t in[16],const uint32_t rk[44]){ unsigned a;_mm_lfence();uint64_t c0=__rdtscp(&a);_mm_lfence();enc(in,rk);_mm_lfence();uint64_t c1=__rdtscp(&a);_mm_lfence();return c1-c0; }
static uint64_t rng=0x1234567; static inline uint32_t xr(){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (uint32_t)rng;}
static uint64_t krng; static inline uint8_t kbyte(){krng^=krng<<13;krng^=krng>>7;krng^=krng<<17;return (uint8_t)krng;}

static const int LANE[4][4]={{0,5,10,15},{4,9,14,3},{8,13,2,7},{12,1,6,11}};
static const int COEF[4]={2,3,1,1};
static uint8_t *PT[16]; static uint16_t *TT; static long M;
static void collect(const uint32_t rk[44],long N,uint64_t cutoff){ uint8_t in[16];M=0;
 for(long n=0;n<N;n++){ for(int j=0;j<16;j++)in[j]=(uint8_t)xr(); evict(); uint64_t t=timed(in,rk);
  if(cutoff&&t>cutoff)continue; for(int j=0;j<16;j++)PT[j][M]=in[j]; TT[M]=(uint16_t)(t>65535?65535:t); M++; } }
static double g_sum[16][256],g_cnt[16][256];
static void profile_stream(const uint32_t rk[44],long N,uint64_t cutoff,double out[16][256]){
 memset(g_sum,0,sizeof(g_sum));memset(g_cnt,0,sizeof(g_cnt)); uint8_t in[16];
 for(long n=0;n<N;n++){ for(int j=0;j<16;j++)in[j]=(uint8_t)xr(); evict(); uint64_t t=timed(in,rk);
  if(cutoff&&t>cutoff)continue; for(int i=0;i<16;i++){ g_sum[i][in[i]]+=t; g_cnt[i][in[i]]++; } }
 for(int b=0;b<16;b++){double m=0;int c=0;for(int v=0;v<256;v++)if(g_cnt[b][v]>0){m+=g_sum[b][v]/g_cnt[b][v];c++;}m/=c;
  for(int v=0;v<256;v++)out[b][v]=g_cnt[b][v]>0?(g_sum[b][v]/g_cnt[b][v]-m):0;} }
static float *Rr; static double *Cs; static uint32_t *Cc; static double *A1s,*A1c;
#define CIDX(u,x,y) (((size_t)(u)<<16)|((size_t)(x)<<8)|(size_t)(y))
static void run_lane(int lane,const uint8_t ktop[4],int outlo[4],double*ov,double*oconf){
 const int*bi=LANE[lane]; const uint8_t *b0=PT[bi[0]],*b1=PT[bi[1]],*b2=PT[bi[2]],*b3=PT[bi[3]];
 memset(A1s,0,65536*sizeof(double));memset(A1c,0,65536*sizeof(double));
 for(long i=0;i<M;i++){int idx=(((b0[i]>>4)^ktop[0])<<12)|(((b1[i]>>4)^ktop[1])<<8)|(((b2[i]>>4)^ktop[2])<<4)|((b3[i]>>4)^ktop[3]);A1s[idx]+=TT[i];A1c[idx]++;}
 for(long i=0;i<M;i++){int idx=(((b0[i]>>4)^ktop[0])<<12)|(((b1[i]>>4)^ktop[1])<<8)|(((b2[i]>>4)^ktop[2])<<4)|((b3[i]>>4)^ktop[3]);Rr[i]=(float)(TT[i]-A1s[idx]/A1c[idx]);}
 static uint8_t term[4][16][256];
 for(int s=0;s<4;s++)for(int lo=0;lo<16;lo++)for(int p=0;p<256;p++)term[s][lo][p]=(uint8_t)(gfmul(SBOX[p^((ktop[s]<<4)|lo)],COEF[s])>>4);
 int ba=0,bb=0,bc=0,bd=0;double best=-1e300; double sumv=0,sumv2=0; long cntv=0;
 for(int a=0;a<16;a++)for(int b=0;b<16;b++){const uint8_t*A=term[0][a],*B=term[1][b];
   memset(Cs,0,(size_t)16*256*256*sizeof(double));memset(Cc,0,(size_t)16*256*256*sizeof(uint32_t));
   for(long i=0;i<M;i++){int u=A[b0[i]]^B[b1[i]];size_t id=CIDX(u,b2[i],b3[i]);Cs[id]+=Rr[i];Cc[id]++;}
   for(int c=0;c<16;c++)for(int d=0;d<16;d++){const uint8_t*C=term[2][c],*D=term[3][d];
     double sumL[16]={0};uint64_t cntL[16]={0};
     for(int u=0;u<16;u++)for(int x=0;x<256;x++){int ul=u^C[x];const double*rs=&Cs[CIDX(u,x,0)];const uint32_t*rc=&Cc[CIDX(u,x,0)];
       for(int y=0;y<256;y++){int L=ul^D[y];sumL[L]+=rs[y];cntL[L]+=rc[y];}}
     double mean[16],am=0;int cc=0;for(int L=0;L<16;L++)if(cntL[L]>0){mean[L]=sumL[L]/cntL[L];am+=mean[L];cc++;}
     am/=cc;double v=0;for(int L=0;L<16;L++)if(cntL[L]>0)v+=(mean[L]-am)*(mean[L]-am);v/=cc;
     sumv+=v; sumv2+=v*v; cntv++;
     if(v>best){best=v;ba=a;bb=b;bc=c;bd=d;}}}
 outlo[0]=ba;outlo[1]=bb;outlo[2]=bc;outlo[3]=bd;*ov=best;
 double mv=sumv/cntv; double var=sumv2/cntv-mv*mv; double sd=sqrt(var>1e-12?var:1e-12);
 *oconf=(best-mv)/sd;
}
static uint64_t measure_min(const uint32_t rk[44], long K){ uint8_t in[16]; uint64_t mn=~0ULL;
 for(long i=0;i<K;i++){ for(int j=0;j<16;j++)in[j]=(uint8_t)xr(); evict(); uint64_t t=timed(in,rk); if(t<mn)mn=t; } return mn; }
static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }

// score one stride: how many of the 16 top nibbles round-1 resolves on a KNOWN key
static int score_stride_round1(const uint8_t CALKEY[16], long calN){
 uint32_t rk[44]; key_expand(CALKEY,rk);
 uint8_t ZK[16]={0}; uint32_t rk0[44]; key_expand(ZK,rk0);
 static double dp[16][256],da[16][256];
 uint64_t base=measure_min(rk,200000); uint64_t cutoff=base*2;
 profile_stream(rk0,calN,cutoff,dp);
 profile_stream(rk,calN,cutoff,da);
 int score=0;
 for(int b=0;b<16;b++){
   double nib[16];
   for(int n=0;n<16;n++){ double s=0; for(int lo=0;lo<16;lo++){ int d=(n<<4)|lo; double c=0;
     for(int v=0;v<256;v++)c+=da[b][v]*dp[b][v^d]; s+=c; } nib[n]=s; }
   int n=0; for(int m=1;m<16;m++) if(nib[m]>nib[n]) n=m;
   if(n==(CALKEY[b]>>4)) score++;
 }
 return score;
}

// full attack on one random key at the (already-built) chosen stride
static int attack_one(int kidx,const uint8_t KEY[16],uint8_t rec[16],
                      long N1,int REPS1,long N2,int MAXR,int WARM,uint64_t base){
 uint32_t rk[44]; key_expand(KEY,rk);
 uint8_t ZK[16]={0}; uint32_t rk0[44]; key_expand(ZK,rk0);
 uint64_t cutoff1=base*2;
 static double dp[16][256],da[16][256];
 double t0=now_s();
 profile_stream(rk0,N1,cutoff1,dp);
 int vtop[16][16],ftop[16][16]; memset(vtop,0,sizeof vtop);
 for(int b=0;b<16;b++)for(int n=0;n<16;n++)ftop[b][n]=1<<30;
 for(int r=0;r<REPS1;r++){ profile_stream(rk,N1,cutoff1,da); int rok=0;
   for(int b=0;b<16;b++){
     double nib[16];
     for(int n=0;n<16;n++){ double s=0; for(int lo=0;lo<16;lo++){ int d=(n<<4)|lo; double c=0;
       for(int v=0;v<256;v++)c+=da[b][v]*dp[b][v^d]; s+=c; } nib[n]=s; }
     int n=0; for(int m=1;m<16;m++) if(nib[m]>nib[n]) n=m;
     vtop[b][n]++; if(r<ftop[b][n])ftop[b][n]=r; if(n==(KEY[b]>>4))rok++; }
   printf("  [k%d] r1 rep %d: top %d/16\n",kidx,r+1,rok); fflush(stdout); }
 uint8_t ktop[16]; int topv=0;
 for(int b=0;b<16;b++){ int bn=0,bv=-1,bf=1<<30; for(int n=0;n<16;n++) if(vtop[b][n]>bv||(vtop[b][n]==bv&&ftop[b][n]<bf)){bv=vtop[b][n];bf=ftop[b][n];bn=n;} ktop[b]=(uint8_t)bn; if(ktop[b]==(KEY[b]>>4))topv++; }
 printf("  [k%d] round1 VOTED top = %d/16  (%.0fs)\n",kidx,topv,now_s()-t0); fflush(stdout);

 // ranked top-nibble candidates per byte (from the last round-1 profile `da`):
 // cand_top[b][0] is round-1's pick, [1]/[2] are the 2nd/3rd choices used for repair.
 uint8_t cand_top[16][3];
 for(int b=0;b<16;b++){
   double nib[16];
   for(int n=0;n<16;n++){ double s=0; for(int lo=0;lo<16;lo++){ int d=(n<<4)|lo; double c=0;
     for(int v=0;v<256;v++)c+=da[b][v]*dp[b][v^d]; s+=c; } nib[n]=s; }
   int used_[16]={0};
   for(int r=0;r<3;r++){ int bn=-1; double bv=-1e300; for(int n=0;n<16;n++) if(!used_[n]&&nib[n]>bv){bv=nib[n];bn=n;} cand_top[b][r]=(uint8_t)bn; used_[bn]=1; }
 }

 // robust cutoff: median of several short-window mins (one noisy warm_min can
 // mis-set the cutoff and poison the whole key's round-2)
 uint64_t ms[7]; for(int i=0;i<7;i++)ms[i]=measure_min(rk,40000);
 for(int i=0;i<7;i++)for(int j=i+1;j<7;j++) if(ms[j]<ms[i]){uint64_t t=ms[i];ms[i]=ms[j];ms[j]=t;}
 uint64_t cutoff2=ms[3]*2;   // median * 2
 double ZLIVE=12.0; { const char*z=getenv("BERN_ZLIVE"); if(z)ZLIVE=atof(z); }
 for(int w=0;w<WARM;w++){ collect(rk,N2,cutoff2); }   // warm the core

 // ===== round-2 with DEAD-WINDOW RETRY (key-free decisions) =====
 // A batch whose best lane-z is below ZLIVE is a dead measurement window (external
 // contention): discard it and re-collect. Only LIVE batches are voted (weighted by
 // z^2 per lane). MAXR is the TOTAL batch budget (live + dead). The accept/discard
 // decision uses only z and vote-stability -- never the key.
 double wlow[16][16]; memset(wlow,0,sizeof wlow);
 int prev[16]; for(int b=0;b<16;b++)prev[b]=-1; int stable=0; int live=0,dead=0,total=0;
 uint8_t klow[16]; for(int b=0;b<16;b++)klow[b]=0;
 while(total < MAXR){
   collect(rk,N2,cutoff2); total++;
   int rok=0; double lz[4]; int lo_all[4][4]; double maxz=0;
   for(int lane=0;lane<4;lane++){ const int*bi=LANE[lane]; uint8_t kt[4]; for(int s=0;s<4;s++)kt[s]=ktop[bi[s]];
     double v,conf; run_lane(lane,kt,lo_all[lane],&v,&conf); lz[lane]=conf; if(conf>maxz)maxz=conf;
     for(int s=0;s<4;s++){ int n=lo_all[lane][s]&0xf; if(n==(KEY[bi[s]]&0xf))rok++; } }
   if(maxz < ZLIVE){
     dead++;
     printf("  [k%d] r2 batch %2d: DEAD z=[%.0f %.0f %.0f %.0f] maxz=%.0f -> discard, retry\n",
            kidx,total,lz[0],lz[1],lz[2],lz[3],maxz); fflush(stdout);
     continue;
   }
   for(int lane=0;lane<4;lane++){ const int*bi=LANE[lane]; double w=(lz[lane]>0)?lz[lane]*lz[lane]:0;
     for(int s=0;s<4;s++){ int bb=bi[s],n=lo_all[lane][s]&0xf; wlow[bb][n]+=w; } }
   live++;
   for(int b=0;b<16;b++){ int bn=0; double bv=-1; for(int n=0;n<16;n++) if(wlow[b][n]>bv){bv=wlow[b][n];bn=n;} klow[b]=(uint8_t)bn; }
   int votok=0; for(int b=0;b<16;b++) if(klow[b]==(KEY[b]&0xf))votok++;
   int changed=0; for(int b=0;b<16;b++) if(klow[b]!=prev[b])changed=1;
   stable=changed?0:(stable+1);
   for(int b=0;b<16;b++)prev[b]=klow[b];
   printf("  [k%d] r2 batch %2d: LIVE low %2d/16 z=[%.0f %.0f %.0f %.0f] voted %2d/16 stable=%d (live=%d)\n",
          kidx,total,rok,lz[0],lz[1],lz[2],lz[3],votok,stable,live); fflush(stdout);
   if(stable>=3 && live>=4) break;
 }
 int lowv=0; for(int b=0;b<16;b++) if(klow[b]==(KEY[b]&0xf))lowv++;
 printf("  [k%d] round2: %d live / %d dead / %d total batches ; VOTED low = %d/16 %s\n",
        kidx,live,dead,total,lowv,(live>=4&&stable>=3)?"(stabilized)":"(LOW CONFIDENCE - few clean windows)"); fflush(stdout);

 // ===== z-GUIDED REPAIR: fix a lane whose top nibble round-1 got wrong =====
 // Grab a good-window batch (high max lane-z), then for any lane whose z is well
 // below the clean lanes, try each of its bytes' 2nd/3rd round-1 top-nibble choices
 // and keep whichever makes that lane's z jump to clean-lane level.
 {
   double lz[4]; int lo_tmp[4][4]; int tries=0; double maxz=0;
   do {
     collect(rk,N2,cutoff2);
     for(int lane=0;lane<4;lane++){ const int*bi=LANE[lane]; uint8_t kt[4]; for(int s=0;s<4;s++)kt[s]=ktop[bi[s]];
       double v; run_lane(lane,kt,lo_tmp[lane],&v,&lz[lane]); }
     maxz=0; for(int l=0;l<4;l++) if(lz[l]>maxz)maxz=lz[l];
     tries++;
   } while(maxz<15.0 && tries<3);
   printf("  [k%d] repair: per-lane z=[%.0f %.0f %.0f %.0f] (maxz=%.0f)\n",kidx,lz[0],lz[1],lz[2],lz[3],maxz); fflush(stdout);

   for(int lane=0;lane<4;lane++){
     if(lz[lane] >= 0.5*maxz) continue;           // lane looks clean; leave it
     const int*bi=LANE[lane];
     uint8_t base_kt[4]; for(int s=0;s<4;s++)base_kt[s]=ktop[bi[s]];
     double best_z=lz[lane]; uint8_t best_kt[4]; int best_lo[4];
     for(int s=0;s<4;s++){best_kt[s]=base_kt[s];best_lo[s]=lo_tmp[lane][s];}
     int fixed_byte=-1,fixed_nib=-1;
     for(int s=0;s<4;s++){
       for(int rnk=1;rnk<3;rnk++){                // try 2nd and 3rd round-1 choices
         uint8_t alt=cand_top[bi[s]][rnk]; if(alt==base_kt[s]) continue;
         uint8_t kt[4]; for(int t=0;t<4;t++)kt[t]=base_kt[t]; kt[s]=alt;
         int lo[4]; double v,z; run_lane(lane,kt,lo,&v,&z);
         if(z>best_z){ best_z=z; for(int t=0;t<4;t++){best_kt[t]=kt[t];best_lo[t]=lo[t];} fixed_byte=bi[s]; fixed_nib=alt; }
       }
     }
     if(best_z > lz[lane]*1.5 && best_z > 0.6*maxz && fixed_byte>=0){
       for(int s=0;s<4;s++){ ktop[bi[s]]=best_kt[s]; klow[bi[s]]=(uint8_t)(best_lo[s]&0xf); }
       printf("  [k%d] repair: lane %d FIXED byte %d top->0x%x  (z %.0f -> %.0f)\n",
              kidx,lane,fixed_byte,fixed_nib,lz[lane],best_z); fflush(stdout);
     } else {
       printf("  [k%d] repair: lane %d no confident fix (best z %.0f)\n",kidx,lane,best_z); fflush(stdout);
     }
   }
 }

 topv=0; for(int b=0;b<16;b++) if(ktop[b]==(KEY[b]>>4))topv++;
 lowv=0; for(int b=0;b<16;b++) if(klow[b]==(KEY[b]&0xf))lowv++;
 int full=0; for(int b=0;b<16;b++){ rec[b]=(uint8_t)((ktop[b]<<4)|klow[b]); if(rec[b]==KEY[b])full++; }
 printf("  [k%d] after repair: top %d/16  low %d/16\n",kidx,topv,lowv); fflush(stdout);
 return full;
}

int main(int argc,char**argv){
 int NKEYS  = (argc>1)?atoi(argv[1]):3;
 long N1    = (argc>2)?atol(argv[2]):(288L*1000*1000);
 int REPS1  = (argc>3)?atoi(argv[3]):2;
 long N2    = (argc>4)?atol(argv[4]):(32L*1000*1000);
 int MAXR   = (argc>5)?atoi(argv[5]):12;
 int WARM   = (argc>6)?atoi(argv[6]):2;
 if(argc>7) EVSZ=(size_t)atol(argv[7])*1024;
 long calN  = (argc>8)?atol(argv[8]):(48L*1000*1000);

 int cpu=1; { const char*c=getenv("BERN_CPU"); if(c)cpu=atoi(c); }
 cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu,&set);
 if(sched_setaffinity(0,sizeof set,&set)!=0) printf("[warn] could not pin to CPU %d\n",cpu); else printf("pinned to CPU %d\n",cpu);

 // candidate strides
 long cands[32]; int ncand=0;
 { const char* s=getenv("BERN_STRIDES");
   if(s&&*s){ char buf[512]; strncpy(buf,s,sizeof buf-1); buf[sizeof buf-1]=0; char*tok=strtok(buf,", ");
     while(tok&&ncand<32){ long v=atol(tok); if(v>=64) cands[ncand++]=v; tok=strtok(NULL,", "); } }
   if(ncand==0){ long def[]={4160,4288,4352,4608,8256,12352}; for(unsigned i=0;i<sizeof def/sizeof def[0];i++)cands[ncand++]=def[i]; } }

 build_tables(); evbuf=aligned_alloc(4096,EVSZ); memset(evbuf,1,EVSZ);
 for(int i=0;i<16;i++)PT[i]=malloc(N2); TT=malloc(N2*sizeof(uint16_t)); Rr=malloc(N2*sizeof(float));
 Cs=malloc((size_t)16*256*256*sizeof(double));Cc=malloc((size_t)16*256*256*sizeof(uint32_t));
 A1s=malloc(65536*sizeof(double));A1c=malloc(65536*sizeof(double));
 if(!TT||!Rr||!Cs||!Cc||!A1s||!A1c){printf("alloc failed\n");return 1;}
 krng=__rdtsc()^0x243f6a8885a308d3ULL; for(int i=0;i<8;i++)kbyte();

 // fixed known calibration key (NOT one of the attack keys)
 uint8_t CALKEY[16]={0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0};

 printf("NKEYS=%d N1=%ld REPS1=%d N2=%ld MAXREPS2=%d WARM=%d evict=%zuKB calN=%ld\n",
        NKEYS,N1,REPS1,N2,MAXR,WARM,EVSZ/1024,calN);

 // ===== CALIBRATION: pick the best stride for THIS instance =====
 printf("[cal] sweeping %d candidate strides on a known key (calN=%ld) ...\n",ncand,calN); fflush(stdout);
 long best_stride=cands[0]; int best_score=-1; double tcal=now_s();
 for(int c=0;c<ncand;c++){
   STRIDE=cands[c]; build_layout();
   int sc=score_stride_round1(CALKEY,calN);
   printf("  [cal] stride=%5ld : top %2d/16\n",STRIDE,sc); fflush(stdout);
   if(sc>best_score){best_score=sc;best_stride=STRIDE;}
   if(sc==16) break;   // this stride already resolves all 16 at calN -- good enough
 }
 printf("[cal] chosen stride = %ld (score %d/16 at calN, %.0fs)\n\n",best_stride,best_score,now_s()-tcal);
 STRIDE=best_stride; build_layout();

 // base min at the chosen stride (key-independent)
 uint8_t k0[16]; for(int i=0;i<16;i++)k0[i]=CALKEY[i];
 uint32_t rk0s[44]; key_expand(k0,rk0s);
 uint64_t base=measure_min(rk0s,300000);
 printf("[run] stride=%ld base_min=%llu ; attacking %d random keys\n\n",STRIDE,(unsigned long long)base,NKEYS);

 int recovered=0;
 for(int k=0;k<NKEYS;k++){
   uint8_t KEY[16]; for(int i=0;i<16;i++)KEY[i]=kbyte();
   printf("===== KEY %d/%d : ",k+1,NKEYS); for(int b=0;b<16;b++)printf("%02x",KEY[b]); printf(" =====\n"); fflush(stdout);
   uint8_t rec[16]; double tk=now_s();
   int full=attack_one(k+1,KEY,rec,N1,REPS1,N2,MAXR,WARM,base);
   int ok=(full==16); if(ok)recovered++;
   printf("----- KEY %d/%d RESULT -----\n",k+1,NKEYS);
   printf("  true : "); for(int b=0;b<16;b++)printf("%02x",KEY[b]); printf("\n");
   printf("  recov: "); for(int b=0;b<16;b++)printf("%02x",rec[b]); printf("\n");
   printf("  FULL BYTES %d/16  %s   (%.0fs)\n\n", full, ok?"*** KEY RECOVERED ***":"(partial)", now_s()-tk);
   fflush(stdout);
 }
 printf("================ SUMMARY ================\n");
 printf("chosen stride: %ld\n", best_stride);
 printf("full keys recovered: %d/%d\n", recovered, NKEYS);
 return 0;
}
