// victim_bern.c -- the victim process. Builds strided AES-128 T-tables, holds a known
// reference key (zero) and a random secret key, and on each attacker trigger runs ONE
// encryption of the shared-memory plaintext with the selected key, then clears the
// trigger. It never looks at timing -- it just computes, like a real victim would.
//
// Build: gcc -O2 -march=native victim_bern.c -o victim_bern -lrt
// Run:   taskset -c 0 ./victim_bern <stride> [secret_key_32hex]   (pin to its own core)
//        If a 32-hex key is given it is used as the secret key (lets a benchmark hold
//        the key fixed while sweeping N); otherwise a random secret key is generated.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include "common_bern.h"

int main(int argc,char**argv){
 BSTRIDE = (argc>1)?atol(argv[1]):4160;
 bern_build_tables(); bern_build_layout();

 shm_unlink(SHM_BERN_NAME);
 int fd=shm_open(SHM_BERN_NAME,O_CREAT|O_RDWR,0666);
 if(fd==-1){perror("shm_open");return 1;}
 if(ftruncate(fd,sizeof(BernShared))==-1){perror("ftruncate");return 1;}
 BernShared* st=mmap(NULL,sizeof(BernShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 if(st==MAP_FAILED){perror("mmap");return 1;}

 // known reference key = zero; secret key = random
 uint8_t known[16]={0};
 uint8_t secret[16];
 if(argc>2 && strlen(argv[2])>=32){
   for(int i=0;i<16;i++){unsigned b;sscanf(argv[2]+2*i,"%2x",&b);secret[i]=(uint8_t)b;}
 } else {
   uint64_t s=(uint64_t)time(NULL)^0x9e3779b97f4a7c15ULL^(uint64_t)getpid();
   for(int i=0;i<16;i++){s^=s<<13;s^=s>>7;s^=s<<17;secret[i]=(uint8_t)s;}
 }
 uint32_t rk_known[44],rk_secret[44];
 bern_key_expand(known,rk_known);
 bern_key_expand(secret,rk_secret);

 for(int i=0;i<16;i++)st->true_key[i]=secret[i];   // validation only
 st->trigger=0; st->keysel=0; st->exit_flag=0;
 __sync_synchronize();
 st->ready_v=1;

 fprintf(stderr,"[victim] stride=%ld ready. secret key = ",BSTRIDE);
 for(int i=0;i<16;i++)fprintf(stderr,"%02x",secret[i]); fprintf(stderr,"\n");

 // service loop
 while(!st->exit_flag){
   while(!st->trigger && !st->exit_flag) _mm_pause();
   if(st->exit_flag) break;
   uint8_t in[16]; for(int i=0;i<16;i++)in[i]=st->plaintext[i];
   const uint32_t* rk = st->keysel ? rk_secret : rk_known;
   bern_enc(in,rk);
   __sync_synchronize();
   st->trigger=0;            // signal done
 }
 munmap(st,sizeof(BernShared)); close(fd);
 fprintf(stderr,"[victim] exit\n");
 return 0;
}
