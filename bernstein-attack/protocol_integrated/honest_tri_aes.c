// honest_tri_aes.c -- honest Beaver-triplet party whose PRG is REAL AES-128.
// Runs the protocol's offline PRG step on each trigger: reads the attacker-supplied
// counter block (prg_in), AES-128-encrypts it with its secret key over strided T-tables,
// and publishes the masked wire (wire_M1). This is the protocol's PRG expansion; the
// party never looks at timing. Structurally identical to the toy honest.c, but the
// 1-byte-key two-lookup PRG is replaced by full AES-128.
//
// Build: gcc -O2 -march=native honest_tri_aes.c -o honest_tri_aes -lrt
// Run:   taskset -c 0 ./honest_tri_aes <stride> [secret_key_32hex]
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include "common_tri_aes.h"

int main(int argc,char**argv){
 BSTRIDE = (argc>1)?atol(argv[1]):4160;
 bern_build_tables(); bern_build_layout();

 shm_unlink(SHM_TRI_AES);
 int fd=shm_open(SHM_TRI_AES,O_CREAT|O_RDWR,0666);
 if(fd==-1){perror("shm_open");return 1;}
 if(ftruncate(fd,sizeof(TriAesShared))==-1){perror("ftruncate");return 1;}
 TriAesShared* st=mmap(NULL,sizeof(TriAesShared),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 if(st==MAP_FAILED){perror("mmap");return 1;}

 uint8_t known[16]={0}, secret[16];
 if(argc>2 && strlen(argv[2])>=32){ for(int i=0;i<16;i++){unsigned b;sscanf(argv[2]+2*i,"%2x",&b);secret[i]=(uint8_t)b;} }
 else { uint64_t s=(uint64_t)time(NULL)^0x9e3779b97f4a7c15ULL^(uint64_t)getpid(); for(int i=0;i<16;i++){s^=s<<13;s^=s>>7;s^=s<<17;secret[i]=(uint8_t)s;} }
 uint32_t rk_known[44],rk_secret[44];
 bern_key_expand(known,rk_known); bern_key_expand(secret,rk_secret);

 for(int i=0;i<16;i++)st->true_key[i]=secret[i];
 st->trigger_prg=0; st->keysel=0; st->exit_flag=0;
 __sync_synchronize(); st->p2_ready=1;

 fprintf(stderr,"[honest] PRG=AES-128 stride=%ld ready. secret PRG key = ",BSTRIDE);
 for(int i=0;i<16;i++)fprintf(stderr,"%02x",secret[i]); fprintf(stderr,"\n");

 // protocol PRG service loop
 while(!st->exit_flag){
   while(!st->trigger_prg && !st->exit_flag) _mm_pause();
   if(st->exit_flag) break;
   uint8_t in[16]; for(int i=0;i<16;i++)in[i]=st->prg_in[i];
   const uint32_t* rk = st->keysel ? rk_secret : rk_known;
   bern_enc(in,rk);                 // AES-128 over the strided T-tables
   st->wire_M1 = bern_sink;         // publish the masked wire (PRG output word)
   __sync_synchronize();
   st->trigger_prg=0;               // PRG done -- ack to attacker
 }
 munmap(st,sizeof(TriAesShared)); close(fd);
 fprintf(stderr,"[honest] exit\n");
 return 0;
}
