/* This simple test app is created with the sole purpose to check the validity
 * of the structures and ioctl IDs as defined in cryptodev.h against the 
 * cryptodev.pas Pascal header */

#include <stdio.h>

#include <linux/ioctl.h>
#include "crypto/cryptodev.h"

#define SEPARATOR "=============================================================\n"

void dump_struct_sizes()
{
  printf("Struct/Record sizes (in bytes):\n");
  printf(SEPARATOR);
  printf("TSessionOp:     %d\n",sizeof(struct session_op));
  printf("TAlgInfo:       %d\n",sizeof(struct alg_info));
  printf("TSessionInfoOp: %d\n",sizeof(struct session_info_op));
  printf("TCryptOp:       %d\n",sizeof(struct crypt_op));
  printf("TCryptAuthOp:   %d\n",sizeof(struct crypt_auth_op));
  printf("TCryptKOp:      %d\n",sizeof(struct crypt_kop));
}

void dump_ioctl_ids()
{
  printf("ioctl IDs:\n");
  printf(SEPARATOR);
  printf("CRIOGET          $%x\n",CRIOGET);
  printf("CIOCGSESSION     $%x\n",CIOCGSESSION);
  printf("CIOCFSESSION     $%x\n",CIOCFSESSION);
  printf("CIOCCRYPT        $%x\n",CIOCCRYPT);
  printf("CIOCKEY          $%x\n",CIOCKEY);
  printf("CIOCASYMFEAT     $%x\n",CIOCASYMFEAT);
  printf("CIOCGSESSIONINFO $%x\n",CIOCGSESSINFO);
  printf("CIOCAUTHCRYPT    $%x\n",CIOCAUTHCRYPT);
  printf("CIOCASYNCCRYPT   $%x\n",CIOCASYNCCRYPT);
  printf("CIOCASYNCFETCH   $%x\n",CIOCASYNCFETCH);
};

int main(int argc, char** argv)
{
  printf("\n");
  dump_struct_sizes();
  printf("\n");
  dump_ioctl_ids();
  printf("\n");

  return 0;
}
