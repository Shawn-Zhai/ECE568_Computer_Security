#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include "lib/sha1.h"


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// current unix time divided by default step interval
    unsigned long T = time(NULL) / 30;
   	uint8_t message[8];
	memset(message, 0, 8);

	for (int i = 7; i >= 0; i--) { // big endian filling?
		message[i] = T & 0xff;
		T >>= 8;
	}

	// binary secret
	uint8_t secret_int[SHA1_BLOCKSIZE];
	memset(secret_int, 0, SHA1_BLOCKSIZE);

	int upper_4_bits, lower_4_bits;
	for (int i = 0; i < 10; i++) {
		upper_4_bits = 0;
		if (secret_hex[2 * i] >= 48 && secret_hex[2 * i] <= 57) // 0 - 9
			upper_4_bits = secret_hex[2 * i] - 48;
		else if (secret_hex[2 * i] >= 65 && secret_hex[2 * i] <= 70) // A - F
			upper_4_bits = secret_hex[2 * i] - 55;
		
		lower_4_bits = 0;
		if (secret_hex[2 * i + 1] >= 48 && secret_hex[2 * i + 1] <= 57) // 0 - 9
			lower_4_bits = secret_hex[2 * i + 1] - 48;
		else if (secret_hex[2 * i + 1] >= 65 && secret_hex[2 * i + 1] <= 70) // A - F
			lower_4_bits = secret_hex[2 * i + 1] - 55;

		secret_int[i] = upper_4_bits << 4 | lower_4_bits;
	}

	// XOR to make inner and outer key
	uint8_t inner_key[SHA1_BLOCKSIZE];
	uint8_t outer_key[SHA1_BLOCKSIZE];
	memset(inner_key, 0x36, SHA1_BLOCKSIZE);
	memset(outer_key, 0x5c, SHA1_BLOCKSIZE);

	for (int i = 0; i < SHA1_BLOCKSIZE; i++) {
		inner_key[i] ^= secret_int[i];
		outer_key[i] ^= secret_int[i];
	}

	// HMAC inner and outer hashing
	SHA1_INFO ctx;
	uint8_t sha_inner[SHA1_DIGEST_LENGTH];
	uint8_t sha_outer[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, inner_key, SHA1_BLOCKSIZE);
	sha1_update(&ctx, message, 8);
	sha1_final(&ctx, sha_inner);

	sha1_init(&ctx);
	sha1_update(&ctx, outer_key, SHA1_BLOCKSIZE);
	sha1_update(&ctx, sha_inner, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, sha_outer);

	// put selected bytes into result int
	int offset = sha_outer[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary =
	((sha_outer[offset] & 0x7f) << 24) |
	((sha_outer[offset + 1] & 0xff) << 16) |
	((sha_outer[offset + 2] & 0xff) << 8) |
	(sha_outer[offset + 3] & 0xff);

	int otp = binary % 1000000;
	int TOTP_val = atoi(TOTP_string);

	if (otp == TOTP_val)
		return 1;
	else
		return 0;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
