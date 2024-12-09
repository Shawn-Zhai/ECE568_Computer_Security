#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	char URI[256];
	uint8_t base32_secret[17];

	uint8_t secret_int[10];
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

	base32_encode(secret_int, 10, base32_secret, 16);
	base32_secret[16] = '\0';

	sprintf(URI, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
			urlEncode(accountName), urlEncode(issuer), base32_secret);

	displayQRcode(URI);

	return (0);
}
