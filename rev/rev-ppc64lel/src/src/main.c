/**
 * @mebeim - 2025-04-06
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

/* Generated at build time */
#include "verifier.h"

/* Placeholders to avoid IDE warnings */
#ifndef VERIFIER_KEY_SIZE
extern uint8_t *verify(const char *);
#define VERIFIER_KEY_SIZE 0
#endif

const unsigned char nonce[crypto_stream_chacha20_NONCEBYTES] = {0};

// toh{F1n4lly_4_l3g17_sw17ch_3nd14n_us3_c4s3_0M3GALUL}
const unsigned char enc_flag[] = {
	0x4f, 0x4c, 0xb0, 0xd0, 0x15, 0x96, 0xf9, 0xe1, 0x43, 0xcb, 0x72, 0xa0,
	0x1f, 0x67, 0x84, 0x2e, 0xe2, 0x34, 0xf4, 0xfe, 0x61, 0xb3, 0xf1, 0xea,
	0xf2, 0xfc, 0xe5, 0x90, 0x61, 0xb3, 0xac, 0x81, 0x99, 0x42, 0xad, 0x9b,
	0x14, 0x09, 0xf5, 0xab, 0xe9, 0x74, 0x6b, 0x4d, 0x26, 0x81, 0x29, 0x0f,
	0xe0, 0x1b, 0x13, 0x54
};

static int decrypt_flag(uint8_t *out, const uint8_t *key) {
	uint8_t hash[crypto_generichash_BYTES];
	_Static_assert(crypto_generichash_BYTES == crypto_stream_chacha20_KEYBYTES);

	if (sodium_init() == -1)
		return -1;

	if (crypto_generichash(hash, sizeof(hash), key, VERIFIER_KEY_SIZE, NULL, 0) != 0)
		return -1;

	if (crypto_stream_chacha20_xor_ic(out, enc_flag, sizeof(enc_flag), nonce, 0, hash) != 0)
		return -1;

	out[sizeof(enc_flag)] = 0;
	return 0;
}

int main(int argc, char **argv) {
	char flag[sizeof(enc_flag) + 1];
	uint8_t *key;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s KEY\n", argv[0]);
		return 1;
	}

	key = verify(argv[1]);
	if (!key)
		errx(1, "Invalid key");

	if (decrypt_flag((uint8_t *)flag, key) != 0)
		return 1;

	puts(flag);
	return 0;
}
