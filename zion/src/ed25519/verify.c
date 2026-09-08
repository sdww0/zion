// SPDX-License-Identifier: BSD-3-Clause
/* Derived from the Zion SDK Ed25519 verifier. */
#include "../sha3/sha3.h"
#include "ed25519.h"
#include "ge.h"
#include "sc.h"

static const unsigned char group_order[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

static int consttime_equal_32(const unsigned char *x,
			      const unsigned char *y)
{
	unsigned char different = 0;

	for (int i = 0; i < 32; i++)
		different |= x[i] ^ y[i];
	return !different;
}

static int scalar_is_canonical(const unsigned char scalar[32])
{
	for (int i = 31; i >= 0; i--) {
		if (scalar[i] < group_order[i])
			return 1;
		if (scalar[i] > group_order[i])
			return 0;
	}
	return 0;
}

static int point_encoding_is_canonical(const unsigned char encoded[32])
{
	unsigned char y_encoding[32];
	unsigned char canonical[32];
	fe y;

	for (int i = 0; i < 32; i++)
		y_encoding[i] = encoded[i];
	y_encoding[31] &= 0x7f;
	fe_frombytes(y, y_encoding);
	fe_tobytes(canonical, y);
	return consttime_equal_32(canonical, y_encoding);
}

static int point_is_small_order(const ge_p3 *point)
{
	static const unsigned char identity[32] = { 1 };
	unsigned char encoded[32];
	ge_p1p1 doubled;
	ge_p3 multiple;

	ge_p3_dbl(&doubled, point);
	ge_p1p1_to_p3(&multiple, &doubled);
	ge_p3_dbl(&doubled, &multiple);
	ge_p1p1_to_p3(&multiple, &doubled);
	ge_p3_dbl(&doubled, &multiple);
	ge_p1p1_to_p3(&multiple, &doubled);
	ge_p3_tobytes(encoded, &multiple);
	return consttime_equal_32(encoded, identity);
}

int ed25519_verify(const unsigned char *signature,
		   const unsigned char *message, size_t message_len,
		   const unsigned char *public_key)
{
	unsigned char h[64];
	unsigned char checker[32];
	sha3_ctx_t hash;
	ge_p3 public_point;
	ge_p3 signature_point;
	ge_p2 result;
	int valid;

	if (!signature || !public_key || (message_len && !message) ||
	    !scalar_is_canonical(signature + 32) ||
	    !point_encoding_is_canonical(signature) ||
	    !point_encoding_is_canonical(public_key))
		return 0;
	if (ge_frombytes_negate_vartime(&public_point, public_key) ||
	    point_is_small_order(&public_point) ||
	    ge_frombytes_negate_vartime(&signature_point, signature) ||
	    point_is_small_order(&signature_point))
		return 0;

	sha3_init(&hash, 64);
	sha3_update(&hash, signature, 32);
	sha3_update(&hash, public_key, 32);
	sha3_update(&hash, message, message_len);
	sha3_final(h, &hash);
	sc_reduce(h);
	ge_double_scalarmult_vartime(&result, h, &public_point,
				     signature + 32);
	ge_tobytes(checker, &result);
	valid = consttime_equal_32(checker, signature);

	for (int i = 0; i < sizeof(h); i++)
		h[i] = 0;
	for (int i = 0; i < sizeof(checker); i++)
		checker[i] = 0;
	return valid;
}
