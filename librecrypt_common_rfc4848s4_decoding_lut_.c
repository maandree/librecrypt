/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const unsigned char librecrypt_common_rfc4848s4_decoding_lut_[256u] = {
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, 62, XX, XX, XX, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, XX, XX, XX, XX, XX, XX,
	XX,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, XX, XX, XX, XX, XX,
	XX, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX
};


#else


int
main(void)
{
	unsigned i, found[64u], invalids = 0u;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* Ensure values [0, 64) are encoded exactly once each,
	 * and that all other characters are marked as invalid */
	memset(found, 0, sizeof(found));
	for (i = 0u; i < 256u; i++) {
		if (librecrypt_common_rfc4848s4_decoding_lut_[i] == 0xFFu) {
			invalids += 1u;
		} else {
			EXPECT(librecrypt_common_rfc4848s4_decoding_lut_[i] < 64u);
			found[librecrypt_common_rfc4848s4_decoding_lut_[i]] += 1u;
		}
	}
	EXPECT(invalids == 256u - 64u);
	for (i = 0u; i < 64u; i++)
		EXPECT(found[i] == 1u);

	/* Match with librecrypt_common_rfc4848s4_encoding_lut_ is
	 * tested in librecrypt_common_rfc4848s4_decoding_lut_.c */

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
