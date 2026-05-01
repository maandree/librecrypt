/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
NONSTRING const char librecrypt_common_rfc4848s4_encoding_lut_[256u] = MAKE_ENCODING_LUT(ALPHABET);


#else


int
main(void)
{
	size_t i;
	char c;

	SET_UP_ALARM();

	for (i = 0u; i < 64u; i++) {
		c = librecrypt_common_rfc4848s4_encoding_lut_[i];

		/* Check alphabet repeated 4 times (64 characters become 256) */
		EXPECT(librecrypt_common_rfc4848s4_encoding_lut_[i + 64u * 1u] == c);
		EXPECT(librecrypt_common_rfc4848s4_encoding_lut_[i + 64u * 2u] == c);
		EXPECT(librecrypt_common_rfc4848s4_encoding_lut_[i + 64u * 3u] == c);

		/* Check alphabet is valid: */
		/*   printable but not whitespace */
		EXPECT(c > ' ');
		EXPECT(c < '\x7F');
		/*   character does not have special mean */
		EXPECT(c != LIBRECRYPT_HASH_COMPOSITION_DELIMITER);
		EXPECT(c != LIBRECRYPT_ALGORITHM_LINK_DELIMITER);
		EXPECT(c != '*');
		/*   character is not ':' which has special meaning in table files */
		EXPECT(c != ':');
		/*   other characters forbidden by crypt(5) */
		EXPECT(c != ';');
		EXPECT(c != '!');
		EXPECT(c != '\\');

		/* Check encoding LUT matches decoding LUT;
		 * this verifies that characters in the alphabet are unique */
		EXPECT(librecrypt_common_rfc4848s4_decoding_lut_[(unsigned char)c] == i);
	}

	return 0;
}


#endif
