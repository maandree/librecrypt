/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#define ENTRY(ALGO)\
	{\
		.is_algorithm = &librecrypt__##ALGO##__is_algorithm,\
		.hash = librecrypt__##ALGO##__hash,\
		.test_supported = &librecrypt__##ALGO##__test_supported,\
		.make_settings = &librecrypt__##ALGO##__make_settings,\
		.encoding_lut = librecrypt__##ALGO##__encoding_lut,\
		.decoding_lut = librecrypt__##ALGO##__decoding_lut,\
		.hash_size = ALGO##__HASH_SIZE,\
		.flexible_hash_size = ALGO##__FLEXIBLE_HASH_SIZE,\
		.strict_pad = ALGO##__STRICT_PAD,\
		.pad = ALGO##__PAD\
	}


#define X(ALGO) IF__##ALGO##__SUPPORTED(ENTRY(ALGO) COMMA)
struct algorithm librecrypt_algorithms_[] = {
	LIST_ALGORITHMS(X)
	END_OF_ALGORITHMS
};
#undef X


#else


int
main(void)
{
#define X(ALGO) IF__##ALGO##__SUPPORTED(+ 1u)
	const size_t count = 0u LIST_ALGORITHMS(X);
#undef X
	size_t i;

	SET_UP_ALARM();

	/* Validate algorithm entry  */
	for (i = 0u; i < count; i++) {
		/* Stop at end-of-list marker */
		EXPECT(!IS_END_OF_ALGORITHMS(&librecrypt_algorithms_[i]));

		/* Check all functions are set */
		EXPECT(librecrypt_algorithms_[i].is_algorithm != NULL);
		EXPECT(librecrypt_algorithms_[i].hash != NULL);
		EXPECT(librecrypt_algorithms_[i].test_supported != NULL);
		EXPECT(librecrypt_algorithms_[i].make_settings != NULL);

		/* Check the salt and hash encoding tables are set */
		EXPECT(librecrypt_algorithms_[i].encoding_lut != NULL);
		EXPECT(librecrypt_algorithms_[i].decoding_lut != NULL);

		/* Check .flexible_hash_size is either 0 and 1 */
		EXPECT(librecrypt_algorithms_[i].flexible_hash_size >= 0);
		EXPECT(librecrypt_algorithms_[i].flexible_hash_size <= 1);

		/* Check hash_size is set if .flexible_hash_size is 0 */
		if (!librecrypt_algorithms_[i].flexible_hash_size)
			EXPECT(librecrypt_algorithms_[i].hash_size > 0u);

		/* Check .strict_pad is either 0 and 1 */
		EXPECT(librecrypt_algorithms_[i].strict_pad >= 0);
		EXPECT(librecrypt_algorithms_[i].strict_pad <= 1);

		/* Check .pad is NUL (none) or valid */
		if (librecrypt_algorithms_[i].pad) {
			/* printable but not whitespace */
			EXPECT(librecrypt_algorithms_[i].pad > ' ');
			EXPECT(librecrypt_algorithms_[i].pad < 0x7F);
			/* does not have special meaning */
			EXPECT(librecrypt_algorithms_[i].pad != LIBRECRYPT_HASH_COMPOSITION_DELIMITER);
			EXPECT(librecrypt_algorithms_[i].pad != LIBRECRYPT_ALGORITHM_LINK_DELIMITER);
			EXPECT(librecrypt_algorithms_[i].pad != '*');
			/* is not ':' which has special meaning in table files */
			EXPECT(librecrypt_algorithms_[i].pad != ':');
			/* other characters forbidden by crypt(5) */
			EXPECT(librecrypt_algorithms_[i].pad != '!');
			EXPECT(librecrypt_algorithms_[i].pad != ';');
			EXPECT(librecrypt_algorithms_[i].pad != '\\');
		}
	}

	/* Check number of algorithms in the list was the number of supported algorithms */
	assert(i == count);
	/* Check that the list has an end-of-list marker */
	EXPECT(IS_END_OF_ALGORITHMS(&librecrypt_algorithms_[count]));

	return 0;
}


#endif
