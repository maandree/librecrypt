/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#define ENTRY(ALGO)\
	{\
		.get_prefix = &librecrypt__##ALGO##__get_prefix,\
		.is_algorithm = &librecrypt__##ALGO##__is_algorithm,\
		.hash = librecrypt__##ALGO##__hash,\
		.test_supported = &librecrypt__##ALGO##__test_supported,\
		.make_settings = &librecrypt__##ALGO##__make_settings,\
		.encoding_lut = &librecrypt__##ALGO##__encoding_lut,\
		.decoding_lut = &librecrypt__##ALGO##__decoding_lut,\
		.hash_size = ALGO##__HASH_SIZE,\
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

	for (i = 0u; i < count; i++) {
		CHECK(!IS_END_OF_ALGORITHMS(&librecrypt_algorithms_[i]));
		CHECK(librecrypt_algorithms_[i].get_prefix != NULL);
		CHECK(librecrypt_algorithms_[i].is_algorithm != NULL);
		CHECK(librecrypt_algorithms_[i].hash != NULL);
		CHECK(librecrypt_algorithms_[i].test_supported != NULL);
		CHECK(librecrypt_algorithms_[i].make_settings != NULL);
		CHECK(librecrypt_algorithms_[i].encoding_lut != NULL);
		CHECK(librecrypt_algorithms_[i].decoding_lut != NULL);
		CHECK(librecrypt_algorithms_[i].hash_size > 0u);
		CHECK(librecrypt_algorithms_[i].strict_pad >= 0);
		CHECK(librecrypt_algorithms_[i].strict_pad <= 1);
		if (librecrypt_algorithms_[i].pad) {
			CHECK(librecrypt_algorithms_[i].pad > ' ');
			CHECK(librecrypt_algorithms_[i].pad < 0x7F);
			CHECK(librecrypt_algorithms_[i].pad != LIBRECRYPT_HASH_COMPOSITION_DELIMITER);
			CHECK(librecrypt_algorithms_[i].pad != LIBRECRYPT_ALGORITHM_LINK_DELIMITER);
			CHECK(librecrypt_algorithms_[i].pad != '*');
		}
	}
	assert(i == count);
	CHECK(IS_END_OF_ALGORITHMS(&librecrypt_algorithms_[count]));

	return 0;
}


#endif
