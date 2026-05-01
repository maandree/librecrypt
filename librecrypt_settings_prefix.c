/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


size_t
librecrypt_settings_prefix(const char *hash, size_t *hashsize_out)
{
	size_t i, len, ret = 0u;
	size_t last_offset = 0u;
	const struct algorithm *algo;
	uintmax_t hashsize;

	/* Find last algorithm, and beginning of result */
	for (i = 0u; hash[i]; i++) {
		if (hash[i] == LIBRECRYPT_HASH_COMPOSITION_DELIMITER)
			ret = i + 1u;
		else if (hash[i] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
			last_offset = ret = i + 1u;
	}
	/* and get `strlen(hash)` */
	len = i;

	/* TODO "_" is a prefix that is being used */

	/* Return if hash size is not required */
	if (!hashsize_out)
		goto out;
	/* Return 0 as hash size if default is specified */
	if (ret == i)
		goto zero;
	/* Return 0 as hash size if algorithm cannot be identified or has fixed hash size */
	algo = librecrypt_find_first_algorithm_(&hash[last_offset], len - last_offset);
	if (!algo || !algo->flexible_hash_size)
		goto zero;

	/* Get the hash size */
	if (!librecrypt_check_settings_(&hash[ret], len - ret, "%^b",
	                                &hashsize, (uintmax_t)1u, (uintmax_t)SIZE_MAX,
	                                algo->decoding_lut, algo->pad, algo->strict_pad))
		goto zero;

	*hashsize_out = (size_t)hashsize;
	goto out;

zero:
	*hashsize_out = 0u;
out:
	return ret;
}


#else


#define CHECK_NULL(PREFIX, SUFFIX)\
	do {\
		EXPECT(librecrypt_settings_prefix(PREFIX SUFFIX, NULL) == sizeof(PREFIX) - 1u);\
		EXPECT(librecrypt_settings_prefix(PREFIX, NULL) == sizeof(PREFIX) - 1u); \
	} while (0)

#if 0
#define CHECK_ASTERISK(PREFIX, SUFFIX, HASH)\
	do {\
		size_t hashsize = 99999u;\
		EXPECT(librecrypt_settings_prefix(PREFIX SUFFIX #HASH, &hashsize) == sizeof(PREFIX) - 1u);\
		EXPECT(hashsize == HASH##u);\
	} while (0)

#define CHECK_ZERO(PREFIX, SUFFIX)\
	do {\
		size_t hashsize = 99999u;\
		EXPECT(librecrypt_settings_prefix(PREFIX SUFFIX, &hashsize) == sizeof(PREFIX) - 1u);\
		EXPECT(hashsize == 0u);\
	} while (0)

#define CHECK_HASHED(PREFIX, SUFFIX, HASH)\
	do {\
		size_t hashsize = 99999u;\
		EXPECT(librecrypt_settings_prefix(PREFIX SUFFIX, &hashsize) == sizeof(PREFIX) - 1u);\
		EXPECT(hashsize == HASH##u);\
	} while (0)
#endif


int
main(void)
{
	SET_UP_ALARM();

	/* Simple cases */
	CHECK_NULL("", "result");
	CHECK_NULL(">", "double-des result");
	CHECK_NULL("$", "x");
	CHECK_NULL("y$", "x");
	CHECK_NULL("y>", "x");
	CHECK_NULL("a$b$c>d$e$", "x");
	CHECK_NULL("a$b$c>", "x");

	/* Discard asterisk-notation */
	CHECK_NULL("", "*10");
	CHECK_NULL(">", "*11");
	CHECK_NULL("$", "*12");
	CHECK_NULL("y$", "*13");
	CHECK_NULL("y>", "*012");
	CHECK_NULL("a$b$c>d$e$", "*1");
	CHECK_NULL("a$b$c>", "*2");
	CHECK_NULL("a$b$c>*10$", "*2");

	/* TODO test hash size output (requires algorithms) */

	return 0;
}


#endif
