/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST

#include <libar2.h>


int
librecrypt__argon2__test_supported(const char *phrase, size_t len, int text, const char *settings, size_t prefix, size_t *len_out)
{
	uintmax_t hashsize;
	int r;

	/* We don't care about password content, arbitrary binary is supported */
	(void) phrase;
	(void) text;

#define RANGE(MIN, MAX) (uintmax_t)(MIN), (uintmax_t)(MAX)
#define BASE64 librecrypt_common_rfc4848s4_decoding_lut_, argon2__PAD, argon2__STRICT_PAD

	/* Validate string format and parameters */
	r = librecrypt_check_settings_(settings, prefix,
		"$%*$%sm=%p,t=%p,p=%p$%b$%^h",
		"v=16$", "v=19$", "", NULL,
		RANGE(LIBAR2_MIN_M_COST, LIBAR2_MAX_M_COST),
		RANGE(LIBAR2_MIN_T_COST, LIBAR2_MAX_T_COST),
		RANGE(LIBAR2_MIN_LANES, LIBAR2_MAX_LANES),
		RANGE(LIBAR2_MIN_SALTLEN, LIBAR2_MAX_SALTLEN), BASE64,
		&hashsize, RANGE(LIBAR2_MIN_HASHLEN, LIBAR2_MAX_HASHLEN), BASE64);
	if (!r)
		return 0;

	/* Return hash size */
	if (!hashsize)
		hashsize = argon2__HASH_SIZE;
	*len_out = (size_t)hashsize;

	/* Check password size */
#if SIZE_MAX > UINT32_MAX
	return len <= UINT32_MAX;
#else
	(void) len;
	return 1;
#endif
}


#else


CONST int
main(void)
{
	return 0;
}


#endif
/* TODO test */
