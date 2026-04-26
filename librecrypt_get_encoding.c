/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const void *
librecrypt_get_encoding(const char *settings, size_t len, char *pad_out, int *strict_pad_out, int decoding)
{
	size_t i, start = 0u;
	const struct algorithm *algo;

	for (i = 0u; i < len; i++)
		if (settings[i] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
			start = i + 1u;
	settings = &settings[start];
	len -= start;

	algo = librecrypt_find_first_algorithm_(settings, len);
	if (!algo) {
		errno = ENOSYS;
		return NULL;
	}

	*pad_out = algo->pad;
	*strict_pad_out = algo->strict_pad;
	if (decoding)
		return algo->decoding_lut;
	else
		return algo->encoding_lut;
}


#else


int
main(void)
{
	SET_UP_ALARM();

	return 0;
}


#endif
/* TODO test */
