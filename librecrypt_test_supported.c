/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_test_supported(const char *phrase, size_t len, int text, const char *settings)
{
	const struct algorithm *algo;
	size_t n;

	/* For each chained algorithm*/
	for (;;) {
		/* Measure until next '>' */
		for (n = 0u; settings[n]; n++)
			if (settings[n] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;

		/* Identify algorithm */
		algo = librecrypt_find_first_algorithm_(settings, n);
		if (!algo)
			return 0;

		/* Check configuration and input support, and get hash size */
		if (!(*algo->test_supported)(phrase, len, text, settings, n, &len))
			return 0;

		/* Return just process last chained algorithm */
		if (!settings[n])
			return 1;

		/* Hashes are binary */
		phrase = NULL;
		text = 0;

		/* Goto next algorithm */
		settings = &settings[n]; /* conf */
		settings++; /* '>' */
	}
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
