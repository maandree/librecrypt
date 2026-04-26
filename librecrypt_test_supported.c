/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_test_supported(const char *phrase, size_t len, int text, const char *settings)
{
	const struct algorithm *algo;
	size_t n, prefix;
	int has_next;

	for (;;) {
		has_next = 0;
		for (n = 0u; settings[n]; n++) {
			if (settings[n] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER) {
				has_next = 1;
				break;
			}
		}

		algo = librecrypt_find_first_algorithm_(settings, n);
		if (!algo)
			return 0;

		prefix = (*algo->get_prefix)(settings, n);
		if (has_next && prefix < n)
			return 0;

		if (!(*algo->test_supported)(phrase, len, text, settings, prefix))
			return 0;

		if (!has_next)
			return 1;

		phrase = NULL;
		len = algo->hash_size;
		text = 0;

		settings = &settings[n];
		settings++;
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
