/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const struct algorithm *
librecrypt_find_first_algorithm_(const char *settings, size_t len)
{
	unsigned r, priority = 0;
	const struct algorithm *algo, *found = NULL;
	size_t i;

	for (i = 0u;; i++) {
		algo = &librecrypt_algorithms_[i];
		if (IS_END_OF_ALGORITHMS(algo))
			break;
		r = (*algo->is_algorithm)(settings, len);
		if (r > priority) {
			priority = r;
			found = algo;
		}
	}

	return found;
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
