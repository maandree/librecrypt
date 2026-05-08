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
		/* Get next algorithm in the list */
		algo = &librecrypt_algorithms_[i];
		if (IS_END_OF_ALGORITHMS(algo))
			break;

		/* Get match-priority, bigger is more prioritised,
		 * 0 is non-match, so we save if we get a bigger
		 * value then our current best (we start at 0
		 * (no match found)) */
		r = (*algo->is_algorithm)(settings, len);
		if (r > priority) {
			priority = r;
			found = algo;
		}
	}

	/* NULL if all `is_algorithm` returned 0 (including if the
	 * last was completly empty), otherwise the first one
	 * (actually an arbitrary one) that returned the greated
	 * match-priority (which doesn't necessarily mean it's better,
	 * which is why we don't just break at the first match
	 * (`librecrypt_algorithms_` is ordered by how good they are)) */
	return found;
}


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
/* TODO test */
