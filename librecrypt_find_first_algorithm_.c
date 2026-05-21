/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const struct librecrypt_algorithm *
librecrypt_find_first_algorithm_(const char *settings, size_t len, LIBRECRYPT_CONTEXT *ctx)
{
	unsigned r, priority = 0;
	const struct librecrypt_algorithm *algo, *found = NULL;
	size_t i;

	/* Search application provided hash functions first;
	 * they should have priority of they report the same
	 * priority as library-provided hash functions */
	if (!ctx)
		goto library_provided;
	/* TODO test */
	for (i = 0u; i < ctx->nalgos; i++) {
		algo = &ctx->algos[i];
		r = (*algo->is_algorithm)(settings, len);
		if (r > priority) {
			priority = r;
			found = algo;
		}
	}

library_provided:
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


#define NSA "$~no~such~algorithm~$"


#define CHECK(ALGO)\
	do {\
		algo = librecrypt_find_first_algorithm_(ALGO, sizeof(ALGO) - 1u, NULL);\
		EXPECT(algo != NULL);\
		EXPECT((*algo->is_algorithm)(ALGO, sizeof(ALGO) - 1u) > 0u);\
		EXPECT(librecrypt_find_first_algorithm_(ALGO">"NSA, sizeof(ALGO">"NSA) - 1u, NULL) == algo);\
	} while (0)


int
main(void)
{
	const struct librecrypt_algorithm *algo;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	EXPECT(librecrypt_find_first_algorithm_(NSA, sizeof(NSA) - 1u, NULL) == NULL);
	EXPECT(librecrypt_find_first_algorithm_(NSA">", sizeof(NSA">") - 1u, NULL) == NULL);

	IF__argon2i__SUPPORTED(CHECK("$argon2i$"));
	IF__argon2d__SUPPORTED(CHECK("$argon2d$"));
	IF__argon2id__SUPPORTED(CHECK("$argon2id$"));
	IF__argon2ds__SUPPORTED(CHECK("$argon2ds$"));

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
