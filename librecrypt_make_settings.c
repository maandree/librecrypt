/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_make_settings(char *out_buffer, size_t size, const char *algorithm, size_t memcost, uintmax_t timecost,
                         int gensalt, ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	const struct algorithm *algo;

	/* Get algorithm */
	if (!algorithm) {
		/* Select best algorithm if `NULL` is specified */
		algo = &librecrypt_algorithms_[0];
		if (IS_END_OF_ALGORITHMS(algo))
			goto enosys;
	} else {
		/* Verify single, unchained algorithm is specified if not `NULL`*/
		if (strchr(algorithm, LIBRECRYPT_ALGORITHM_LINK_DELIMITER)) {
			errno = EINVAL;
			return -1;
		}
		/* Identify the algorithm */
		algo = librecrypt_find_first_algorithm_(algorithm, strlen(algorithm));
		if (!algo)
			goto enosys;
	}

	/* Use default random number generator if none was specified */
	if (!rng)
		rng = &librecrypt_rng_;

	/* Configure */
	return (*algo->make_settings)(out_buffer, size, algorithm, memcost, timecost, gensalt, rng, user);

enosys:
	errno = ENOSYS;
	return -1;
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
