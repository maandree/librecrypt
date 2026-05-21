/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const enum librecrypt_hash_algorithm librecrypt_hash_algorithm_end = LIBRECRYPT_HASH_ALGORITHM_END;


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	assert(librecrypt_hash_algorithm_end == LIBRECRYPT_HASH_ALGORITHM_END);
	/* LIBRECRYPT_HASH_ALGORITHM_END having the corret value is tested
	 * in librecrypt_is_enabled.c */

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
