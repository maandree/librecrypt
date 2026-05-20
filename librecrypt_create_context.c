/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


LIBRECRYPT_CONTEXT *
librecrypt_create_context(void)
{
	LIBRECRYPT_CONTEXT *ret;
	size_t i;

	ret = calloc(1u, sizeof(*ret));
	if (!ret)
		return NULL;

	/* calloc, sets all bytes to 0, but NULL isn't necessarily
	 * presented by all zeroes even though assigning 0 to a
	 * pointer assigns it NULL, therefore we have to manually
	 * set all pointers to NULL; just to be defensive, we
	 * set all pointers to NULL, even ones that have a length
	 * (zeroed) associated with them */

	ret->user_data = NULL;
	for (i = 0u; i < ELEMSOF(ret->peppers); i++)
		ret->peppers[i].data = NULL;

	return ret;
}


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* TODO test */

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
