/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_context_set_pepper(LIBRECRYPT_CONTEXT *ctx, enum librecrypt_hash_algorithm algo, const void *data, size_t len)
{
	struct pepper *pepper;

	pepper = librecrypt_context_get_pepper_(ctx, algo, len);
	if (!pepper)
		return -1;

	pepper->data = data;
	pepper->len = len;
	return 0;
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
