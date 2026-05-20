/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void *
librecrypt_context_get_user_data(LIBRECRYPT_CONTEXT *ctx)
{
	return ctx->user_data;
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
