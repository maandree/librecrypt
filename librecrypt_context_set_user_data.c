/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
librecrypt_context_set_user_data(LIBRECRYPT_CONTEXT *ctx, void *user)
{
	ctx->user_data = user;
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
