/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
librecrypt_free_context(LIBRECRYPT_CONTEXT *ctx)
{
	librecrypt_wipe(ctx, sizeof(*ctx));
	free(ctx);
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
