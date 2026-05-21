/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
librecrypt_free_context(LIBRECRYPT_CONTEXT *ctx)
{
	if (!ctx)
		return;
	librecrypt_wipe(ctx, sizeof(*ctx));
	free(ctx);
}


#else


CONST int
main(void)
{
	/* Tested in other files */
	librecrypt_free_context(NULL);
	return 0;
}


#endif
