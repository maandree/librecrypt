/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void *
librecrypt_get_user_data(const LIBRECRYPT_CONTEXT *ctx)
{
	return ctx->user_data;
}


#else


CONST int
main(void)
{
	/* Tested in librecrypt_set_user_data.c */
	return 0;
}


#endif
