/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
librecrypt_set_user_data(LIBRECRYPT_CONTEXT *ctx, void *user)
{
	ctx->user_data = user;
}


#else


extern LIBRECRYPT_CONTEXT *volatile ctx;
LIBRECRYPT_CONTEXT *volatile ctx;


int
main(void)
{
	char *user = &(char){0};

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

	EXPECT(librecrypt_get_user_data(ctx) == NULL);
	EXPECT(librecrypt_get_user_data(ctx) == NULL);
	librecrypt_set_user_data(ctx, user);
	EXPECT(librecrypt_get_user_data(ctx) == user);
	EXPECT(librecrypt_get_user_data(ctx) == user);
	librecrypt_set_user_data(ctx, user);
	librecrypt_set_user_data(ctx, NULL);
	EXPECT(librecrypt_get_user_data(ctx) == NULL);
	EXPECT(librecrypt_get_user_data(ctx) == NULL);
	librecrypt_set_user_data(ctx, NULL);

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
