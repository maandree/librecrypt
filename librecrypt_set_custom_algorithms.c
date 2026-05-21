/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
librecrypt_set_custom_algorithms(LIBRECRYPT_CONTEXT *ctx, const struct librecrypt_algorithm *algos, size_t nalgos)
{
	ctx->algos = algos;
	ctx->nalgos = nalgos;
}


#else


int
main(void)
{
	LIBRECRYPT_CONTEXT *ctx;
	struct librecrypt_algorithm algos[5];

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

	EXPECT(ctx->algos == NULL);
	EXPECT(ctx->nalgos == 0u);
	librecrypt_set_custom_algorithms(ctx, algos, 5u);
	EXPECT(ctx->algos == algos);
	EXPECT(ctx->nalgos == 5u);
	librecrypt_set_custom_algorithms(ctx, algos, 5u);
	EXPECT(ctx->algos == algos);
	EXPECT(ctx->nalgos == 5u);
	librecrypt_set_custom_algorithms(ctx, algos, 4u);
	EXPECT(ctx->algos == algos);
	EXPECT(ctx->nalgos == 4u);
	librecrypt_set_custom_algorithms(ctx, NULL, 0u);
	EXPECT(ctx->algos == NULL);
	EXPECT(ctx->nalgos == 0u);

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
