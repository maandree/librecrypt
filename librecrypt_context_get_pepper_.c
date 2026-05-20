/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


struct pepper *
librecrypt_context_get_pepper_(LIBRECRYPT_CONTEXT *ctx, enum librecrypt_hash_algorithm algo, size_t len)
{
	struct pepper *pepper;
	size_t index = (size_t)algo;

	switch (algo) {

#if defined(SUPPORT_ARGON2I) || defined(SUPPORT_ARGON2D) || defined(SUPPORT_ARGON2ID) ||  defined(SUPPORT_ARGON2DS)
# if defined(SUPPORT_ARGON2I)
	case LIBRECRYPT_ARGON2I_V1_0:
	case LIBRECRYPT_ARGON2I_V1_3:
# endif
# if defined(SUPPORT_ARGON2D)
	case LIBRECRYPT_ARGON2D_V1_0:
	case LIBRECRYPT_ARGON2D_V1_3:
# endif
# if defined(SUPPORT_ARGON2ID)
	case LIBRECRYPT_ARGON2ID_V1_0:
	case LIBRECRYPT_ARGON2ID_V1_3:
# endif
# if defined(SUPPORT_ARGON2DS)
	case LIBRECRYPT_ARGON2DS_V1_0:
	case LIBRECRYPT_ARGON2DS_V1_3:
# endif
# if SIZE_MAX > UINT32_MAX /* LIBAR2_MAX_KEYLEN is just UINT32_MAX cast to size_t; keep it simple: don't include <libar2.h> */
		if (len > UINT32_MAX) {
			errno = EINVAL;
			return NULL;
		}
# endif
		return &ctx->peppers[algo];
#endif

	default:
		errno = ENOSYS;
		return NULL;
	}
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
