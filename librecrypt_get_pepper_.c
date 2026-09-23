/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wswitch-enum"
#endif


struct pepper *
librecrypt_get_pepper_(LIBRECRYPT_CONTEXT *ctx, enum librecrypt_hash_algorithm algo, size_t len)
{
	switch (algo) {

#if defined(SUPPORT_ARGON2I) || defined(SUPPORT_ARGON2D) || defined(SUPPORT_ARGON2ID) ||  defined(SUPPORT_ARGON2DS)
	IF__argon2i_v1_0__SUPPORTED(case LIBRECRYPT_ARGON2I_V1_0:)
	IF__argon2i_v1_3__SUPPORTED(case LIBRECRYPT_ARGON2I_V1_3:)
	IF__argon2d_v1_0__SUPPORTED(case LIBRECRYPT_ARGON2D_V1_0:)
	IF__argon2d_v1_3__SUPPORTED(case LIBRECRYPT_ARGON2D_V1_3:)
	IF__argon2id_v1_0__SUPPORTED(case LIBRECRYPT_ARGON2ID_V1_0:)
	IF__argon2id_v1_3__SUPPORTED(case LIBRECRYPT_ARGON2ID_V1_3:)
	IF__argon2ds_v1_0__SUPPORTED(case LIBRECRYPT_ARGON2DS_V1_0:)
	IF__argon2ds_v1_3__SUPPORTED(case LIBRECRYPT_ARGON2DS_V1_3:)
# if SIZE_MAX > UINT32_MAX /* LIBAR2_MAX_KEYLEN is just UINT32_MAX cast to size_t; keep it simple: don't include <libar2.h> */
		if (len > UINT32_MAX) {
			errno = EINVAL;
			return NULL;
		}
# endif
		(void) len;
		return &ctx->peppers[algo];
#endif

	default:
		errno = ENOSYS;
		return NULL;
	}
}


#else


#define CHECK_DISABLED(ALGO)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_get_pepper_(ctx, ALGO, 0u) == NULL);\
		EXPECT(errno == ENOSYS);\
		errno = 0;\
		EXPECT(librecrypt_get_pepper_(ctx, ALGO, 1u) == NULL);\
		EXPECT(errno == ENOSYS);\
		errno = 0;\
		EXPECT(librecrypt_get_pepper_(ctx, ALGO, 64u) == NULL);\
		EXPECT(errno == ENOSYS);\
		errno = 0;\
		EXPECT(librecrypt_get_pepper_(ctx, ALGO, SIZE_MAX) == NULL);\
		EXPECT(errno == ENOSYS);\
	} while (0)

#define CHECK_ARGON2_(ALGO)\
	do {\
		pepper = librecrypt_get_pepper_(ctx, ALGO, 0u);\
		EXPECT(pepper != NULL);\
		EXPECT(pepper->data == NULL);\
		EXPECT(pepper->len == 0u);\
		pepper = librecrypt_get_pepper_(ctx, ALGO, 1u);\
		EXPECT(pepper != NULL);\
		EXPECT(pepper->data == NULL);\
		EXPECT(pepper->len == 0u);\
		pepper = librecrypt_get_pepper_(ctx, ALGO, UINT32_MAX);\
		EXPECT(pepper != NULL);\
		EXPECT(pepper->data == NULL);\
		EXPECT(pepper->len == 0u);\
	} while (0)

#if SIZE_MAX > UINT32_MAX
# define CHECK_ARGON2(ALGO)\
	do {\
		CHECK_ARGON2_(ALGO);\
		errno = 0;\
		EXPECT(librecrypt_get_pepper_(ctx, ALGO, (size_t)UINT32_MAX + 1u) == NULL);\
		EXPECT(errno == EINVAL);\
	} while (0)
#else
# define CHECK_ARGON2(ALGO) CHECK_ARGON2_(ALGO)
#endif


int
main(void)
{
	LIBRECRYPT_CONTEXT *ctx;
	struct pepper *pepper;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2_V1_0)
	CHECK_ARGON2(LIBRECRYPT_ARGON2I_V1_0);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2I_V1_0);
#endif

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2_V1_3)
	CHECK_ARGON2(LIBRECRYPT_ARGON2I_V1_3);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2I_V1_3);
#endif

#if defined(SUPPORT_ARGON2D) && defined(SUPPORT_ARGON2_V1_0)
	CHECK_ARGON2(LIBRECRYPT_ARGON2D_V1_0);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2D_V1_0);
#endif

#if defined(SUPPORT_ARGON2D) && defined(SUPPORT_ARGON2_V1_3)
	CHECK_ARGON2(LIBRECRYPT_ARGON2D_V1_3);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2D_V1_3);
#endif

#if defined(SUPPORT_ARGON2ID) && defined(SUPPORT_ARGON2_V1_0)
	CHECK_ARGON2(LIBRECRYPT_ARGON2ID_V1_0);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2ID_V1_0);
#endif

#if defined(SUPPORT_ARGON2ID) && defined(SUPPORT_ARGON2_V1_3)
	CHECK_ARGON2(LIBRECRYPT_ARGON2ID_V1_3);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2ID_V1_3);
#endif

#if defined(SUPPORT_ARGON2DS) && defined(SUPPORT_ARGON2_V1_0)
	CHECK_ARGON2(LIBRECRYPT_ARGON2DS_V1_0);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2DS_V1_0);
#endif

#if defined(SUPPORT_ARGON2DS) && defined(SUPPORT_ARGON2_V1_3)
	CHECK_ARGON2(LIBRECRYPT_ARGON2DS_V1_3);
#else
	CHECK_DISABLED(LIBRECRYPT_ARGON2DS_V1_3);
#endif

	CHECK_DISABLED(LIBRECRYPT_HASH_ALGORITHM_END);

	/* Further tested in librecrypt_set_pepper.c */

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
