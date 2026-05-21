/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_set_pepper(LIBRECRYPT_CONTEXT *ctx, enum librecrypt_hash_algorithm algo, const void *data, size_t len)
{
	struct pepper *pepper;

	pepper = librecrypt_get_pepper_(ctx, algo, len);
	if (!pepper)
		return -1;

	pepper->data = data;
	pepper->len = len;
	return 0;
}


#else


#define CHECK_ENOSYS(ALGO, DATA, LEN)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_set_pepper(ctx, ALGO, DATA, LEN) == -1);\
		EXPECT(errno == ENOSYS);\
	} while (0)

#define CHECK_EINVAL(ALGO, DATA, LEN)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_set_pepper(ctx, ALGO, DATA, LEN) == -1);\
		EXPECT(errno == EINVAL);\
	} while (0)

#define SET_PEPPER(ALGO, DATA, LEN)\
	EXPECT(librecrypt_set_pepper(ctx, ALGO, DATA, LEN) == 0)

#define CHECK_PEPPER(ALGO, DATA, LEN)\
	do {\
		pepper = librecrypt_get_pepper_(ctx, ALGO, 0u);\
		EXPECT(pepper != NULL);\
		EXPECT(pepper->data == (DATA));\
		EXPECT(pepper->len == (LEN));\
	} while (0)


int
main(void)
{
	LIBRECRYPT_CONTEXT *ctx;
	char a2i10 = 1, a2d10 = 2, a2id10 = 3, a2ds10 = 4;
	char a2i13 = 5, a2d13 = 6, a2id13 = 7, a2ds13 = 8;
	struct pepper *pepper;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	ctx = librecrypt_create_context();
	assert(ctx != NULL);


#if defined(SUPPORT_ARGON2I)
	SET_PEPPER(LIBRECRYPT_ARGON2I_V1_0, &a2i10, 2u);
	SET_PEPPER(LIBRECRYPT_ARGON2I_V1_3, &a2i13, 5u);
# if SIZE_MAX > UINT32_MAX
	CHECK_EINVAL(LIBRECRYPT_ARGON2I_V1_0, NULL, (size_t)UINT32_MAX + 1u);
	CHECK_EINVAL(LIBRECRYPT_ARGON2I_V1_3, NULL, (size_t)UINT32_MAX + 1u);
# endif
#else
	CHECK_ENOSYS(LIBRECRYPT_ARGON2I_V1_0, &a2i10, 2u);
	CHECK_ENOSYS(LIBRECRYPT_ARGON2I_V1_3, &a2i13, 5u);
#endif

#if defined(SUPPORT_ARGON2D)
	SET_PEPPER(LIBRECRYPT_ARGON2D_V1_0, &a2d10, 3u);
	SET_PEPPER(LIBRECRYPT_ARGON2D_V1_3, &a2d13, 8u);
# if SIZE_MAX > UINT32_MAX
	CHECK_EINVAL(LIBRECRYPT_ARGON2D_V1_0, NULL, (size_t)UINT32_MAX + 1u);
	CHECK_EINVAL(LIBRECRYPT_ARGON2D_V1_3, NULL, (size_t)UINT32_MAX + 1u);
# endif
#else
	CHECK_ENOSYS(LIBRECRYPT_ARGON2D_V1_0, &a2d10, 3u);
	CHECK_ENOSYS(LIBRECRYPT_ARGON2D_V1_3, &a2d13, 8u);
#endif

#if defined(SUPPORT_ARGON2ID)
	SET_PEPPER(LIBRECRYPT_ARGON2ID_V1_0, &a2id10, 7u);
	SET_PEPPER(LIBRECRYPT_ARGON2ID_V1_3, &a2id13, 4u);
# if SIZE_MAX > UINT32_MAX
	CHECK_EINVAL(LIBRECRYPT_ARGON2ID_V1_0, NULL, (size_t)UINT32_MAX + 1u);
	CHECK_EINVAL(LIBRECRYPT_ARGON2ID_V1_3, NULL, (size_t)UINT32_MAX + 1u);
# endif
#else
	CHECK_ENOSYS(LIBRECRYPT_ARGON2ID_V1_0, &a2id10, 7u);
	CHECK_ENOSYS(LIBRECRYPT_ARGON2ID_V1_3, &a2id13, 4u);
#endif

#if defined(SUPPORT_ARGON2DS)
	SET_PEPPER(LIBRECRYPT_ARGON2DS_V1_0, &a2ds10, 9u);
	SET_PEPPER(LIBRECRYPT_ARGON2DS_V1_3, &a2ds13, 6u);
# if SIZE_MAX > UINT32_MAX
	CHECK_EINVAL(LIBRECRYPT_ARGON2DS_V1_0, NULL, (size_t)UINT32_MAX + 1u);
	CHECK_EINVAL(LIBRECRYPT_ARGON2DS_V1_3, NULL, (size_t)UINT32_MAX + 1u);
# endif
#else
	CHECK_ENOSYS(LIBRECRYPT_ARGON2DS_V1_0, &a2ds10, 9u);
	CHECK_ENOSYS(LIBRECRYPT_ARGON2DS_V1_3, &a2ds13, 6u);
#endif


	CHECK_ENOSYS(LIBRECRYPT_HASH_ALGORITHM_END, NULL, 0u);
	CHECK_ENOSYS(LIBRECRYPT_HASH_ALGORITHM_END, &(char){4}, 32u);


#if defined(SUPPORT_ARGON2I)
	CHECK_PEPPER(LIBRECRYPT_ARGON2I_V1_0, &a2i10, 2u);
	CHECK_PEPPER(LIBRECRYPT_ARGON2I_V1_3, &a2i13, 5u);
#endif
#if defined(SUPPORT_ARGON2D)
	CHECK_PEPPER(LIBRECRYPT_ARGON2D_V1_0, &a2d10, 3u);
	CHECK_PEPPER(LIBRECRYPT_ARGON2D_V1_3, &a2d13, 8u);
#endif
#if defined(SUPPORT_ARGON2ID)
	CHECK_PEPPER(LIBRECRYPT_ARGON2ID_V1_0, &a2id10, 7u);
	CHECK_PEPPER(LIBRECRYPT_ARGON2ID_V1_3, &a2id13, 4u);
#endif
#if defined(SUPPORT_ARGON2DS)
	CHECK_PEPPER(LIBRECRYPT_ARGON2DS_V1_0, &a2ds10, 9u);
	CHECK_PEPPER(LIBRECRYPT_ARGON2DS_V1_3, &a2ds13, 6u);
#endif


	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
