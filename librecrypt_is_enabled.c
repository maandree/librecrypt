/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#define INCLUDE(ALGO, VAL) IF__##ALGO##__SUPPORTED((UINT64_C(1) << (VAL)) |)

static const uint64_t enabled =
	INCLUDE(argon2i_v1_0, LIBRECRYPT_ARGON2I_V1_0)
	INCLUDE(argon2i_v1_3, LIBRECRYPT_ARGON2I_V1_3)
	INCLUDE(argon2d_v1_0, LIBRECRYPT_ARGON2D_V1_0)
	INCLUDE(argon2d_v1_3, LIBRECRYPT_ARGON2D_V1_3)
	INCLUDE(argon2id_v1_0, LIBRECRYPT_ARGON2ID_V1_0)
	INCLUDE(argon2id_v1_3, LIBRECRYPT_ARGON2ID_V1_3)
	INCLUDE(argon2ds_v1_0, LIBRECRYPT_ARGON2DS_V1_0)
	INCLUDE(argon2ds_v1_3, LIBRECRYPT_ARGON2DS_V1_3)
	UINT64_C(0);


int
librecrypt_is_enabled(enum librecrypt_hash_algorithm algo)
{
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wtautological-unsigned-enum-zero-compare"
#endif

	if (algo < 0 || algo >= 64)
		return 0;

#if defined(__clang__)
# pragma clang diagnostic pop
#endif

	/* Version 1.0 and 1.3 of Argon2 are supported in all
	 * versions of libar2, so there is no need to check
	 * libar2_latest_argon2_version. For the reference
	 * implementation of Argon2, the it's algorithms marked
	 * as supported depend on which version of the reference
	 * implementation is used (unfortunately the reference
	 * implementation isn't properly designed as a library). */

	return (int)(enabled >> (unsigned)algo) & 1;
}


#else


#if defined(__clang__)
# pragma clang diagnostic ignored "-Wassign-enum"
# pragma clang diagnostic ignored "-Wsign-conversion"
#endif


#define CHECK(ALGO, EXPECTED)\
	do {\
		EXPECT(librecrypt_is_enabled(ALGO) == (EXPECTED));\
		if ((int)(ALGO) > highest)\
			highest = (int)(ALGO);\
	} while (0)


int
main(void)
{
	int i, highest = -1;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	CHECK((enum librecrypt_hash_algorithm)-1, 0);
	CHECK(LIBRECRYPT_ARGON2I_V1_0, IF__argon2i_v1_0__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2I_V1_3, IF__argon2i_v1_3__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2D_V1_0, IF__argon2d_v1_0__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2D_V1_3, IF__argon2d_v1_3__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2ID_V1_0, IF__argon2id_v1_0__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2ID_V1_3, IF__argon2id_v1_3__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2DS_V1_0, IF__argon2ds_v1_0__SUPPORTED(1 + ) 0);
	CHECK(LIBRECRYPT_ARGON2DS_V1_3, IF__argon2ds_v1_3__SUPPORTED(1 + ) 0);
	assert((enum librecrypt_hash_algorithm)(highest + 1) == LIBRECRYPT_HASH_ALGORITHM_END);

	for (i = 0; i < 1024 && highest != INT_MAX; i++)
		CHECK((enum librecrypt_hash_algorithm)(highest + 1), 0);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
