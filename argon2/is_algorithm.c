/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST


#define DECLARE_IS_ALGORITHM(ALGO)\
	unsigned\
	librecrypt__##ALGO##__is_algorithm(const char *settings, size_t len)\
	{\
		return len >= sizeof("$"#ALGO"$") - 1u && !strncmp(settings, "$"#ALGO"$", sizeof("$"#ALGO"$") - 1u);\
	}

IF__argon2i__SUPPORTED(DECLARE_IS_ALGORITHM(argon2i))
IF__argon2d__SUPPORTED(DECLARE_IS_ALGORITHM(argon2d))
IF__argon2id__SUPPORTED(DECLARE_IS_ALGORITHM(argon2id))
IF__argon2ds__SUPPORTED(DECLARE_IS_ALGORITHM(argon2ds))


#else


#define CHECK(ALGO, PREFIX, SUFFIX, RET)\
	EXPECT(librecrypt__##ALGO##__is_algorithm(PREFIX SUFFIX, sizeof(PREFIX) - 1u) == (RET))


int
main(void)
{
#if defined(SUPPORT_ARGON2I)
	CHECK(argon2i, "", "", 0u);
	CHECK(argon2i, "$argon2$", "", 0u);
	CHECK(argon2i, "$argon2i", "$", 0u);
	CHECK(argon2i, "$argon2i$", "", 1u);
	CHECK(argon2i, "$ARGON2I$", "", 0u);
	CHECK(argon2i, "$argon2i$x", "", 1u);
	CHECK(argon2i, "$argon2d$", "", 0u);
	CHECK(argon2i, "$argon2id$", "", 0u);
	CHECK(argon2i, "$argon2ds$", "", 0u);
#endif

#if defined(SUPPORT_ARGON2D)
	CHECK(argon2d, "", "", 0u);
	CHECK(argon2d, "$argon2$", "", 0u);
	CHECK(argon2d, "$argon2d", "$", 0u);
	CHECK(argon2d, "$argon2d$", "", 1u);
	CHECK(argon2d, "$ARGON2D$", "", 0u);
	CHECK(argon2d, "$argon2d$x", "", 1u);
	CHECK(argon2d, "$argon2i$", "", 0u);
	CHECK(argon2d, "$argon2id$", "", 0u);
	CHECK(argon2d, "$argon2ds$", "", 0u);
#endif

#if defined(SUPPORT_ARGON2ID)
	CHECK(argon2id, "", "", 0u);
	CHECK(argon2id, "$argon2$", "", 0u);
	CHECK(argon2id, "$argon2id", "$", 0u);
	CHECK(argon2id, "$argon2id$", "", 1u);
	CHECK(argon2id, "$ARGON2ID$", "", 0u);
	CHECK(argon2id, "$argon2id$x", "", 1u);
	CHECK(argon2id, "$argon2i$", "", 0u);
	CHECK(argon2id, "$argon2d$", "", 0u);
	CHECK(argon2id, "$argon2ds$", "", 0u);
#endif

#if defined(SUPPORT_ARGON2DS)
	CHECK(argon2ds, "", "", 0u);
	CHECK(argon2ds, "$argon2$", "", 0u);
	CHECK(argon2ds, "$argon2ds", "$", 0u);
	CHECK(argon2ds, "$argon2ds$", "", 1u);
	CHECK(argon2ds, "$ARGON2DS$", "", 0u);
	CHECK(argon2ds, "$argon2ds$x", "", 1u);
	CHECK(argon2ds, "$argon2i$", "", 0u);
	CHECK(argon2ds, "$argon2d$", "", 0u);
	CHECK(argon2ds, "$argon2id$", "", 0u);
#endif

	return 0;
}


#endif
