/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_hash_binary(void *restrict out_buffer, size_t size, const char *phrase,
                       size_t len, const char *settings, LIBRECRYPT_CONTEXT *ctx)
{
	return librecrypt_hash_(out_buffer, size, phrase, len, settings, ctx, BINARY_HASH);
}


#else


#define SP4 "    "
#define SP20 SP4 SP4 SP4 SP4 SP4
#define SP80 SP20 SP20 SP20 SP20
#define SP84 SP80 SP4

#define GET_ARGON2_SCRATCH_SIZE(HASHLEN) ((HASHLEN) > 64u ? ((HASHLEN) + 63u) & ~31u : (HASHLEN))


static void
check(const char *phrase, const char *settings, const char *chain, const char *hash,
      size_t hashlen, size_t scratchsize, LIBRECRYPT_CONTEXT *ctx)
{
	size_t len = strlen(phrase);
	char buf[1024], buf2[sizeof(buf)], expected[256], pad;
	int strict_pad;
	const void *lut;
	ssize_t r;

	assert(hashlen <= sizeof(buf));
	assert(hashlen <= sizeof(expected));

	lut = librecrypt_get_encoding(settings, strlen(settings), &pad, &strict_pad, 1, ctx);
	assert(lut);

	r = librecrypt_decode(expected, sizeof(expected), hash, strlen(hash), lut, pad, strict_pad);
	assert(r > 0 && (size_t)r == hashlen);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash_binary(buf, sizeof(buf), phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(buf, expected, hashlen));
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash_binary(buf, hashlen, phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(buf, expected, hashlen));
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash_binary(buf, 1u, phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(buf, expected, 1u));
	CANARY_X_CHECK(buf, 1u, 1u);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash_binary(buf, 0u, phrase, len, settings, ctx) == (ssize_t)hashlen);
	CANARY_X_CHECK(buf, 0u, 0u);
	EXPECT(librecrypt_hash_binary(NULL, 0u, phrase, len, settings, ctx) == (ssize_t)hashlen);

	CANARY_FILL(buf);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_hash_binary(buf, sizeof(buf), expected, hashlen, settings, ctx) == (ssize_t)hashlen);
	errno = 0;
	EXPECT(librecrypt_hash_binary(buf2, sizeof(buf2), phrase, len, chain, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(buf, buf2, hashlen));
	CANARY_X_CHECK(buf, hashlen, scratchsize);
	CANARY_X_CHECK(buf2, hashlen, scratchsize);
}


#define CHECK(PHRASE, CONF, HASHLEN, IS_DEFAULT_HASHLEN, HASH)\
	do {\
		size_t scratchsize = GET_SCRATCH_SIZE(HASHLEN);\
		check(PHRASE, CONF HASH, CONF "*" #HASHLEN ">" CONF HASH, HASH, (size_t)HASHLEN, scratchsize, ctx);\
		check(PHRASE, CONF "*" #HASHLEN, CONF "*" #HASHLEN ">" CONF "*" #HASHLEN, HASH, (size_t)HASHLEN, scratchsize, ctx);\
		if (IS_DEFAULT_HASHLEN)\
			check(PHRASE, CONF, CONF ">" CONF, HASH, (size_t)HASHLEN, scratchsize, ctx);\
	} while (0)


#define CHECK_BAD(ALGO)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_hash_binary(NULL, 0u, NULL, 0u, ALGO"m=0,t=999999999999999999,p=0$AAAABBBB$*0", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash_binary(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$*32$", ctx) == -1);\
		EXPECT(errno == EINVAL);\
	} while (0)


int
main(void)
{
	LIBRECRYPT_CONTEXT *ctx = NULL;
	char nuls[256];

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#define GET_SCRATCH_SIZE(HASHLEN) GET_ARGON2_SCRATCH_SIZE(HASHLEN)
#if defined(SUPPORT_ARGON2I)
# if defined(SUPPORT_ARGON2_V1_0)
	CHECK("password",  "$argon2i$"   "m=256,t=2,p=1$c29tZXNhbHQ$",  32, 1, "/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
# endif
# if defined(SUPPORT_ARGON2_V1_3)
	CHECK("password",  "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$",  32, 1, "iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
# endif
	CHECK_BAD("$argon2i$");
#endif
#if defined(SUPPORT_ARGON2ID)
# if defined(SUPPORT_ARGON2_V1_3)
	CHECK("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$",  32, 1, "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4");
# endif
	CHECK_BAD("$argon2id$");
#endif
#if defined(SUPPORT_ARGON2DS)
# if defined(SUPPORT_ARGON2_V1_0)
	CHECK("",         "$argon2ds$v=16$m=""8,t=1,p=1$ICAgICAgICA$",  32, 1, "zgdykk9ZjN5VyrW0LxGw8LmrJ1Z6fqSC+3jPQtn4n0s");
# endif
	CHECK_BAD("$argon2ds$");
#endif
#if defined(SUPPORT_ARGON2D)
# if defined(SUPPORT_ARGON2_V1_0)
	CHECK("",          "$argon2d$v=16$m=""8,t=1,p=1$ICAgICAgICA$", 100, 0, "NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9"
	                                                                       "n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdE"
	                                                                       "yLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");
# endif
	CHECK_BAD("$argon2d$");
#endif
#undef GET_SCRATCH_SIZE

	ctx = librecrypt_create_context();
	assert(ctx != NULL);
	memset(nuls, 0, sizeof(nuls));

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2_V1_3)
# define GET_SCRATCH_SIZE(HASHLEN) GET_ARGON2_SCRATCH_SIZE(HASHLEN)
	assert(sizeof(nuls) >= 4u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 4u) == 0);
	CHECK(" ",  "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "Mhl4o3AkJuA");
	CHECK(SP84, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "+hlEcRn+F3s");
	CHECK(SP80, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "z2d6ce8UqS0");

	assert(sizeof(nuls) >= 140u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 140u) == 0);
	CHECK(SP80, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "15FAGe1KIX8");

	assert(sizeof(nuls) >= 160u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 160u) == 0);
	CHECK(SP80, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "oH3H5atuca8");

	assert(sizeof(nuls) >= 128u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 128u) == 0);
	CHECK(SP80, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "TsimqI1YC08");

	assert(sizeof(nuls) >= 256u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 256u) == 0);
	CHECK(SP80, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$", 8, 0, "mzPlVOVjVos");
# undef GET_SCRATCH_SIZE
#endif

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
