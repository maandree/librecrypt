/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len, const char *settings, void *reserved)
{
	return librecrypt_hash_(out_buffer, size, phrase, len, settings, reserved, ASCII_HASH);
}


#else


static void
check(const char *phrase, const char *settings, const char *chain, const char *hash, size_t scratchsize)
{
	size_t hashlen = strlen(hash);
	size_t len = strlen(phrase);
	char buf[1024], buf2[sizeof(buf)], expected[256], pad;
	int strict_pad;
	const void *lut;
	ssize_t r;

	assert(hashlen <= sizeof(buf));
	assert(hashlen < sizeof(expected));

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, sizeof(buf), phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 1u, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, hashlen + 1u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 1u, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, hashlen, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen - 1u));
	EXPECT(!buf[hashlen - 1]);
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, 2u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, 1u));
	EXPECT(!buf[1u]);
	CANARY_X_CHECK(buf, 2u, 2u);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, 1u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!buf[0u]);
	CANARY_X_CHECK(buf, 1u, 1u);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, 0u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	CANARY_X_CHECK(buf, 0u, 0u);
	EXPECT(librecrypt_hash(NULL, 0u, phrase, len, settings, NULL) == (ssize_t)hashlen);

	lut = librecrypt_get_encoding(settings, strlen(settings), &pad, &strict_pad, 1);
	assert(lut);
	r = librecrypt_decode(expected, sizeof(expected), hash, strlen(hash), lut, pad, strict_pad);
	assert(r > 0 && (size_t)r <= sizeof(expected));

	CANARY_FILL(buf);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_hash(buf, sizeof(buf), expected, (size_t)r, settings, NULL) == (ssize_t)hashlen);
	errno = 0;
	EXPECT(librecrypt_hash(buf2, sizeof(buf2), phrase, len, chain, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(buf, buf2, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 2, scratchsize);
	CANARY_X_CHECK(buf2, hashlen + 2, scratchsize);
}


#define CHECK(PHRASE, CONF, HASHLEN, IS_DEFAULT_HASHLEN, HASH)\
	do {\
		size_t scratchsize = GET_SCRATCH_SIZE(HASHLEN);\
		check(PHRASE, CONF HASH, CONF "*" #HASHLEN ">" CONF HASH, HASH, scratchsize);\
		check(PHRASE, CONF "*" #HASHLEN, CONF "*" #HASHLEN ">" CONF "*" #HASHLEN, HASH, scratchsize);\
		if (IS_DEFAULT_HASHLEN)\
			check(PHRASE, CONF, CONF ">" CONF, HASH, scratchsize);\
	} while (0)


#define CHECK_BAD(ALGO)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=0,t=999999999999999999,p=0$AAAABBBB$*0", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$*32$", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*0", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*x", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*2x", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*9999999999999999999999999999999", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$AAAABBBBCCCCDDDDEEEEFFFF>", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$AAAABBBBCCCCDDDDEEEEFFFFG", NULL) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$AAAABBBBCCCCDDDDEEEEFFFF~", NULL) == -1);\
		EXPECT(errno == EINVAL);\
	} while (0)


int
main(void)
{
	char conf[256];
	int r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#define GET_SCRATCH_SIZE(HASHLEN) ((HASHLEN) > 64u ? ((HASHLEN) + 63u) & ~31u : (HASHLEN))
#if defined(SUPPORT_ARGON2I)
	r = snprintf(conf, sizeof(conf), "$argon2i$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", SIZE_MAX / 4u * 3u + 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, conf, NULL) == -1);
# if SIZE_MAX > UINT32_MAX
	EXPECT(errno == EINVAL);
# else
	EXPECT(errno == EOVERFLOW);
	if (libtest_have_custom_malloc()) {
		char buf[1024];
		libtest_pretend_allocation_successful = 1;
		errno = 0;
		EXPECT(librecrypt_hash(buf, sizeof(buf), NULL, 0u, conf, NULL) == -1);
		libtest_pretend_allocation_successful = 0;
		EXPECT(errno == EOVERFLOW);
	}
# endif

	CHECK("password",  "$argon2i$"   "m=256,t=2,p=1$c29tZXNhbHQ$",  32, 1, "/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
	CHECK("password",  "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$",  32, 1, "iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
	CHECK_BAD("$argon2i$");
#endif
#if defined(SUPPORT_ARGON2ID)
	CHECK("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$",  32, 1, "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4");
	CHECK_BAD("$argon2id$");
#endif
#if defined(SUPPORT_ARGON2DS)
	CHECK("",         "$argon2ds$v=16$m=""8,t=1,p=1$ICAgICAgICA$",  32, 1, "zgdykk9ZjN5VyrW0LxGw8LmrJ1Z6fqSC+3jPQtn4n0s");
	CHECK_BAD("$argon2ds$");
#endif
#if defined(SUPPORT_ARGON2D)
	CHECK("",          "$argon2d$v=16$m=""8,t=1,p=1$ICAgICAgICA$", 100, 0, "NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9"
	                                                                       "n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdE"
	                                                                       "yLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");
	CHECK_BAD("$argon2d$");
#endif
#undef GET_SCRATCH_SIZE

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
