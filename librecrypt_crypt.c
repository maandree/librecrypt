/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_crypt(char *restrict out_buffer, size_t size, const char *phrase, size_t len, const char *settings, void *reserved)
{
	return librecrypt_hash_(out_buffer, size, phrase, len, settings, reserved, ASCII_CRYPT);
}


#else


static void
check(const char *phrase, const char *settings, const char *chain, size_t chain_prefix, const char *hash,
      size_t hash_prefix, size_t scratchsize)
{
	size_t hashlen = strlen(hash);
	size_t len = strlen(phrase);
	char buf[1024], buf2[sizeof(buf)], expected[sizeof(buf)], pad;
	int strict_pad;
	const void *lut;
	ssize_t r;

	assert(hashlen <= sizeof(buf));

	CANARY_FILL(buf);
	EXPECT(librecrypt_crypt(buf, sizeof(buf), phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 1u, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_crypt(buf, hashlen + 1u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 1u, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_crypt(buf, hashlen, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen - 1u));
	EXPECT(!buf[hashlen - 1u]);
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_crypt(buf, 2u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, 1u));
	EXPECT(!buf[1u]);
	CANARY_X_CHECK(buf, 2u, 2u);

	CANARY_FILL(buf);
	EXPECT(librecrypt_crypt(buf, 1u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(!buf[0u]);
	CANARY_X_CHECK(buf, 1u, 1u);

	EXPECT(librecrypt_crypt(buf, 0u, phrase, len, settings, NULL) == (ssize_t)hashlen);
	EXPECT(librecrypt_crypt(NULL, 0u, phrase, len, settings, NULL) == (ssize_t)hashlen);

	lut = librecrypt_get_encoding(settings, strlen(settings), &pad, &strict_pad, 1, NULL);
	assert(lut);
	r = librecrypt_decode(expected, sizeof(expected), &hash[hash_prefix], hashlen - hash_prefix, lut, pad, strict_pad);
	assert(r > 0 && (size_t)r <= sizeof(expected));

	CANARY_FILL(buf);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_crypt(buf, sizeof(buf), expected, (size_t)r, settings, NULL) == (ssize_t)hashlen);
	errno = 0;
	EXPECT(librecrypt_crypt(buf2, sizeof(buf2), phrase, len, chain, NULL) == (ssize_t)(hashlen - hash_prefix + chain_prefix));
	EXPECT(!memcmp(buf2, chain, chain_prefix));
	EXPECT(!memcmp(&buf[hash_prefix], &buf2[chain_prefix], hashlen - hash_prefix + 1u));
	CANARY_X_CHECK(buf, hashlen, scratchsize);
	CANARY_X_CHECK(buf2, hashlen - hash_prefix + chain_prefix, scratchsize);
}


#define CHECK(PHRASE, CONF, HASHLEN, IS_DEFAULT_HASHLEN, HASH)\
	do {\
		size_t scratchsize = GET_SCRATCH_SIZE(HASHLEN);\
		check(PHRASE, CONF HASH, CONF "*" #HASHLEN ">" CONF HASH,\
		      sizeof(CONF "*" #HASHLEN ">" CONF) - 1u, CONF HASH, sizeof(CONF) - 1u, scratchsize);\
		check(PHRASE, CONF "*" #HASHLEN, CONF "*" #HASHLEN ">" CONF "*" #HASHLEN,\
		      sizeof(CONF "*" #HASHLEN ">" CONF) - 1u, CONF HASH, sizeof(CONF) - 1u, scratchsize);\
		if (IS_DEFAULT_HASHLEN) {\
			check(PHRASE, CONF, CONF ">" CONF, sizeof(CONF ">" CONF) - 1u,\
			      CONF HASH, sizeof(CONF) - 1u, scratchsize);\
		}\
	} while (0)


#define CHECK_BAD(ALGO)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_crypt(NULL, 0u, NULL, 0u, ALGO"m=0,t=999999999999999999,p=0$AAAABBBB$*0", NULL) == -1);\
		EXPECT(errno == EINVAL);\
	} while (0)


int
main(void)
{
	char buf[1024], buf2[1024], conf[256];
	ssize_t r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#if defined(__linux__)
	libtest_getrandom_real = 0;
	libtest_getrandom_error = ENOSYS;
#endif

#define GET_SCRATCH_SIZE(HASHLEN) ((HASHLEN) > 64u ? ((HASHLEN) + 63u) & ~31u : (HASHLEN))
#if defined(SUPPORT_ARGON2I)
	r = snprintf(conf, sizeof(conf), "$argon2i$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", SIZE_MAX / 4u * 3u + 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_crypt(NULL, 0u, NULL, 0u, conf, NULL) == -1);
# if SIZE_MAX > UINT32_MAX
	EXPECT(errno == EINVAL);
# else
	EXPECT(errno == EOVERFLOW);
	if (libtest_have_custom_malloc()) {
		libtest_pretend_allocation_successful = 1;
		errno = 0;
		EXPECT(librecrypt_crypt(buf, sizeof(buf), NULL, 0u, conf, NULL) == -1);
		libtest_pretend_allocation_successful = 0;
		EXPECT(errno == EOVERFLOW);
	}
# endif

# if SIZE_MAX == UINT32_MAX
	r = snprintf(conf, sizeof(conf), "$argon2i$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", (SIZE_MAX / 4u * 3u) / 2u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_crypt(NULL, 0u, NULL, 0u, conf, NULL) == -1);
	EXPECT(errno == EOVERFLOW);
# endif

# if SIZE_MAX == UINT32_MAX
	r = snprintf(conf, sizeof(conf), "$argon2i$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", SIZE_MAX / 4u * 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_crypt(NULL, 0u, NULL, 0u, conf, NULL) == -1);
	EXPECT(errno == EOVERFLOW);
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
#if defined(SUPPORT_ARGON2ID)
	assert(!libtest_getentropy_error);

	libtest_getentropy_real = 0;
	libtest_random_pattern = (const unsigned char *)"\x00\x01\x02\x03";
	/* since librecrypt_realise_salts doesn't generate random data then base64-encode it,
	 * but rather just takes random characters from base64 alphabet (with restrictions
	 * one the list one if the count isn't a multiple of 4), this will map to a repeation
	 * of "ABCD", rather the become "AAECAwABAgMAAQIDAAECAwAB" */
	libtest_random_pattern_length = 4u;
	libtest_random_pattern_offset = 0u;
	CANARY_FILL(buf);
	r = librecrypt_crypt(buf, sizeof(buf), "", 0u, "$argon2id$v=19$m=8,t=1,p=1$*18$*33", NULL);
	libtest_random_pattern = NULL;
	libtest_random_pattern_length = 0u;
	libtest_random_pattern_offset = 0u;
	libtest_getentropy_real = 1;
	EXPECT(r > 0);
	assert((size_t)r < sizeof(buf));
	EXPECT((size_t)r == sizeof("$argon2id$v=19$m=8,t=1,p=1$$") - 1u + 24u + 44u);
	EXPECT(!buf[r]);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_crypt(buf2, sizeof(buf2), "", 0u, buf, NULL) == r);
	EXPECT(!memcmp(buf, buf2, (size_t)r + 1u));
	EXPECT(!memcmp(buf, "$argon2id$v=19$m=8,t=1,p=1$ABCDABCDABCDABCDABCDABCD$",
	             sizeof("$argon2id$v=19$m=8,t=1,p=1$ABCDABCDABCDABCDABCDABCD$") - 1u));
	CANARY_X_CHECK(buf, (size_t)r + 1u, 33u);
	CANARY_X_CHECK(buf2, (size_t)r + 1u, 33u);

	libtest_getentropy_real = 0;
	libtest_random_pattern = (const unsigned char *)"\x00\x01\x02\03";
	libtest_random_pattern_length = 4u;
	libtest_random_pattern_offset = 0u;
	CANARY_FILL(buf);
	r = librecrypt_crypt(buf, sizeof(buf), "", 0u, "$argon2id$v=19$m=8,t=1,p=1$*18$*33>"
	                                               "$argon2id$v=19$m=8,t=1,p=1$*18$*33", NULL);
	libtest_random_pattern = NULL;
	libtest_random_pattern_length = 0u;
	libtest_random_pattern_offset = 0u;
	libtest_getentropy_real = 1;
	EXPECT(r > 0);
	assert((size_t)r < sizeof(buf));
	EXPECT((size_t)r == sizeof("$argon2id$v=19$m=8,t=1,p=1$$*33>$argon2id$v=19$m=8,t=1,p=1$$") - 1u + 2u * 24u + 44u);
	EXPECT(!buf[r]);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_crypt(buf2, sizeof(buf2), "", 0u, buf, NULL) == r);
	EXPECT(!memcmp(buf, buf2, (size_t)r + 1u));
	EXPECT(!memcmp(buf, "$argon2id$v=19$m=8,t=1,p=1$ABCDABCDABCDABCDABCDABCD$*33>"
	                    "$argon2id$v=19$m=8,t=1,p=1$ABCDABCDABCDABCDABCDABCD$",
	             sizeof("$argon2id$v=19$m=8,t=1,p=1$ABCDABCDABCDABCDABCDABCD$*33>"
	                    "$argon2id$v=19$m=8,t=1,p=1$ABCDABCDABCDABCDABCDABCD$") - 1u));
	CANARY_X_CHECK(buf, (size_t)r + 1u, 33u);
	CANARY_X_CHECK(buf2, (size_t)r + 1u, 33u);
#endif
#undef GET_SCRATCH_SIZE

#if defined(__linux__)
	libtest_getrandom_real = 1;
	libtest_getrandom_error = 0;
#endif

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
