/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST

#include <libar2.h>
#include <libar2simplified.h>


#define RANGE(MIN, MAX) (uintmax_t)(MIN), (uintmax_t)(MAX)
#define BASE64 librecrypt_common_rfc4848s4_decoding_lut_, argon2__PAD, argon2__STRICT_PAD
#define REMOVE_CONST(X) (*(void **)(void *)&(X))


int
librecrypt__argon2__hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                         const char *settings, size_t prefix, void *reserved)
{
	struct libar2_argon2_parameters params;
	struct libar2_context ctx;
	const char *type, *version, *salt_encoded;
	uintmax_t mcost, tcost, lanes, saltlen, hashlen;
	void *salt = NULL, *scratch = NULL;
	size_t scratch_size;
	ssize_t r;
	int saved_errno;

	/* Not yet used */
	(void) reserved;

	/* Parse `settings` */
	r = librecrypt_check_settings_(settings, prefix,
		"$argon2%^s$%^sm=%^p,t=%^p,p=%^p$%&b$%^h",
		&type, "id", "i", "ds", "d", NULL, /* order partially matters */
		&version, "v=19$", "v=16$", "", NULL, /* empty string last */
		&mcost, RANGE(LIBAR2_MIN_M_COST, LIBAR2_MAX_M_COST),
		&tcost, RANGE(LIBAR2_MIN_T_COST, LIBAR2_MAX_T_COST),
		&lanes, RANGE(LIBAR2_MIN_LANES, LIBAR2_MAX_LANES),
		&salt_encoded, &saltlen, RANGE(LIBAR2_MIN_SALTLEN, LIBAR2_MAX_SALTLEN), BASE64,
		&hashlen, RANGE(LIBAR2_MIN_HASHLEN, LIBAR2_MAX_HASHLEN), BASE64);
	if (!r) {
		errno = EINVAL;
		return -1;
	}

	/* If not output, will just validate the input and return 0 */
	if (!size) {
		/* Argon2 has a maximum passphrase length of 2³²-1 */
#if SIZE_MAX > UINT32_MAX
		if (len > (size_t)UINT32_MAX) {
			errno = EINVAL;
			return -1;
		}
#endif
		/* This is important because the caller may have skipped calculating
		 * an intermediate hash, and instead pass `NULL` (= assume non-text)
		 * to us as `phrase`, but leave `len` non-zero is it can be validated,
		 * because we are not provided any output buffer so the input passphrase
		 * does not affect us. So we must return so that libar2_hash(3) does
		 * not attempt to read the passphrase from `NULL`. */
		return 0;
	}

	/* Gives us memory allocation and threading support;
	 * so we don't have to implement any of that ourselves */
	libar2simplified_init_context(&ctx);
	/* Configure automatic erasure of input memory */
	ctx.autoerase_message = 0; /* allows `phrase` to be read-only */
	ctx.autoerase_secret = 0; /* alloes to params.key, which we are not using, but maybe in the future */
	ctx.autoerase_associated_data = 0; /* alloes to params.ad, which we are not using, but maybe in the future */
	ctx.autoerase_salt = 1; /* since we are decoding the salt, we do a memory allocation,
	                         * and our testing always checks that allocated memory is earse;
	                         * it doesn't really matter, but it's paranoid, and that's good */

	/* Decode salt */
	if (!salt_encoded) /* this would be if asterisk-notation is used, but it is not */
		abort(); /* $covered$ */
	r = librecrypt_decode(NULL, 0u, salt_encoded, saltlen, BASE64);
	if (r < 0)
		return -1; /* $covered$ (impossible) */
	if (r > 0) {
		/* We allow `r` to be 0, although that means saltlen is 0,
		 * which it cannot actually be since LIBAR2_MIN_SALTLEN is 8,
		 * but who knows the future. Of course, we cannot run this
		 * part if `r` is 0, because we don't want to run malloc(3)
		 * with 0 because our test's implementation of malloc(3)
		 * doesn't allow that because it's implementation-defined,
		 * and we still would have to have a special case handling
		 * for implementations where it returns NULL, so instead
		 * we just let `salt` remain NULL, and `saltlen` remain 0. */
		salt = malloc((size_t)r);
		if (!salt)
			return -1;
		if (librecrypt_decode(salt, (size_t)r, salt_encoded, saltlen, BASE64) != r)
			abort(); /* $covered$ (impossible) */
		saltlen = (uintmax_t)r;
	}

	/* Apply `settings` */
	params.type = type[1u] == 'd' ? LIBAR2_ARGON2ID :
	              type[1u] == 's' ? LIBAR2_ARGON2DS :
	              type[0u] == 'i' ? LIBAR2_ARGON2I :
	                                LIBAR2_ARGON2D;
	params.version = !*version            ? LIBAR2_ARGON2_VERSION_10 :
	                   version[3u] == '9' ? LIBAR2_ARGON2_VERSION_13 : /* 19 = 0x13 = 1.3 */
	                                        LIBAR2_ARGON2_VERSION_10;  /* 16 = 0x10 = 1.0 */
	params.t_cost = (uint_least32_t)tcost;
	params.m_cost = (uint_least32_t)mcost;
	params.lanes = (uint_least32_t)lanes;
	params.salt = salt;
	params.saltlen = (size_t)saltlen;
	params.key = NULL;
	params.keylen = 0u;
	params.ad = NULL;
	params.adlen = 0u;
	params.hashlen = hashlen ? (size_t)hashlen : argon2__HASH_SIZE;

	/* Argon2 may require a larger buffer to work with for the hash than it outputs */
	scratch_size = libar2_hash_buf_size(&params);
	if (scratch_size > size) {
		scratch = malloc(scratch_size);
		if (!scratch)
			goto fail;
	}

	/* Calculate hash */
	if (libar2_hash(scratch ? scratch : out_buffer, REMOVE_CONST(phrase), len, &params, &ctx))
		goto fail;
	if (scratch && out_buffer)
		memcpy(out_buffer, scratch, MIN(params.hashlen, size));

	/* same rationale as for `ctx.autoerase_salt = 1;` */
	if (scratch) {
		librecrypt_wipe(scratch, scratch_size);
		free(scratch);
	} else if (scratch_size > params.hashlen) {
		librecrypt_wipe(&out_buffer[params.hashlen], scratch_size - params.hashlen);
	}

	free(salt);
	return 0;

fail:
	saved_errno = errno;
	if (scratch) {
		librecrypt_wipe(scratch, scratch_size);
		free(scratch);
	}
	if (salt) {
		librecrypt_wipe(salt, saltlen);
		free(salt);
	}
	errno = saved_errno;
	return -1;
}


#else


static int discarded_int;


static void
check(const char *phrase, const char *settings, const char *hash, size_t hashlen, size_t scratchsize)
{
	size_t i, len = strlen(phrase);
	size_t prefix = strlen(settings);
	char buf[1024], expected[256];
	ssize_t r;

	assert(hashlen <= sizeof(buf));
	assert(hashlen <= sizeof(expected));
	assert(2u * hashlen <= sizeof(buf));

	r = librecrypt_decode(expected, sizeof(expected), hash, strlen(hash),
	                      librecrypt_common_rfc4848s4_decoding_lut_,
	                      argon2__PAD, argon2__STRICT_PAD);
	assert(r > 0 && (size_t)r == hashlen);

	CANARY_FILL(buf);
	EXPECT(librecrypt__argon2__hash(buf, sizeof(buf), phrase, len, settings, prefix, NULL) == 0);
	EXPECT(!memcmp(expected, buf, hashlen));
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt__argon2__hash(buf, hashlen, phrase, len, settings, prefix, NULL) == 0);
	EXPECT(!memcmp(expected, buf, hashlen));
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt__argon2__hash(buf, 0u, phrase, len, settings, prefix, NULL) == 0);
	CANARY_X_CHECK(buf, 0u, 0u);
	EXPECT(librecrypt__argon2__hash(NULL, 0u, phrase, len, settings, prefix, NULL) == 0);

	for (i = 1u; i <= hashlen * 2u; i++) {
		CANARY_FILL(buf);
		EXPECT(librecrypt__argon2__hash(buf, i, phrase, len, settings, prefix, NULL) == 0);
		EXPECT(!memcmp(expected, buf, MIN(i, hashlen)));
		CANARY_X_CHECK(buf, MIN(i, hashlen), scratchsize);
	}

}


#define S(STR) (STR), (sizeof(STR) - 1u)


#define CHECK(PHRASE, CONF, HASHLEN, HASH)\
	do {\
		size_t scratchsize = GET_SCRATCH_SIZE(HASHLEN);\
		check(PHRASE, CONF HASH, HASH, (size_t)HASHLEN, scratchsize);\
		if ((size_t)HASHLEN == argon2__HASH_SIZE)\
			check(PHRASE, CONF, HASH, (size_t)HASHLEN, scratchsize);\
		check(PHRASE, CONF "*" #HASHLEN, HASH, (size_t)HASHLEN, scratchsize);\
	} while (0)


#if SIZE_MAX > UINT32_MAX
# define CHECK_MEGAPASSPHRASE(ALGO)\
	libtest_set_alloc_failure_in(3u);\
	errno = 0;\
	EXPECT(librecrypt__argon2__hash(NULL, 0u, NULL, (size_t)UINT32_MAX + 1u,\
					S(ALGO"m=1024,t=10,p=1$ABCDabcdABCDabcd$"), NULL) == -1);\
	EXPECT(errno == EINVAL);\
	libtest_set_alloc_failure_in(0u)
#else
# define CHECK_MEGAPASSPHRASE(ALGO)\
	((void)0)
#endif


#define COMMON buf, 1u, NULL, 0u
#define CHECK_BAD(ALGO)\
	do {\
		errno = 0;\
		EXPECT(librecrypt__argon2__hash(COMMON, S(ALGO"m=0,t=999999999999999999,p=0$AAAABBBB$*0"), NULL) == -1);\
		EXPECT(errno == EINVAL);\
		\
		/* target `if (!salt_encoded)` */\
		EXPECT_ABORT(discarded_int = librecrypt__argon2__hash(COMMON, S(ALGO"m=1024,t=10,p=1$*10$"), NULL));\
		\
		if (!libtest_have_custom_malloc())\
			break;\
		\
		CHECK_MEGAPASSPHRASE(ALGO);\
		\
		/* target `salt = malloc((size_t)r);` */\
		libtest_set_alloc_failure_in(1u);\
		errno = 0;\
		EXPECT(librecrypt__argon2__hash(COMMON, S(ALGO"m=1024,t=10,p=1$AAAABBBBCCCCDDDD$"), NULL) == -1);\
		EXPECT(errno == ENOMEM);\
		\
		/* target `scratch = malloc(scratch_size);` */\
		libtest_set_alloc_failure_in(2u);\
		errno = 0;\
		EXPECT(librecrypt__argon2__hash(COMMON, S(ALGO"m=1024,t=10,p=1$BBBBCCCCDDDDAAAA$"), NULL) == -1);\
		EXPECT(errno == ENOMEM);\
		\
		/* target `libar2_hash` */\
		libtest_set_alloc_failure_in(3u);\
		errno = 0;\
		EXPECT(librecrypt__argon2__hash(COMMON, S(ALGO"m=1024,t=10,p=1$CCCCDDDDAAAABBBB$"), NULL) == -1);\
		EXPECT(errno == ENOMEM);\
		\
		assert(!libtest_get_alloc_failure_in());\
	} while (0)


int
main(void)
{
	char buf[1024];

	SET_UP_ALARM();
	INIT_TEST_ABORT();
	INIT_RESOURCE_TEST();

#define GET_SCRATCH_SIZE(HASHLEN) ((HASHLEN) > 64u ? ((HASHLEN) + 63u) & ~31u : (HASHLEN))
#if defined(SUPPORT_ARGON2I)
	CHECK("password",  "$argon2i$"   "m=256,t=2,p=1$c29tZXNhbHQ$",  32, "/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
	CHECK("password",  "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$",  32, "iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
	CHECK_BAD("$argon2i$");
#endif
#if defined(SUPPORT_ARGON2ID)
	CHECK("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$",  32, "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4");
	CHECK_BAD("$argon2id$");
#endif
#if defined(SUPPORT_ARGON2DS)
	CHECK("",         "$argon2ds$v=16$m=""8,t=1,p=1$ICAgICAgICA$",  32, "zgdykk9ZjN5VyrW0LxGw8LmrJ1Z6fqSC+3jPQtn4n0s");
	CHECK_BAD("$argon2ds$");
#endif
#if defined(SUPPORT_ARGON2D)
	CHECK("",          "$argon2d$v=16$m=""8,t=1,p=1$ICAgICAgICA$", 100, "NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9"
	                                                                    "n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdE"
	                                                                    "yLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");
	CHECK_BAD("$argon2d$");
#endif
#undef GET_SCRATCH_SIZE

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
