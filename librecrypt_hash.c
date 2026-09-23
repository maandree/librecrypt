/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_hash(char *restrict out_buffer, size_t size, const char *phrase,
                size_t len, const char *settings, LIBRECRYPT_CONTEXT *ctx)
{
	return librecrypt_hash_(out_buffer, size, phrase, len, settings, ctx, ASCII_HASH);
}


#else


#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define ALT_ALPHABET "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"

NONSTRING static const char encoding_lut[256u] = MAKE_ENCODING_LUT(ALPHABET);
NONSTRING static const char alt_encoding_lut[256u] = MAKE_ENCODING_LUT(ALT_ALPHABET);

static const unsigned char decoding_lut[256u] = {
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, 62, XX, XX, XX, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, XX, XX, XX, XX, XX, XX,
	XX,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, XX, XX, XX, XX, XX,
	XX, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX
};

static const unsigned char alt_decoding_lut[256u] = {
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, 62, XX, XX, XX, 63,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, XX, XX, XX, XX, XX, XX,
	XX, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, XX, XX, XX, XX, XX,
	XX, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
	XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX
};

static unsigned
rot4_is_algorithm(const char *settings, size_t len)
{
	if (len >= sizeof("$rot4$") - 1u)
		if (!strncmp(settings, "$rot4$", sizeof("$rot4$") - 1u))
			return 1u;
	return 0u;
}

static unsigned
trunc_is_algorithm(const char *settings, size_t len)
{
	if (len >= sizeof("$trunc$") - 1u)
		if (!strncmp(settings, "$trunc$", sizeof("$trunc$") - 1u))
			return 1u;
	return 0u;
}

static int
trunc_supported(const char *phrase, size_t len, int text, const char *settings,
                size_t prefix, size_t *len_out)
{
	size_t i, digit, n = 0u, q, r;

	(void) phrase;
	(void) len;
	(void) text;

	if (prefix < sizeof("$trunc$") - 1u || memcmp(settings, "$trunc$", sizeof("$trunc$") - 1u))
		return 0;

	if (prefix == sizeof("$trunc$") - 1u) {
		*len_out = 4u;
		return 1;
	}

	if (settings[sizeof("$trunc$") - 1u] == '*') {
		for (i = sizeof("$trunc$*") - 1u; i < prefix; i++) {
			if ('0' > settings[i] || settings[i] > '9')
				return 0;
			digit = (size_t)(settings[i] - '0');
			if (n > (SIZE_MAX - digit) / 10u)
				return 0;
			n = n * 10u + digit;
		}
	} else {
		for (i = sizeof("$trunc$") - 1u; i < prefix; i++) {
			if (settings[i] == '@')
				break;
			if (alt_decoding_lut[(unsigned char)settings[i]] == XX)
				return 0;
			n += 1u;
		}
		q = n / 4u;
		r = n % 4u;
		if (r == 1u)
			return 0;
		n = q * 3u + r;
		if (r) {
			n -= 1u;
			for (; r < 4u && i < prefix; r++, i++)
				if (settings[i] != '@')
					break;
			if (r != 4u || i != prefix)
				return 0;
		}
	}
	if (!n)
		return 0;
	*len_out = n;
	return 1;
}

static int
rot4_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
          const char *settings, size_t prefix, LIBRECRYPT_CONTEXT *ctx)
{
	size_t i;

	(void) settings;
	(void) prefix;
	(void) ctx;

	for (i = 0u; i < 8u && i < size; i++) {
		out_buffer[i] = '\0';
		if (i < len)
			out_buffer[i] = (char)((((int)phrase[i] & 0x0F) << 4) | (((int)phrase[i] >> 4) & 0x0F));
	}
	return 0;
}

static int
trunc_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
           const char *settings, size_t prefix, LIBRECRYPT_CONTEXT *ctx)
{
	size_t hash_size, i;

	(void) ctx;

	if (!trunc_supported(NULL, 0u, 1, settings, prefix, &hash_size)) {
		errno = EINVAL;
		return -1;
	}

	size = MIN(hash_size, size);
	for (i = 0u; i < size; i++)
		out_buffer[i] = i < len ? phrase[i] : '\0';

	return 0;
}

static const struct librecrypt_algorithm rot4_algo = {
	.is_algorithm = &rot4_is_algorithm,
	.hash = &rot4_hash,
	.encoding_lut = encoding_lut,
	.decoding_lut = decoding_lut,
	.hash_size = 8u,
	.flexible_hash_size = 0,
	.strict_pad = 1,
	.pad = '#'
};

static const struct librecrypt_algorithm trunc_algo = {
	.is_algorithm = &trunc_is_algorithm,
	.hash = &trunc_hash,
	.encoding_lut = alt_encoding_lut,
	.decoding_lut = alt_decoding_lut,
	.hash_size = 4u,
	.flexible_hash_size = 1,
	.strict_pad = 1,
	.pad = '@'
};

#define TEST_PHRASE "\x12\x23\x34\x45\x56\x67\x78\x89"
#define TEST_PHRASE64_ROT4 "EiM0RVZneIk#"
#define TEST_HASH_ROT4 "ITJDVGV2h5g#"
#define TEST_HASH_TRUNC "4ycQhg@@"
#define TEST_HASH_TRUNC6 "4ycQhlpD"
#define TEST_HASH_TRUNC_ROT4 "ITJDVAAAAAA#"
#define TEST_HASH_TRUNC6_ROT4 "ITJDVGV2AAA#"
#define TEST_HASH_ROT4_TRUNC "8j93l0@@"
#define TEST_HASH_ROT4_TRUNC6 "8j93l6lS"
#define TEST_HASH_TRUNC_TRUNC6 "4ycQhg00"
#define WRONG_HASH_ROT4 "AAAAAAAAAAA#"
#define WRONG_HASH_TRUNC "000000@@"
#define WRONG_HASH_TRUNC6 "00000000"

#define SP4 "    "
#define SP20 SP4 SP4 SP4 SP4 SP4
#define SP80 SP20 SP20 SP20 SP20
#define SP84 SP80 SP4

#define GET_ARGON2_SCRATCH_SIZE(HASHLEN) ((HASHLEN) > 64u ? ((HASHLEN) + 63u) & ~31u : (HASHLEN))


static void
check(const char *phrase, const char *settings, const char *chain,
      const char *hash, size_t scratchsize, LIBRECRYPT_CONTEXT *ctx)
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
	EXPECT(librecrypt_hash(buf, sizeof(buf), phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 1u, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, hashlen + 1u, phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen + 1u));
	CANARY_X_CHECK(buf, hashlen + 1u, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, hashlen, phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, hashlen - 1u));
	EXPECT(!buf[hashlen - 1]);
	CANARY_X_CHECK(buf, hashlen, scratchsize);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, 2u, phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(hash, buf, 1u));
	EXPECT(!buf[1u]);
	CANARY_X_CHECK(buf, 2u, 2u);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, 1u, phrase, len, settings, ctx) == (ssize_t)hashlen);
	EXPECT(!buf[0u]);
	CANARY_X_CHECK(buf, 1u, 1u);

	CANARY_FILL(buf);
	EXPECT(librecrypt_hash(buf, 0u, phrase, len, settings, ctx) == (ssize_t)hashlen);
	CANARY_X_CHECK(buf, 0u, 0u);
	EXPECT(librecrypt_hash(NULL, 0u, phrase, len, settings, ctx) == (ssize_t)hashlen);

	lut = librecrypt_get_encoding(settings, strlen(settings), &pad, &strict_pad, 1, ctx);
	assert(lut);
	r = librecrypt_decode(expected, sizeof(expected), hash, strlen(hash), lut, pad, strict_pad);
	assert(r > 0 && (size_t)r <= sizeof(expected));

	CANARY_FILL(buf);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_hash(buf, sizeof(buf), expected, (size_t)r, settings, ctx) == (ssize_t)hashlen);
	errno = 0;
	EXPECT(librecrypt_hash(buf2, sizeof(buf2), phrase, len, chain, ctx) == (ssize_t)hashlen);
	EXPECT(!memcmp(buf, buf2, hashlen + 1u));
	CANARY_X_CHECK(buf2, hashlen + 2, scratchsize);
	CANARY_X_CHECK(buf, hashlen + 2, scratchsize);
}


#define CHECK(PHRASE, CONF, HASHLEN, IS_DEFAULT_HASHLEN /* -1 if fixed */, HASH)\
	do {\
		size_t scratchsize = GET_SCRATCH_SIZE(HASHLEN);\
		if (IS_DEFAULT_HASHLEN >= 0) {\
			check(PHRASE, CONF HASH, CONF "*" #HASHLEN ">" CONF HASH, HASH, scratchsize, ctx);\
			check(PHRASE, CONF "*" #HASHLEN, CONF "*" #HASHLEN ">" CONF "*" #HASHLEN, HASH, scratchsize, ctx);\
		}\
		if (IS_DEFAULT_HASHLEN) {\
			check(PHRASE, CONF, CONF ">" CONF, HASH, scratchsize, ctx);\
			check(PHRASE, CONF HASH, CONF ">" CONF HASH, HASH, scratchsize, ctx);\
		}\
	} while (0)


#define CHECK_DIFF(PHRASE, CONF, HASHLEN, IS_DEFAULT_HASHLEN /* -1 if fixed */, HASH, DIFFHASH)\
	do {\
		size_t scratchsize = GET_SCRATCH_SIZE(HASHLEN);\
		if (IS_DEFAULT_HASHLEN >= 0)\
			check(PHRASE, CONF DIFFHASH, CONF "*" #HASHLEN ">" CONF DIFFHASH, HASH, scratchsize, ctx);\
		if (IS_DEFAULT_HASHLEN)\
			check(PHRASE, CONF DIFFHASH, CONF ">" CONF DIFFHASH, HASH, scratchsize, ctx);\
	} while (0)


#define CHECK_BAD(ALGO)\
	do {\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=0,t=999999999999999999,p=0$AAAABBBB$*0", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$*32$", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*0", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*x", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*2x", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$*9999999999999999999999999999999", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$AAAABBBBCCCCDDDDEEEEFFFF>", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$AAAABBBBCCCCDDDDEEEEFFFFG", ctx) == -1);\
		EXPECT(errno == EINVAL);\
		errno = 0;\
		EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, ALGO"m=4096,t=10,p=1$AAAABBBBCCCCDDDD$AAAABBBBCCCCDDDDEEEEFFFF~", ctx) == -1);\
		EXPECT(errno == EINVAL);\
	} while (0)


int
main(void)
{
	const struct librecrypt_algorithm custom[] = {rot4_algo, trunc_algo};
	char conf[256], nuls[256];
	LIBRECRYPT_CONTEXT *ctx = NULL;
	int r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#define GET_SCRATCH_SIZE(HASHLEN) GET_ARGON2_SCRATCH_SIZE(HASHLEN)
#if defined(SUPPORT_ARGON2I)
# if defined(SUPPORT_ARGON2_V1_0)
	r = snprintf(conf, sizeof(conf), "$argon2i$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", SIZE_MAX / 4u * 3u + 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_hash(NULL, 0u, NULL, 0u, conf, ctx) == -1);
#  if SIZE_MAX > UINT32_MAX
	EXPECT(errno == EINVAL);
#  else
	EXPECT(errno == EOVERFLOW);
	if (libtest_have_custom_malloc()) {
		char buf[1024];
		libtest_pretend_allocation_successful = 1;
		errno = 0;
		EXPECT(librecrypt_hash(buf, sizeof(buf), NULL, 0u, conf, ctx) == -1);
		libtest_pretend_allocation_successful = 0;
		EXPECT(errno == EOVERFLOW);
	}
#  endif

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

#define GET_SCRATCH_SIZE(HASHLEN) (HASHLEN)
	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));
	CHECK(TEST_PHRASE, "$trunc$", 4, 1, TEST_HASH_TRUNC);
	CHECK(TEST_PHRASE, "$trunc$", 6, 0, TEST_HASH_TRUNC6);
	CHECK(TEST_PHRASE, "$rot4$", 8, -1, TEST_HASH_ROT4);
	CHECK(TEST_PHRASE, "$rot4$>$trunc$", 4, 1, TEST_HASH_ROT4_TRUNC);
	CHECK(TEST_PHRASE, "$rot4$>$trunc$", 6, 0, TEST_HASH_ROT4_TRUNC6);
	CHECK(TEST_PHRASE, "$trunc$>$rot4$", 8, -1, TEST_HASH_TRUNC_ROT4);
	CHECK(TEST_PHRASE, "$trunc$*6>$rot4$", 8, -1, TEST_HASH_TRUNC6_ROT4);
	CHECK(TEST_PHRASE, "$trunc$>$trunc$", 4, 1, TEST_HASH_TRUNC);
	CHECK(TEST_PHRASE, "$trunc$>$trunc$", 6, 0, TEST_HASH_TRUNC_TRUNC6);
	CHECK(TEST_PHRASE, "$trunc$*6>$trunc$", 4, 1, TEST_HASH_TRUNC);
	CHECK(TEST_PHRASE, "$trunc$*6>$trunc$", 6, 0, TEST_HASH_TRUNC6);
	CHECK(TEST_PHRASE, "$rot4$>$rot4$", 8, -1, TEST_PHRASE64_ROT4);
	CHECK_DIFF(TEST_PHRASE, "$trunc$", 4, 1, TEST_HASH_TRUNC, WRONG_HASH_TRUNC);
	CHECK_DIFF(TEST_PHRASE, "$trunc$", 6, 0, TEST_HASH_TRUNC6, WRONG_HASH_TRUNC6);
	CHECK_DIFF(TEST_PHRASE, "$rot4$", 8, -1, TEST_HASH_ROT4, WRONG_HASH_ROT4);
	CHECK_DIFF(TEST_PHRASE, "$rot4$>$trunc$", 4, 1, TEST_HASH_ROT4_TRUNC, WRONG_HASH_TRUNC);
	CHECK_DIFF(TEST_PHRASE, "$rot4$>$trunc$", 6, 0, TEST_HASH_ROT4_TRUNC6, WRONG_HASH_TRUNC6);
	CHECK_DIFF(TEST_PHRASE, "$trunc$>$rot4$", 8, -1, TEST_HASH_TRUNC_ROT4, WRONG_HASH_ROT4);
	CHECK_DIFF(TEST_PHRASE, "$trunc$*6>$rot4$", 8, -1, TEST_HASH_TRUNC6_ROT4, WRONG_HASH_ROT4);
	CHECK_DIFF(TEST_PHRASE, "$trunc$>$trunc$", 4, 1, TEST_HASH_TRUNC, WRONG_HASH_TRUNC);
	CHECK_DIFF(TEST_PHRASE, "$trunc$>$trunc$", 6, 0, TEST_HASH_TRUNC_TRUNC6, WRONG_HASH_TRUNC6);
	CHECK_DIFF(TEST_PHRASE, "$trunc$*6>$trunc$", 4, 1, TEST_HASH_TRUNC, WRONG_HASH_TRUNC);
	CHECK_DIFF(TEST_PHRASE, "$trunc$*6>$trunc$", 6, 0, TEST_HASH_TRUNC6, WRONG_HASH_TRUNC6);
	CHECK_DIFF(TEST_PHRASE, "$rot4$>$rot4$", 8, -1, TEST_PHRASE64_ROT4, WRONG_HASH_ROT4);
#undef GET_SCRATCH_SIZE

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
