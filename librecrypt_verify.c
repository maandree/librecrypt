/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_verify(const char *phrase, size_t len, const char *settings, LIBRECRYPT_CONTEXT *ctx)
{
	char *hash = NULL;
	size_t size = 0u;
	size_t off;
	ssize_t n;
	int ret, err;

	/* Measure base64 hash size */
	n = librecrypt_hash_(NULL, 0u, phrase, len, settings, ctx, ASCII_HASH);
	if (n < 0) {
		if (errno == EOVERFLOW)
			errno = ENOMEM; /* $covered$ (on 32-bit) */
		return -1;
	}

	/* Get position of hash in `settings` */
	off = librecrypt_settings_prefix(settings, NULL, ctx);
	if (settings[off] == '*') {
		if ('0' <= settings[off + 1u] && settings[off + 1u] <= '9') {
			errno = EINVAL;
			return -1;
		}
	} else if (!settings[off]) {
		errno = EINVAL;
		return -1;
	}

	/* Allocate hash output buffer for comparsion */
	size = (size_t)n + 128u; /* a little extra so the hasher don't need to allocate output scratch */
	hash = malloc(size);
	if (!hash)
		return -1;

	/* Calculate password hash and encode to base64 */
	n = librecrypt_hash_(hash, size, phrase, len, settings, ctx, ASCII_HASH);
	if (n < 0) {
		err = errno;
		librecrypt_wipe(hash, size);
		free(hash);
		if (err == EOVERFLOW)
			err = ENOMEM; /* $covered$ (impossible) */
		errno = err;
		return -1;
	}
	if ((size_t)n > size)
		abort(); /* $covered$ (impossible) */

	/* Compare hash */
	ret = librecrypt_equal(hash, &settings[off]);

	librecrypt_wipe(hash, size);
	free(hash);
	return ret;
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


int
main(void)
{
	const struct librecrypt_algorithm custom[] = {rot4_algo, trunc_algo};
	LIBRECRYPT_CONTEXT *ctx = NULL;
	char conf[256], nuls[256], spaces[256];
	int r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_verify(NULL, 0u, "$~no~such~algorithm~$", ctx) == -1);
	EXPECT(errno == ENOSYS);

#if defined(SUPPORT_ARGON2ID) && defined(SUPPORT_ARGON2_V1_3)
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", ctx) == 1);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/", ctx) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4x", ctx) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/a", ctx) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$a29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/a", ctx) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$af65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", ctx) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMRauIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", ctx) == 0);

	errno = 0;
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$", ctx) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$*64", ctx) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$*16$nf65EOgLrQMRauIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", ctx) == -1);
	EXPECT(errno == EINVAL);

	if (libtest_have_custom_malloc()) {
		libtest_set_alloc_failure_in(1u);
		errno = 0;
		EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", ctx) == -1);
		assert(errno == ENOMEM);
		assert(libtest_get_alloc_failure_in() == 0u);

		libtest_set_alloc_failure_in(2u);
		errno = 0;
		EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", ctx) == -1);
		assert(errno == ENOMEM);
		assert(libtest_get_alloc_failure_in() == 0u);
	}
#endif

#if defined(SUPPORT_ARGON2ID) && defined(SUPPORT_ARGON2_V1_0)
        r = snprintf(conf, sizeof(conf), "$argon2id$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", SIZE_MAX / 4u * 3u + 3u);
        assert(r > 0 && (size_t)r < sizeof(conf));
        errno = 0;
	EXPECT(librecrypt_verify(NULL, 0u, conf, ctx) == -1);
# if SIZE_MAX > UINT32_MAX
        EXPECT(errno == EINVAL);
# else
        EXPECT(errno == EOVERFLOW);
# endif
#endif

	ctx = librecrypt_create_context();
	assert(ctx != NULL);
	memset(nuls, 0, sizeof(nuls));
	memset(spaces, ' ', sizeof(spaces));

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2_V1_3)
	assert(sizeof(nuls) >= 4u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 4u) == 0);
	EXPECT(librecrypt_verify(spaces,  1u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$Mhl4o3AkJuA", ctx) == 1);
	EXPECT(librecrypt_verify(spaces, 84u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$+hlEcRn+F3s", ctx) == 1);
	EXPECT(librecrypt_verify(spaces, 80u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$z2d6ce8UqS0", ctx) == 1);

	assert(sizeof(nuls) >= 140u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 140u) == 0);
	EXPECT(librecrypt_verify(spaces, 80u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$15FAGe1KIX8", ctx) == 1);

	assert(sizeof(nuls) >= 160u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 160u) == 0);
	EXPECT(librecrypt_verify(spaces, 80u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$oH3H5atuca8", ctx) == 1);

	assert(sizeof(nuls) >= 128u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 128u) == 0);
	EXPECT(librecrypt_verify(spaces, 80u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$TsimqI1YC08", ctx) == 1);

	assert(sizeof(nuls) >= 256u);
	assert(librecrypt_set_pepper(ctx, LIBRECRYPT_ARGON2I_V1_3, nuls, 256u) == 0);
	EXPECT(librecrypt_verify(spaces, 80u, "$argon2i$v=19$m=8,t=1,p=1$ICAgICAgICA$mzPlVOVjVos", ctx) == 1);
#endif

	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));

#define CHECK(CRYPT) EXPECT(librecrypt_verify(TEST_PHRASE, sizeof(TEST_PHRASE) - 1u, CRYPT, ctx) == 1);
	CHECK("$trunc$"TEST_HASH_TRUNC);
	CHECK("$trunc$"TEST_HASH_TRUNC6);
	CHECK("$rot4$"TEST_HASH_ROT4);
	CHECK("$rot4$>$trunc$"TEST_HASH_ROT4_TRUNC);
	CHECK("$rot4$>$trunc$"TEST_HASH_ROT4_TRUNC6);
	CHECK("$trunc$>$rot4$"TEST_HASH_TRUNC_ROT4);
	CHECK("$trunc$*6>$rot4$"TEST_HASH_TRUNC6_ROT4);
	CHECK("$trunc$>$trunc$"TEST_HASH_TRUNC);
	CHECK("$trunc$>$trunc$"TEST_HASH_TRUNC_TRUNC6);
	CHECK("$trunc$*6>$trunc$"TEST_HASH_TRUNC);
	CHECK("$trunc$*6>$trunc$"TEST_HASH_TRUNC6);
	CHECK("$rot4$>$rot4$"TEST_PHRASE64_ROT4);
#undef CHECK

#define CHECK(CRYPT) EXPECT(librecrypt_verify(TEST_PHRASE, sizeof(TEST_PHRASE) - 1u, CRYPT, ctx) == 0);
	CHECK("$trunc$"WRONG_HASH_TRUNC);
	CHECK("$trunc$"WRONG_HASH_TRUNC6);
	CHECK("$rot4$"WRONG_HASH_ROT4);
	CHECK("$rot4$>$trunc$"WRONG_HASH_TRUNC);
	CHECK("$rot4$>$trunc$"WRONG_HASH_TRUNC6);
	CHECK("$trunc$>$rot4$"WRONG_HASH_ROT4);
	CHECK("$trunc$*6>$rot4$"WRONG_HASH_ROT4);
	CHECK("$trunc$>$trunc$"WRONG_HASH_TRUNC);
	CHECK("$trunc$>$trunc$"WRONG_HASH_TRUNC6);
	CHECK("$trunc$*6>$trunc$"WRONG_HASH_TRUNC);
	CHECK("$trunc$*6>$trunc$"WRONG_HASH_TRUNC6);
	CHECK("$rot4$>$rot4$"WRONG_HASH_ROT4);
#undef CHECK

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
