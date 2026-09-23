/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wformat-truncation=" /* we rely on snprintf(3) doing truncation */
#endif


ssize_t
librecrypt_add_algorithm(char *out_buffer, size_t size, const char *augend,
                         const char *restrict augment, LIBRECRYPT_CONTEXT *ctx)
{
	size_t prefix1, prefix2, min, ret, len, phraselen;
	size_t hashsize1, hashsize2;
	char *phrase, pad;
	int strict_pad, r_int, nul_term, saved_errno;
	const unsigned char *lut;
	ssize_t r;

	/* Reserve space for NUL-termination */
	if (size) {
		nul_term = 1;
		size -= 1u;
	} else {
		nul_term = 0;
	}

	/* Get the prefix and hash size in `augend` and `augment` */
	prefix1 = librecrypt_settings_prefix(augend, &hashsize1, ctx);
	prefix2 = librecrypt_settings_prefix(augment, &hashsize2, ctx);

	/* If `augend` specifies a hash size rather than a hash, include it as the prefix */
	if (augend[prefix1] == '*') {
		prefix1 += strlen(&augend[prefix1]);
		hashsize1 = 0u;
	}

	/* If `augend` doesn't contain a hash, we do not need to hash the hash,
	 * but we do need to include the final hash size if it is configurable */
	if (!augend[prefix1]) {
		if (augment[prefix2] == '*') {
			prefix2 += strlen(&augment[prefix2]);
			hashsize2 = 0u;
		}
		ret = prefix1 + 1u + prefix2;
		if (size) {
			min = MIN(prefix1, size);
			if (out_buffer != augend)
				memmove(out_buffer, augend, min);
			out_buffer = &out_buffer[min];
			size -= min;
			if (size) {
				*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
				size -= 1u;
			}
			min = MIN(prefix2, size);
			memcpy(out_buffer, augment, min);
			out_buffer = &out_buffer[min];
			size -= min;
			if (hashsize2) {
				r_int = snprintf(out_buffer, size + 1u, "*%zu", hashsize2);
				if (r_int < 2)
					abort(); /* $covered$ (impossible reliably) */
				if (ret > SIZE_MAX - (size_t)r_int)
					abort(); /* $covered$ (impossible) */
				ret += (size_t)r_int;
			} else {
				out_buffer[0u] = '\0';
			}
		} else {
#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
			if (!hashsize2)
				goto out;
#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif
			r_int = snprintf(NULL, 0u, "*%zu", hashsize2);
			if (r_int < 2)
				abort(); /* $covered$ (impossible reliably) */
			if (ret > SIZE_MAX - (size_t)r_int)
				abort(); /* $covered$ (impossible) */
			ret += (size_t)r_int;
		out:
			if (nul_term)
				out_buffer[0u] = '\0';
		}
		if (ret > (size_t)SSIZE_MAX) {
			/* $covered{$ (manually) */
			errno = EOVERFLOW;
			return -1;
			/* $covered}$ */
		}
		return (ssize_t)ret;
	}

	/* Measure size of hash size specification for `augend` */
	if (hashsize1) {
		r_int = snprintf(NULL, 0u, "*%zu", hashsize1);
		if (r_int < 2)
			abort(); /* $covered$ (impossible reliably) */
	} else {
		r_int = 0;
	}

	/* Measure `augend` and '>' in output */
	if (prefix1 > SIZE_MAX - 1u - (size_t)r_int)
		abort(); /* $covered$ (impossible) */
	ret = prefix1 + (size_t)r_int + 1u;

	/* Decode the hash from base-64 to binary */
	if (size <= ret + prefix2) {
		/* If the new hash doesn't fit, don't bother;
		 * hash sizes are independent of password size */
		phrase = NULL;
		phraselen = 0u;
	} else {
		/* Measure old ASCII hash; `strlen(augent)` will be `prefix1 + len` */
		len = strlen(&augend[prefix1]);

		/* Get encoding information */
		lut = librecrypt_get_encoding(augend, prefix1 + len, &pad, &strict_pad, 1, ctx);
		if (!lut)
			return -1;

		/* Measure old binary hash */
		r = librecrypt_decode(NULL, 0u, &augend[prefix1], len, lut, pad, strict_pad);
		if (r <= 0) {
			if (!r)
				abort(); /* $covered$ (impossible: would have taken the (!augend[prefix1])-path) */
			return -1;
		}
		phraselen = (size_t)r;

		/* Decode old hash from ASCII to binary */
		phrase = malloc(phraselen);
		if (!phrase)
			return -1;
		if (librecrypt_decode(phrase, phraselen, &augend[prefix1], len, lut, pad, strict_pad) != r)
			abort(); /* $covered$ (impossible) */
	}

	/* Chain the hash algorithms: write `augent` */
	min = MIN(prefix1, size);
	if (out_buffer != augend && min)
		memmove(out_buffer, augend, min);
	out_buffer = &out_buffer[min];
	size -= min;
	if (hashsize1 && size) {
		if (snprintf(out_buffer, size + 1u, "*%zu", hashsize1) != r_int)
			abort(); /* $covered$ (impossible reliably) */
		min = MIN((size_t)r_int, size);
		out_buffer = &out_buffer[min];
		size -= min;
	}

	/* Chain the hash algorithms: write '>' */
	if (size) {
		*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
		size -= 1u;
	}

	/* Chain the hash algorithms: write `augment` and hash */
	r = librecrypt_crypt(out_buffer, nul_term ? size + 1u : 0u, phrase, phraselen, augment, ctx);
	if (r <= 0) {
		saved_errno = errno;
		librecrypt_wipe(phrase, phraselen);
		free(phrase);
		if (!r)
			abort(); /* $covered$ (impossible) */
		errno = saved_errno;
		return -1;
	}
	if (ret > (size_t)(SSIZE_MAX - r)) {
		/* $covered{$ (manually) */
		librecrypt_wipe(phrase, phraselen);
		free(phrase);
		errno = EOVERFLOW;
		return -1;
		/* $covered}$ */
	}
	ret += (size_t)r;

	librecrypt_wipe(phrase, phraselen);
	free(phrase);
	return (ssize_t)ret;
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

#define TEST_PHRASE64_ROT4 "EiM0RVZneIk#"
#define TEST_HASH_ROT4 "ITJDVGV2h5g#"
#define TEST_HASH_TRUNC "4ycQhg@@"
#define TEST_HASH_TRUNC6 "4ycQhlpD"
#define TEST_HASH_TRUNC_ROT4 "ITJDVAAAAAA#"
#define TEST_HASH_TRUNC6_ROT4 "ITJDVGV2AAA#"
#define TEST_HASH_ROT4_TRUNC "8j93l0@@"
#define TEST_HASH_ROT4_TRUNC6 "8j93l6lS"
#define TEST_HASH_TRUNC_TRUNC6 "4ycQhg00"


int
main(void)
{
#define SALT1 "ABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd"
#define SALT2 "0123abcd0123ABCD0123abcd0123ABCD0123abcd0123ABCD0123abcd0123ABCD"
#define HASH1 "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTYVWXYZ/+"
#define ASTRA "*48"

	const struct librecrypt_algorithm custom[] = {rot4_algo, trunc_algo};
	LIBRECRYPT_CONTEXT *ctx = NULL;
	char buf[1024], phrase[sizeof(buf)], expected[sizeof(buf)], pad;
	size_t i, min, phraselen;
	int strict_pad;
	const void *lut;
	size_t n;
	ssize_t r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#define CHECK(AUGEND, AUGMENT, RESULT)\
	do {\
		CANARY_FILL(buf);\
		r = librecrypt_add_algorithm(buf, sizeof(buf), (AUGEND), (AUGMENT), ctx);\
		EXPECT(r > 0);\
		EXPECT((size_t)r == strlen(RESULT));\
		assert((size_t)r < sizeof(buf) + 1u);\
		EXPECT(!buf[r]);\
		EXPECT(!memcmp(buf, (RESULT), (size_t)r));\
		CANARY_CHECK(buf, (size_t)r + 1u);\
		\
		for (i = (size_t)r + 2u;; i--) {\
			CANARY_FILL(buf);\
			EXPECT(librecrypt_add_algorithm(buf, i, (AUGEND), (AUGMENT), ctx) == r);\
			if (!i) {\
				CANARY_CHECK(buf, 0u);\
				break;\
			}\
			min = MIN(i - 1u, (size_t)r);\
			EXPECT(!buf[min]);\
			EXPECT(!memcmp(buf, (RESULT), min));\
			CANARY_CHECK(buf, min + 1u);\
		}\
		\
		EXPECT(librecrypt_add_algorithm(NULL, 0u, (AUGEND), (AUGMENT), ctx) == r);\
		\
		assert(sizeof(buf) > strlen(AUGEND));\
		\
		CANARY_FILL(buf);\
		stpcpy(buf, (AUGEND));\
		EXPECT(librecrypt_add_algorithm(buf, sizeof(buf), buf, (AUGMENT), ctx) == r);\
		EXPECT(!buf[r]);\
		EXPECT(!memcmp(buf, (RESULT), (size_t)r));\
		n = strlen(AUGEND) + 1u;\
		n = MAX(n, (size_t)r + 1u);\
		CANARY_CHECK(buf, n);\
		\
		for (i = (size_t)r + 2u;; i--) {\
			CANARY_FILL(buf);\
			stpcpy(buf, (AUGEND));\
			n = strlen(AUGEND) + 1u;\
			EXPECT(librecrypt_add_algorithm(buf, i, buf, (AUGMENT), ctx) == r);\
			if (!i) {\
				CANARY_CHECK(buf, n);\
				break;\
			}\
			min = MIN(i - 1u, (size_t)r);\
			EXPECT(!buf[min]);\
			EXPECT(!memcmp(buf, (RESULT), min));\
			n = MAX(n, min + 1u);\
			CANARY_CHECK(buf, n);\
		}\
	} while (0)

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2D) && defined(SUPPORT_ARGON2_V1_0)

	CHECK("$argon2d$v=16$m=8,t=1,p=1$*16$*40", "$argon2i$v=19$m=16,t=4,p=2$*18$*50",
	      "$argon2d$v=16$m=8,t=1,p=1$*16$*40>" "$argon2i$v=19$m=16,t=4,p=2$*18$*50");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$*40", "$argon2i$m=8,t=4,p=2$"SALT2"$*50",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$*40>" "$argon2i$m=8,t=4,p=2$"SALT2"$*50");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$", "$argon2i$m=8,t=4,p=2$"SALT2"$",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$>" "$argon2i$m=8,t=4,p=2$"SALT2"$");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$*40", "$argon2i$m=8,t=4,p=2$"SALT2"$",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$*40>" "$argon2i$m=8,t=4,p=2$"SALT2"$");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$", "$argon2i$m=8,t=4,p=2$"SALT2"$*50",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$>" "$argon2i$m=8,t=4,p=2$"SALT2"$*50");

	CHECK("$argon2d$m=8,t=1,p=1$*16$", "$argon2i$m=8,t=4,p=2$"SALT2"$",
	      "$argon2d$m=8,t=1,p=1$*16$>" "$argon2i$m=8,t=4,p=2$"SALT2"$");

	CHECK("$argon2d$m=8,t=1,p=1$*16$*50", "$argon2i$m=8,t=4,p=2$"SALT2"$",
	      "$argon2d$m=8,t=1,p=1$*16$*50>" "$argon2i$m=8,t=4,p=2$"SALT2"$");

	CHECK("$argon2d$m=8,t=1,p=1$*16$", "$argon2i$m=8,t=4,p=2$"SALT2"$*60",
	      "$argon2d$m=8,t=1,p=1$*16$>" "$argon2i$m=8,t=4,p=2$"SALT2"$*60");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$", "$argon2i$m=8,t=4,p=2$*20$",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$>" "$argon2i$m=8,t=4,p=2$*20$");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$*32", "$argon2i$m=8,t=4,p=2$*20$",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$*32>" "$argon2i$m=8,t=4,p=2$*20$");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$", "$argon2i$m=8,t=4,p=2$*20$*32",
	      "$argon2d$m=8,t=1,p=1$"SALT1"$>" "$argon2i$m=8,t=4,p=2$*20$*32");

	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$", "$argon2i$m=8,t=4,p=2$*20$"HASH1,
	      "$argon2d$m=8,t=1,p=1$"SALT1"$>" "$argon2i$m=8,t=4,p=2$*20$"ASTRA);

	CHECK("$argon2d$m=8,t=1,p=1$$", "$argon2i$m=8,t=4,p=2$$",
	      "$argon2d$m=8,t=1,p=1$$>" "$argon2i$m=8,t=4,p=2$$");

	CANARY_FILL(buf);
	errno = 0;
	EXPECT(librecrypt_add_algorithm(buf, sizeof(buf), "$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1,
	                                "$argon2i$m=8,t=4,p=1$$", NULL) == -1);
	EXPECT(errno == EINVAL);
	CANARY_CHECK(buf, sizeof("$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1));

	errno = 0;
	EXPECT(librecrypt_add_algorithm(NULL, 0u, "$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1,
	                                "$argon2i$m=8,t=4,p=1$$", NULL) == -1);
	EXPECT(errno == EINVAL);

	/* we just don't want to crash on this one, don't care if it pretends
	 * everything is fine or if it sets errno to EINVAL and returns -1 */
	EXPECT(librecrypt_add_algorithm(NULL, 0u, "$argon2d$m=8,t=1,p=1$"ASTRA"$"HASH1,
	                                "$argon2i$m=8,t=4,p=1$"SALT2"$", NULL) > -2);

	lut = librecrypt_get_encoding("$argon2d$", sizeof("$argon2d$") - 1u, &pad, &strict_pad, 1, NULL);
	assert(lut);
	r = librecrypt_decode(phrase, sizeof(phrase), HASH1, strlen(HASH1), lut, pad, strict_pad);
	assert(r > 0 && (size_t)r <= sizeof(phrase));
	phraselen = (size_t)r;

	stpcpy(expected, "$argon2d$m=8,t=1,p=1$"SALT1"$"ASTRA">$argon2i$m=8,t=4,p=1$"SALT2"$");
	n = strlen(expected);
	r = librecrypt_hash(&expected[n], sizeof(expected) - n,
	                    phrase, phraselen, "$argon2i$m=8,t=4,p=1$"SALT2"$*32", NULL);
	assert(r > 0 && (size_t)r < sizeof(expected) - n);
	assert(!expected[n + (size_t)r]);
	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1, "$argon2i$m=8,t=4,p=1$"SALT2"$*32", expected);
	CHECK("$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1,
	      "$argon2i$m=8,t=4,p=1$"SALT2"$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", expected);

	if (libtest_have_custom_malloc()) {
		CANARY_FILL(buf);
		libtest_set_alloc_failure_in(1u);
		errno = 0;
		EXPECT(librecrypt_add_algorithm(buf, sizeof(buf), "$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1,
		                                "$argon2d$m=8,t=1,p=1$"SALT2"$", NULL) == -1);
		EXPECT(errno == ENOMEM);
		assert(libtest_get_alloc_failure_in() == 0u);
		CANARY_CHECK(buf, 0u);
	}

	CANARY_FILL(buf);
	errno = 0;
	EXPECT(librecrypt_add_algorithm(buf, sizeof(buf),
	                                "$argon2d$m=8,t=1,p=1$"SALT1"$"
	                                "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
	                                "$argon2d$m=8,t=1,p=1$"SALT2"$", NULL) == -1);
	EXPECT(errno == EINVAL);
	CANARY_CHECK(buf, 0u);

#endif

	CANARY_FILL(buf);
	errno = 0;
	EXPECT(librecrypt_add_algorithm(buf, sizeof(buf), "$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1,
	                                "$~no~such~algorithm~$", NULL) == -1);
	EXPECT(errno == ENOSYS);
	CANARY_CHECK(buf, sizeof("$argon2d$m=8,t=1,p=1$"SALT1"$"HASH1));

	CANARY_FILL(buf);
	errno = 0;
	EXPECT(librecrypt_add_algorithm(buf, sizeof(buf), "$~no~such~algorithm~$"HASH1,
	                                "$argon2d$m=8,t=1,p=1$"SALT1"$", NULL) == -1);
	EXPECT(errno == ENOSYS);
	CANARY_CHECK(buf, 0u);

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));
	CHECK("$rot4$", "$rot4$", "$rot4$>$rot4$");
	CHECK("$rot4$", "$trunc$", "$rot4$>$trunc$");
	CHECK("$rot4$", "$trunc$*6", "$rot4$>$trunc$*6");
	CHECK("$trunc$", "$trunc$", "$trunc$>$trunc$");
	CHECK("$trunc$", "$trunc$*6", "$trunc$>$trunc$*6");
	CHECK("$trunc$", "$rot4$", "$trunc$>$rot4$");
	CHECK("$trunc$*4", "$trunc$", "$trunc$*4>$trunc$");
	CHECK("$trunc$*4", "$trunc$*6", "$trunc$*4>$trunc$*6");
	CHECK("$trunc$*4", "$rot4$", "$trunc$*4>$rot4$");
	CHECK("$trunc$*6", "$trunc$", "$trunc$*6>$trunc$");
	CHECK("$trunc$*6", "$trunc$*6", "$trunc$*6>$trunc$*6");
	CHECK("$trunc$*6", "$rot4$", "$trunc$*6>$rot4$");
	CHECK("$rot4$"TEST_HASH_ROT4, "$rot4$", "$rot4$>$rot4$"TEST_PHRASE64_ROT4);
	CHECK("$rot4$"TEST_HASH_ROT4, "$trunc$", "$rot4$>$trunc$"TEST_HASH_ROT4_TRUNC);
	CHECK("$rot4$"TEST_HASH_ROT4, "$trunc$*6", "$rot4$>$trunc$"TEST_HASH_ROT4_TRUNC6);
	CHECK("$trunc$"TEST_HASH_TRUNC6, "$trunc$", "$trunc$*6>$trunc$"TEST_HASH_TRUNC);
	CHECK("$trunc$"TEST_HASH_TRUNC6, "$trunc$*6", "$trunc$*6>$trunc$"TEST_HASH_TRUNC6);
	CHECK("$trunc$"TEST_HASH_TRUNC6, "$rot4$", "$trunc$*6>$rot4$"TEST_HASH_TRUNC6_ROT4);
	CHECK("$trunc$"TEST_HASH_TRUNC, "$trunc$", "$trunc$*4>$trunc$"TEST_HASH_TRUNC);
	CHECK("$trunc$"TEST_HASH_TRUNC, "$trunc$*6", "$trunc$*4>$trunc$"TEST_HASH_TRUNC_TRUNC6);
	CHECK("$trunc$"TEST_HASH_TRUNC, "$rot4$", "$trunc$*4>$rot4$"TEST_HASH_TRUNC_ROT4);

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
