/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_make_settings(char *out_buffer, size_t size, const char *algorithm,
                         size_t memcost, uintmax_t timecost, int gensalt,
                         ssize_t (*rng)(void *out, size_t n, void *user), void *user,
                         LIBRECRYPT_CONTEXT *ctx)
{
	const struct librecrypt_algorithm *algo;

	/* Get algorithm */
	if (!algorithm) {
		/* Select best algorithm if `NULL` is specified */
		algo = &librecrypt_algorithms_[0];
		if (IS_END_OF_ALGORITHMS(algo))
			goto enosys; /* $covered$ (covered iff reachable: when algorithms are disabled) */
	} else {
		/* Verify single, unchained algorithm is specified if not `NULL`*/
		if (strchr(algorithm, LIBRECRYPT_ALGORITHM_LINK_DELIMITER)) {
			errno = EINVAL;
			return -1;
		}
		/* Identify the algorithm */
		algo = librecrypt_find_first_algorithm_(algorithm, strlen(algorithm), ctx);
		if (!algo)
			goto enosys;
	}

	/* Use default random number generator if none was specified */
	if (!rng)
		rng = &librecrypt_rng_;

	/* Configure */
	return (*algo->make_settings)(out_buffer, size, algorithm, memcost, timecost, gensalt, rng, user);

enosys:
	errno = ENOSYS;
	return -1;
}


#else


#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

NONSTRING static const char encoding_lut[256u] = MAKE_ENCODING_LUT(ALPHABET);

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
rot4_supported(const char *phrase, size_t len, int text, const char *settings,
               size_t prefix, size_t *len_out)
{
	size_t i, j, n;

	(void) phrase;
	(void) len;
	(void) text;

	i = sizeof("$rot4$") - 1u;
	if (prefix < i || memcmp(settings, "$rot4$", prefix))
		return 0;
	n = i - prefix;
	if (n && n != 12u)
		return 0;
	if (n == 12u) {
		for (j = 0u; j < 11u; j++, i++)
			if (decoding_lut[(unsigned char)settings[i]] == XX)
				return 0;
		if (decoding_lut[(unsigned char)settings[i]] != '#')
			return 0;
	}

	*len_out = 8u;
	return 1;
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
			if (decoding_lut[(unsigned char)settings[i]] == XX)
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

static ssize_t
rot4_make_settings(char *out_buffer, size_t size, const char *algorithm,
                   size_t memcost, uintmax_t timecost, int gensalt,
                   ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	size_t ret = sizeof("$rot4$") - 1u;

	(void) algorithm;
	(void) memcost;
	(void) timecost;
	(void) gensalt;
	(void) rng;
	(void) user;

	if (size) {
		size = MIN(ret, size - 1u);
		memcpy(out_buffer, "$rot4$", size);
		out_buffer[size] = '\0';
	}

	return (ssize_t) ret;
}

static ssize_t
trunc_make_settings(char *out_buffer, size_t size, const char *algorithm,
                    size_t memcost, uintmax_t timecost, int gensalt,
                    ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	size_t ret = sizeof("$trunc$*4") - 1u;

	(void) algorithm;
	(void) memcost;
	(void) timecost;
	(void) gensalt;
	(void) rng;
	(void) user;

	if (size) {
		size = MIN(ret, size - 1u);
		memcpy(out_buffer, "$trunc$*4", size);
		out_buffer[size] = '\0';
	}

	return (ssize_t)ret;
}

static const struct librecrypt_algorithm rot4_algo = {
	.is_algorithm = &rot4_is_algorithm,
	.test_supported = &rot4_supported,
	.make_settings = &rot4_make_settings,
	.encoding_lut = encoding_lut,
	.decoding_lut = decoding_lut,
	.hash_size = 8u,
	.flexible_hash_size = 0,
	.strict_pad = 1,
	.pad = '#'
};

static const struct librecrypt_algorithm trunc_algo = {
	.is_algorithm = &trunc_is_algorithm,
	.test_supported = &trunc_supported,
	.make_settings = &trunc_make_settings,
	.encoding_lut = encoding_lut,
	.decoding_lut = decoding_lut,
	.hash_size = 4u,
	.flexible_hash_size = 1,
	.strict_pad = 1,
	.pad = '@'
};


static unsigned char saltbyte = 0u;


static ssize_t
saltgen(void *out, size_t n, void *user)
{
	if (!n)
		return 0;
	*(unsigned char *)out = *(unsigned char *)user;
	return 1;
}


static ssize_t
saltfail(void *out, size_t n, void *user)
{
	(void) out;
	(void) n;
	(void) user;
	errno = EDOM;
	return -1;
}


int
main(void)
{
	const struct librecrypt_algorithm custom[] = {rot4_algo, trunc_algo};
	LIBRECRYPT_CONTEXT *ctx = librecrypt_create_context();
	char buf[1024];
	char buf2[sizeof(buf)];
	int any_supported = 0;
	int any_salted = 0;
	ssize_t r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, ">", 0u, 0u, 0, NULL, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, "$argon2id$>", 0u, 0u, 0, NULL, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, ">$argon2id$", 0u, 0u, 0, NULL, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, "$argon2id$>$argon2id$", 0u, 0u, 0, NULL, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, "$~no~such~algorithm~$", 0u, 0u, 0, NULL, NULL, NULL) == -1);
	EXPECT(errno == ENOSYS);

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2_V1_3)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2i$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte, NULL);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2i$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

#if defined(SUPPORT_ARGON2D) && defined(SUPPORT_ARGON2_V1_3)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2d$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte, NULL);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2d$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

#if defined(SUPPORT_ARGON2ID) && defined(SUPPORT_ARGON2_V1_3)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2id$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte, NULL);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2id$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

#if defined(SUPPORT_ARGON2DS) && defined(SUPPORT_ARGON2_V1_3)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2ds$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte, NULL);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2ds$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

	if (any_supported) {
		EXPECT(librecrypt_make_settings(NULL, 0u, NULL, 0u, 0u, 0, NULL, NULL, NULL) > 0);
		EXPECT(librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 0, NULL, NULL, NULL) > 0);

		if (any_salted) {
			errno = 0;
			EXPECT(librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 1, &saltfail, NULL, NULL) == -1);
			EXPECT(errno == EDOM);
		} else {
			EXPECT(librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 1, &saltfail, NULL, NULL) > 0);
		}

		CANARY_FILL(buf);
		CANARY_FILL(buf2);
		r = librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 0, &saltfail, NULL, NULL);
		EXPECT(r > 0 && (size_t)r < sizeof(buf));
		EXPECT(!buf[r] && (size_t)r == strlen(buf));
		EXPECT(librecrypt_make_settings(buf2, sizeof(buf2), NULL, 0u, 0u, 0, &saltfail, NULL, NULL) == r);
		EXPECT(!buf2[r] && (size_t)r == strlen(buf2));
		EXPECT(!strcmp(buf, buf2));
		CANARY_CHECK(buf, (size_t)r + 1u);
		CANARY_CHECK(buf2, (size_t)r + 1u);

		CANARY_FILL(buf);
		CANARY_FILL(buf2);
		r = librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 0, NULL, NULL, NULL);
		EXPECT(r > 0 && (size_t)r < sizeof(buf));
		EXPECT(!buf[r] && (size_t)r == strlen(buf));
		EXPECT(librecrypt_make_settings(buf2, sizeof(buf2), NULL, 0u, 0u, 0, NULL, NULL, NULL) == r);
		EXPECT(!buf2[r] && (size_t)r == strlen(buf2));
		EXPECT(!strcmp(buf, buf2));
		CANARY_CHECK(buf, (size_t)r + 1u);
		CANARY_CHECK(buf2, (size_t)r + 1u);

		CANARY_FILL(buf);
		CANARY_FILL(buf2);
		r = librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 1, NULL, NULL, NULL);
		EXPECT(r > 0 && (size_t)r < sizeof(buf));
		EXPECT(!buf[r] && (size_t)r == strlen(buf));
		EXPECT(librecrypt_make_settings(buf2, sizeof(buf2), NULL, 0u, 0u, 1, NULL, NULL, NULL) == r);
		EXPECT(!buf2[r] && (size_t)r == strlen(buf2));
		EXPECT(strcmp(buf, buf2));
		CANARY_CHECK(buf, (size_t)r + 1u);
		CANARY_CHECK(buf2, (size_t)r + 1u);
	} else {
		errno = 0;
		EXPECT(librecrypt_make_settings(NULL, 0u, NULL, 0u, 0u, 0, NULL, NULL, NULL) == -1);
		EXPECT(errno == ENOSYS);
	}

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));

	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$rot4$", 0u, 0u, 0, NULL, NULL, ctx);
	EXPECT(r == (ssize_t)(sizeof("$rot4$") - 1u));
	EXPECT(!strcmp(buf, "$rot4$"));
	CANARY_CHECK(buf, (size_t)r + 1u);

	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$trunc$", 0u, 0u, 0, NULL, NULL, ctx);
	EXPECT(r == (ssize_t)(sizeof("$trunc$*4") - 1u));
	EXPECT(!strcmp(buf, "$trunc$*4"));
	CANARY_CHECK(buf, (size_t)r + 1u);

	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$trunc$*6", 0u, 0u, 0, NULL, NULL, ctx);
	EXPECT(r == (ssize_t)(sizeof("$trunc$*4") - 1u));
	EXPECT(!strcmp(buf, "$trunc$*4"));
	CANARY_CHECK(buf, (size_t)r + 1u);

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
