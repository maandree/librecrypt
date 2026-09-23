/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_test_supported(const char *phrase, size_t len, int text, const char *settings, LIBRECRYPT_CONTEXT *ctx)
{
	const struct librecrypt_algorithm *algo;
	size_t n;

	/* For each chained algorithm */
	for (;;) {
		/* Measure until next '>' */
		for (n = 0u; settings[n]; n++)
			if (settings[n] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;

		/* Identify algorithm */
		algo = librecrypt_find_first_algorithm_(settings, n, ctx);
		if (!algo)
			return 0;

		/* Check configuration and input support, and get hash size */
		if (!(*algo->test_supported)(phrase, len, text, settings, n, &len))
			return 0;

		/* Return if just processed last chained algorithm */
		if (!settings[n])
			return 1;

		/* Hashes are binary */
		phrase = NULL;
		text = 0;

		/* Go to next algorithm */
		settings = &settings[n]; /* conf */
		settings++; /* '>' */
	}
}


#else
# ifndef FUZZ


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

static const struct librecrypt_algorithm rot4_algo = {
	.is_algorithm = &rot4_is_algorithm,
	.test_supported = &rot4_supported,
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
	.encoding_lut = encoding_lut,
	.decoding_lut = decoding_lut,
	.hash_size = 4u,
	.flexible_hash_size = 1,
	.strict_pad = 1,
	.pad = '@'
};

#define NSA "$~no~such~algorithm~$"


#define CHECK(ALGO, VALID, INVALID)\
	do {\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO VALID, ctx) == 1);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO VALID">"NSA, ctx) == 0);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, NSA">"ALGO VALID, ctx) == 0);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO VALID">"ALGO VALID, ctx) == 1);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO INVALID, ctx) == 0);\
	} while (0)


int
main(void)
{
	const struct librecrypt_algorithm custom[] = {rot4_algo, trunc_algo};
	LIBRECRYPT_CONTEXT *ctx = NULL;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, NSA, NULL) == 0);
	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, NSA">", NULL) == 0);
	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, ">"NSA, NULL) == 0);
	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, NSA">"NSA, NULL) == 0);

	IF__argon2i_v1_3__SUPPORTED(CHECK("$argon2i$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2d_v1_3__SUPPORTED(CHECK("$argon2d$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2id_v1_3__SUPPORTED(CHECK("$argon2id$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2ds_v1_3__SUPPORTED(CHECK("$argon2ds$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));

	IF__argon2i_v1_0__SUPPORTED(CHECK("$argon2i$v=16$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2d_v1_0__SUPPORTED(CHECK("$argon2d$v=16$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2id_v1_0__SUPPORTED(CHECK("$argon2id$v=16$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2ds_v1_0__SUPPORTED(CHECK("$argon2ds$v=16$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));

	IF__argon2i_v1_0__SUPPORTED(CHECK("$argon2i$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2d_v1_0__SUPPORTED(CHECK("$argon2d$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2id_v1_0__SUPPORTED(CHECK("$argon2id$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2ds_v1_0__SUPPORTED(CHECK("$argon2ds$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));
	CHECK("$rot4$", "", "x");
	CHECK("$trunc$", "", "*0");
	CHECK("$trunc$", "*6", "*0");
	EXPECT(librecrypt_test_supported(NULL, 4096u, 0, "$rot4$>$trunc$", ctx) == 1);
	EXPECT(librecrypt_test_supported(NULL, 4096u, 0, "$rot4$>$trunc$*8", ctx) == 1);
	EXPECT(librecrypt_test_supported(NULL, 4096u, 0, "$trunc$*6>$rot4$", ctx) == 1);
	EXPECT(librecrypt_test_supported(NULL, 4096u, 0, "$trunc$>$rot4$", ctx) == 1);

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


# else


extern volatile int discarded_return_value;
volatile int discarded_return_value;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const void *phrase;
	size_t len;
	int text;
	char *settings;

	if (size < 4u)
		return 0;

	text = (int)data[0u] & 1;
	len = (size_t)data[1u];
	if (len > size - 2u)
		return 0;
	phrase = &data[2u];
	data = &data[2u + len];
	size -= 2u + len;
	settings = malloc(size + 1u);
	assert(settings);
	memcpy(settings, data, size);
	settings[size] = '\0';

	discarded_return_value = librecrypt_test_supported(phrase, len, text, settings, NULL);

	free(settings);
	return 0;
}


# endif
#endif
