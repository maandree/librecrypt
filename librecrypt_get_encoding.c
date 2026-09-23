/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const void *
librecrypt_get_encoding(const char *settings, size_t len, char *pad_out, int *strict_pad_out,
                        int decoding, LIBRECRYPT_CONTEXT *ctx)
{
	size_t i, start = 0u;
	const struct librecrypt_algorithm *algo;

	/* Find last algorithm in the chain */
	for (i = 0u; i < len; i++)
		if (settings[i] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
			start = i + 1u;
	settings = &settings[start];
	len -= start;

	/* Identify the algorithm */
	algo = librecrypt_find_first_algorithm_(settings, len, ctx);
	if (!algo) {
		errno = ENOSYS;
		return NULL;
	}

	/* Return the algorithms salt/hash encoding format */
	*pad_out = algo->pad;
	*strict_pad_out = algo->strict_pad;
	if (decoding)
		return algo->decoding_lut;
	else
		return algo->encoding_lut;
}


#else
# ifndef FUZZ


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

static const struct librecrypt_algorithm rot4_algo = {
	.is_algorithm = &rot4_is_algorithm,
	.encoding_lut = encoding_lut,
	.decoding_lut = decoding_lut,
	.hash_size = 8u,
	.flexible_hash_size = 0,
	.strict_pad = 1,
	.pad = '#'
};

static const struct librecrypt_algorithm trunc_algo = {
	.is_algorithm = &trunc_is_algorithm,
	.encoding_lut = alt_encoding_lut,
	.decoding_lut = alt_decoding_lut,
	.hash_size = 4u,
	.flexible_hash_size = 1,
	.strict_pad = 1,
	.pad = '@'
};

#define NSA "$~no~such~algorithm~$"


static int
check_encoding_lut(const char *lut, const char *alpha)
{
	size_t i;
	for (i = 0u; i < 256u; i++)
		if (lut[i] != alpha[i % 64u])
			return 0;
	return 1;
}


static int
check_decoding_lut(const unsigned char *lut, const char *alpha)
{
	size_t i, invalid_count = 0u;
	for (i = 0u; i < 64u; i++)
		if (lut[(unsigned char)alpha[i]] != (unsigned char)i)
			return 0;
	for (i = 0u; i < 256u; i++) {
		if (lut[i] == 0xFFu)
			invalid_count += 1u;
		else
			EXPECT(lut[i] < 64u);
	}
	return invalid_count == 256u - 64u;
}


#define CHECK(PREFIX, ALPHABET, PAD, STRICT_PAD) \
	do {\
		pad = (char)~(PAD);\
		strict_pad = -1;\
		elut = librecrypt_get_encoding(PREFIX, sizeof(PREFIX) - 1u, &pad, &strict_pad, 0, ctx);\
		EXPECT(elut != NULL);\
		EXPECT(pad == (PAD));\
		EXPECT(strict_pad == (STRICT_PAD));\
		EXPECT(check_encoding_lut(elut, ALPHABET));\
		\
		pad = (char)~(PAD);\
		strict_pad = -1;\
		dlut = librecrypt_get_encoding(PREFIX, sizeof(PREFIX) - 1u, &pad, &strict_pad, 1, ctx);\
		EXPECT(dlut != NULL);\
		EXPECT(pad == (PAD));\
		EXPECT(strict_pad == (STRICT_PAD));\
		EXPECT(check_decoding_lut(dlut, ALPHABET));\
		\
		pad = (char)~(PAD);\
		strict_pad = -1;\
		elut = librecrypt_get_encoding(NSA">"PREFIX, sizeof(NSA">"PREFIX) - 1u, &pad, &strict_pad, 0, ctx);\
		EXPECT(elut != NULL);\
		EXPECT(pad == (PAD));\
		EXPECT(strict_pad == (STRICT_PAD));\
		EXPECT(check_encoding_lut(elut, ALPHABET));\
	} while (0)


#define DIGIT "0123456789"
#define LOWER "abcdefghijklmnopqrstuvwxyz"
#define UPPER "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


int
main(void)
{
	const struct librecrypt_algorithm custom[] = {rot4_algo, trunc_algo};
	LIBRECRYPT_CONTEXT *ctx = NULL;
	const char *elut;
	const unsigned char *dlut;
	char pad;
	int strict_pad;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_get_encoding(NSA, sizeof(NSA) - 1u, &pad, &strict_pad, 0, ctx) == NULL);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_get_encoding(NSA, sizeof(NSA) - 1u, &pad, &strict_pad, 1, ctx) == NULL);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_get_encoding(">"NSA, sizeof(">"NSA) - 1u, &pad, &strict_pad, 0, ctx) == NULL);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_get_encoding(">"NSA, sizeof(">"NSA) - 1u, &pad, &strict_pad, 1, ctx) == NULL);
	EXPECT(errno == ENOSYS);

	IF__argon2i_v1_0__SUPPORTED(CHECK("$argon2i$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2d_v1_0__SUPPORTED(CHECK("$argon2d$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2id_v1_0__SUPPORTED(CHECK("$argon2id$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2ds_v1_0__SUPPORTED(CHECK("$argon2ds$", UPPER LOWER DIGIT "+/", '=', 0);)

	IF__argon2i_v1_3__SUPPORTED(CHECK("$argon2i$v=19$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2d_v1_3__SUPPORTED(CHECK("$argon2d$v=19$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2id_v1_3__SUPPORTED(CHECK("$argon2id$v=19$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2ds_v1_3__SUPPORTED(CHECK("$argon2ds$v=19$", UPPER LOWER DIGIT "+/", '=', 0);)

	ctx = librecrypt_create_context();
	assert(ctx != NULL);

	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));
	CHECK("$rot4$", ALPHABET, '#', 1);
	CHECK("$trunc$", ALT_ALPHABET, '@', 1);
	CHECK("$trunc$*4", ALT_ALPHABET, '@', 1);
	CHECK("$rot4$>$trunc$", ALT_ALPHABET, '@', 1);
	CHECK("$rot4$>$trunc$*4", ALT_ALPHABET, '@', 1);
	CHECK("$trunc$>$rot4$", ALPHABET, '#', 1);
	CHECK("$trunc$*4>$rot4$", ALPHABET, '#', 1);

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}



# else


extern const void *volatile discarded_return_value;
const void *volatile discarded_return_value;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *settings;
	int decoding;
	if (size < 1u)
		return 0;
	decoding = (int)data[0u] & 1;
	settings = (const void *)&data[1u];
	size -= 1u;
	discarded_return_value = librecrypt_get_encoding(settings, size, &(char){0}, &(int){0}, decoding, NULL);
	return 0;
}


# endif
#endif
