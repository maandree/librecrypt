/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const void *
librecrypt_get_encoding(const char *settings, size_t len, char *pad_out, int *strict_pad_out, int decoding, void *reserved)
{
	size_t i, start = 0u;
	const struct algorithm *algo;

	/* Ensure the reserved parameter is NULL */
	if (reserved != NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* Find last algorithm in the chain */
	for (i = 0u; i < len; i++)
		if (settings[i] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
			start = i + 1u;
	settings = &settings[start];
	len -= start;

	/* Identify the algorithm */
	algo = librecrypt_find_first_algorithm_(settings, len);
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
		elut = librecrypt_get_encoding(PREFIX, sizeof(PREFIX) - 1u, &pad, &strict_pad, 0, NULL);\
		EXPECT(elut != NULL);\
		EXPECT(pad == (PAD));\
		EXPECT(strict_pad == (STRICT_PAD));\
		EXPECT(check_encoding_lut(elut, ALPHABET));\
		\
		pad = (char)~(PAD);\
		strict_pad = -1;\
		dlut = librecrypt_get_encoding(PREFIX, sizeof(PREFIX) - 1u, &pad, &strict_pad, 1, NULL);\
		EXPECT(dlut != NULL);\
		EXPECT(pad == (PAD));\
		EXPECT(strict_pad == (STRICT_PAD));\
		EXPECT(check_decoding_lut(dlut, ALPHABET));\
		\
		pad = (char)~(PAD);\
		strict_pad = -1;\
		elut = librecrypt_get_encoding(NSA">"PREFIX, sizeof(NSA">"PREFIX) - 1u, &pad, &strict_pad, 0, NULL);\
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
	char reserved[1] = {0};
	const char *elut;
	const unsigned char *dlut;
	char pad;
	int strict_pad;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_get_encoding("$argon2i$", sizeof("$argon2i$") - 1u, &pad, &strict_pad, 0, reserved) == NULL);
	EXPECT(errno == EINVAL);

	errno = 0;
	EXPECT(librecrypt_get_encoding(NSA, sizeof(NSA) - 1u, &pad, &strict_pad, 0, NULL) == NULL);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_get_encoding(NSA, sizeof(NSA) - 1u, &pad, &strict_pad, 1, NULL) == NULL);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_get_encoding(">"NSA, sizeof(">"NSA) - 1u, &pad, &strict_pad, 0, NULL) == NULL);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_get_encoding(">"NSA, sizeof(">"NSA) - 1u, &pad, &strict_pad, 1, NULL) == NULL);
	EXPECT(errno == ENOSYS);

	IF__argon2i__SUPPORTED(CHECK("$argon2i$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2d__SUPPORTED(CHECK("$argon2d$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2id__SUPPORTED(CHECK("$argon2id$", UPPER LOWER DIGIT "+/", '=', 0);)
	IF__argon2ds__SUPPORTED(CHECK("$argon2ds$", UPPER LOWER DIGIT "+/", '=', 0);)

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
