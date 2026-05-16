/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_test_supported(const char *phrase, size_t len, int text, const char *settings, void *reserved)
{
	const struct algorithm *algo;
	size_t n;

	/* For each chained algorithm */
	for (;;) {
		/* Measure until next '>' */
		for (n = 0u; settings[n]; n++)
			if (settings[n] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;

		/* Identify algorithm */
		algo = librecrypt_find_first_algorithm_(settings, n);
		if (!algo)
			return 0;

		/* Check configuration and input support, and get hash size */
		if (!(*algo->test_supported)(phrase, len, text, settings, n, &len))
			return 0;

		/* Return just process last chained algorithm */
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


#define NSA "$~no~such~algorithm~$"


#define CHECK(ALGO, VALID, INVALID)\
	do {\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO VALID, NULL) == 1);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO VALID">"NSA, NULL) == 0);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, NSA">"ALGO VALID, NULL) == 0);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO VALID">"ALGO VALID, NULL) == 1);\
		EXPECT(librecrypt_test_supported(NULL, 4096u, 0, ALGO INVALID, NULL) == 0);\
	} while (0)


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, NSA, NULL) == 0);
	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, NSA">", NULL) == 0);
	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, ">"NSA, NULL) == 0);
	EXPECT(librecrypt_test_supported("abcdefgh", 8u, 1, NSA">"NSA, NULL) == 0);

	IF__argon2i__SUPPORTED(CHECK("$argon2i$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2d__SUPPORTED(CHECK("$argon2d$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2id__SUPPORTED(CHECK("$argon2id$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));
	IF__argon2ds__SUPPORTED(CHECK("$argon2ds$v=19$", "m=8,t=1,p=1$*16$*40", "m=0,t=0,p=0$*1$*1"));

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
