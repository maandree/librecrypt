/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wformat-truncation=" /* we rely on snprintf(3) doing truncation */
#endif


ssize_t
librecrypt_add_algorithm(char *out_buffer, size_t size, const char *augend, const char *restrict augment, void *reserved)
{
	size_t prefix1, prefix2, min, ret, len, phraselen;
	size_t hashsize1, hashsize2;
	char *phrase, pad;
	int strict_pad, r_int, nul_term;
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
	prefix1 = librecrypt_settings_prefix(augend, &hashsize1);
	prefix2 = librecrypt_settings_prefix(augment, &hashsize2);

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
			ret += (size_t)r_int;
		out:
			if (nul_term)
				out_buffer[0u] = '\0';
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

	/* Measure `augent` and '>' in output */
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
		lut = librecrypt_get_encoding(augend, prefix1 + len, &pad, &strict_pad, 1);
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
	r = librecrypt_crypt(out_buffer, nul_term ? size + 1u : 0u, phrase, phraselen, augment, reserved);
	if (r <= 0) {
		librecrypt_wipe(phrase, phraselen);
		free(phrase);
		if (!r)
			abort(); /* $covered$ (impossible) */
		return -1;
	}
	ret += (size_t)r;

	librecrypt_wipe(phrase, phraselen);
	free(phrase);
	return (ssize_t)ret;
}


#else


int
main(void)
{
#define SALT1 "ABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd"
#define SALT2 "0123abcd0123ABCD0123abcd0123ABCD0123abcd0123ABCD0123abcd0123ABCD"
#define HASH1 "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTYVWXYZ/+"
#define ASTRA "*48"

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
		r = librecrypt_add_algorithm(buf, sizeof(buf), (AUGEND), (AUGMENT), NULL);\
		EXPECT(r > 0);\
		EXPECT((size_t)r == strlen(RESULT));\
		assert((size_t)r < sizeof(buf) + 1u);\
		EXPECT(!buf[r]);\
		EXPECT(!memcmp(buf, (RESULT), (size_t)r));\
		CANARY_CHECK(buf, (size_t)r + 1u);\
		\
		for (i = (size_t)r + 2u;; i--) {\
			CANARY_FILL(buf);\
			EXPECT(librecrypt_add_algorithm(buf, i, (AUGEND), (AUGMENT), NULL) == r);\
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
		EXPECT(librecrypt_add_algorithm(NULL, 0u, (AUGEND), (AUGMENT), NULL) == r);\
		\
		assert(sizeof(buf) > strlen(AUGEND));\
		\
		CANARY_FILL(buf);\
		stpcpy(buf, (AUGEND));\
		EXPECT(librecrypt_add_algorithm(buf, sizeof(buf), buf, (AUGMENT), NULL) == r);\
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
			EXPECT(librecrypt_add_algorithm(buf, i, buf, (AUGMENT), NULL) == r);\
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

#if defined(SUPPORT_ARGON2I) && defined(SUPPORT_ARGON2D)

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

	lut = librecrypt_get_encoding("$argon2d$", sizeof("$argon2d$") - 1u, &pad, &strict_pad, 1);
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

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
