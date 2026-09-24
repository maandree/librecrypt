/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


static ssize_t
zero_generator(void *out, size_t n, void *user)
{
	(void) user;
	if (n > (size_t)SSIZE_MAX)
		n = (size_t)SSIZE_MAX; /* $covered$ (impossible, but covered otherwise) */
	memset(out, 0, n);
	return (ssize_t)n;
}


PURE static int
has_asterisk_encoded_salt(const char *settings)
{
	int asterisk = 0;
	for (; *settings; settings++) {
		if (*settings == '*') {
			/* Require digit after '*' to recognise as asterisk-encoding */
			if ('0' <= settings[1u] && settings[1u] <= '9') {
				settings++;
				asterisk = 1;
			}
		} else if (*settings == LIBRECRYPT_HASH_COMPOSITION_DELIMITER) {
			/* If asterisk was found before a '$' in an algorithm
			 * it it was for the salt (or other random parameter) */
			if (asterisk)
				return 1;
		} else if (*settings == LIBRECRYPT_ALGORITHM_LINK_DELIMITER) {
			/* If asterisk was found between '$' and '>', it was
			 * the hash size specificiation */
			asterisk = 0;
		}
	}
	/* If asterisk was found after the last '$' or '>', or if
	 * there was no '$', it was the hash size specificiation */
	return 0;
}


ssize_t
librecrypt_hash_(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                 const char *settings, LIBRECRYPT_CONTEXT *ctx, enum action action)
{
	struct concat_state concat_state = {out_buffer, size, 0u};
	const struct librecrypt_algorithm *algo;
	ssize_t (*rng)(void *out, size_t n, void *user) = NULL;
	char *settings_scratch = NULL;
	char *phrase_scratches[2] = {NULL, NULL};
	size_t phrase_scratch_sizes[2] = {0u, 0u};
	size_t i, n, ascii_len, prefix, hash_size, digit;
	int r, saved_errno, has_next, phrase_scratch_i = 0;
	ssize_t r_len;
	void *new;

	/* Realise asterisk-encoded salts */
	if (has_asterisk_encoded_salt(settings)) {
		/* Only `librecrypt_crypt` outputs the configrations,
		 * and thus only `librecrypt_crypt` outputs salts, so
		 * `librecrypt_hash` and `librecrypt_hash_binary` may
		 * not use asterisk-encoding for salts as the generated
		 * salt would be lost (use `librecrypt_realise_salts`
		 * first instead) */
		if (action != ASCII_CRYPT)
			goto einval;

		/* If there no output, don't waste time and entropy
		 * generating random salts, just write generates
		 * zeroes instead */
		if (!concat_state.size)
			rng = &zero_generator;

		/* Generate the salts */
		r_len = librecrypt_realise_salts(NULL, 0u, settings, rng, NULL, ctx);
		if (r_len < 0) {
			if (errno == ERANGE) {
				errno = ENOMEM;
				return -1;
			}
			return -1;
		}
		settings_scratch = malloc((size_t)r_len + 1u);
		if (!settings_scratch)
			return -1;
		if (librecrypt_realise_salts(settings_scratch, (size_t)r_len + 1u, settings, rng, NULL, ctx) != r_len)
			abort(); /* $covered$ (impossible) */
		settings = settings_scratch;
	}

next:
	/* Measure algorithm configuration size until next-algorithm marker (or end of string) */
	has_next = 0;
	for (n = 0u; settings[n]; n++) {
		if (settings[n] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER) {
			has_next = 1;
			break;
		}
	}

	/* Identify the algorithm */
	algo = librecrypt_find_first_algorithm_(settings, n, ctx);
	if (!algo) {
		errno = ENOSYS;
		goto fail;
	}

	/* Get length of algorithm configuration text sans hash size */
	prefix = 0u;
	for (i = 0u; i < n; i++)
		if (settings[i] == LIBRECRYPT_HASH_COMPOSITION_DELIMITER)
			prefix = i + 1u;
	if (n && !prefix && settings[i] == '_') {
		/* Special case for bsdicrypt */
		prefix = 1u; /* $covered$ (TODO we currently don't have an algorithm to trigger this) */
	}

	/* Get hash size */
	if (prefix == n) {
		/* default */
		hash_size = algo->hash_size;
	} else if (settings[prefix] == '*') {
		/* hash length encoded, not allowed when fixed */
		if (!algo->flexible_hash_size)
			goto einval;
		i = prefix + 1u;
		hash_size = 0u;
		for (; i < n; i++) {
			if ('0' > settings[i] || settings[i] > '9')
				goto einval;
			digit = (size_t)(settings[i] - '0');
			if (hash_size > (SIZE_MAX - digit) / 10u)
				goto einval;
			hash_size = hash_size * 10u + digit;
		}
		if (!hash_size)
			goto einval;
	} else if (has_next) {
		/* hash encoded, but is intermediate hash */
		goto einval;
	} else {
		/* hash encoded, and is final hash */
		for (i = prefix; i < n; i++)
			if (algo->decoding_lut[(unsigned char)settings[i]] == 0xFFu)
				break;
		hash_size = i - prefix;
		if (algo->pad && algo->strict_pad) {
			for (; i < n; i++)
				if (settings[i] != algo->pad)
					break;
			if (!librecrypt_is_base64_properly_padded_(hash_size, i - prefix))
				goto einval;
		}
		if (i != n)
			goto einval;
		if (!librecrypt_base64_len_to_raw_len_(hash_size, &hash_size))
			goto einval;
		/* Must align with fixed hash size when hash size is fixed */
		if (!algo->flexible_hash_size && hash_size != algo->hash_size)
			goto einval;
	}

	/* For `librecrypt_crypt`: copy hash configurations to output */
	if (action == ASCII_CRYPT) {
		if (has_next) {
			/* Include hash length specification */
			prefix = n;
		}
		librecrypt_concat_mem_(&concat_state, settings, prefix);
	}

	/* Unless output is fully truncated, ensure scratch for intermediate hash is large enough */
	if (concat_state.size && phrase_scratch_sizes[phrase_scratch_i] < hash_size) {
		librecrypt_wipe(phrase_scratches[phrase_scratch_i], phrase_scratch_sizes[phrase_scratch_i]);
		new = realloc(phrase_scratches[phrase_scratch_i], hash_size);
		if (!new) {
			free(phrase_scratches[phrase_scratch_i]);
			phrase_scratches[phrase_scratch_i] = NULL;
			phrase_scratch_sizes[phrase_scratch_i] = 0u;
			errno = ENOMEM;
			goto fail;
		}
		phrase_scratches[phrase_scratch_i] = new;
		phrase_scratch_sizes[phrase_scratch_i] = hash_size;
	}

	/* Calculate intermediate or final hash */
	if (has_next) {
		/* Intermediate hash: write to scratch */
	hash_to_scratch:
		r = (*algo->hash)(concat_state.size ? phrase_scratches[phrase_scratch_i] : NULL,
		                  concat_state.size ? phrase_scratch_sizes[phrase_scratch_i] : 0u,
		                  phrase, len, settings, n, ctx);
	} else if (action == BINARY_HASH) {
		/* Final hash in binary: write immediate to output */
	hash_to_output:
		r = (*algo->hash)(concat_state.buf, concat_state.size, phrase, len, settings, n, ctx);
	} else if (concat_state.size < hash_size) {
		/* Final hash in ASCII: write to scratch if output is truncated,
		 * because it will be converted to ASCII later */
		goto hash_to_scratch;
	} else {
		/* Final hash in ASCII: write immedate to output if it fits,
		 * will be converted to ASCII later */
		goto hash_to_output;
	}
	if (r < 0)
		goto fail;

	/* Maybe convert to ASCII and get hash size */
	if (!has_next) {
		/* Final hash: */
		if (action == BINARY_HASH) {
			/* Binary output: we already have the has in binary,
			 * so yes add the length to the return value */
			if (concat_state.len != 0u)
				abort(); /* $covered$ (impossible) */
			concat_state.len += hash_size;
		} else if (!concat_state.size) {
			/* ASCII hash but not output: just calculate the
			 * ASCII length and add it to the return value */
			if (!librecrypt_raw_len_to_base64_len_(hash_size, algo->pad && algo->strict_pad, &ascii_len))
				goto eoverflow; /* $covered$ (on 32-bit, impossible on wider) */
			goto include_ascii;
		} else {
			/* ASCII output: convert from binary to ASCII,
			 * and add ASCII length to the return value */
			ascii_len = librecrypt_encode(concat_state.buf, concat_state.size,
			                              concat_state.size < hash_size
			                                  ? phrase_scratches[phrase_scratch_i] : concat_state.buf,
			                              hash_size, algo->encoding_lut, algo->strict_pad ? algo->pad : '\0');
			/* SIZE_MAX could mean success, however we will
			 * fail when convert `concat_state.len` from size_t
			 * to ssize_t, so we can treat SIZE_MAX as failure
			 * even when it's a success */
			if (ascii_len == SIZE_MAX)
				goto eoverflow; /* $covered$ (manually) */
	include_ascii:
			if (librecrypt_post_concat_adjust_(&concat_state, ascii_len))
				goto eoverflow; /* $covered$ (on 32-bit) */
		}
	} else {
		/* Intermediate hash: */

		/* Swap scratches, so that the intermediate output
		 * becomes the next algorithm's input, but use NULL if output is
		 * truncated (measure only) */
		phrase = concat_state.size ? phrase_scratches[phrase_scratch_i] : NULL;
		phrase_scratch_i ^= 1;
		len = hash_size;

		/* Seek past the algorithm settings */
		settings = &settings[n];
		/* and the '>' */
		settings++;

		/* For `librecrypt_crypt`: add '>' to the password hash string */
		if (action == ASCII_CRYPT)
			librecrypt_concat_char_no_nul_(&concat_state, LIBRECRYPT_ALGORITHM_LINK_DELIMITER);

		/* Calculate the hash, from the intermediate output */
		goto next;
	}

	/* Erase and deallocate scratch memory */
	if (phrase_scratches[0u]) {
		librecrypt_wipe(phrase_scratches[0u], phrase_scratch_sizes[0u]);
		free(phrase_scratches[0u]);
	}
	if (phrase_scratches[1u]) {
		librecrypt_wipe(phrase_scratches[1u], phrase_scratch_sizes[1u]);
		free(phrase_scratches[1u]);
	}
	if (settings_scratch) {
		librecrypt_wipe_str(settings_scratch);
		free(settings_scratch);
	}

	/* NUL-terminate output if it is a string (`out_buffer` is offset at every write to it) */
	if (concat_state.size && action != BINARY_HASH)
		concat_state.buf[0] = '\0';

	if (concat_state.len > (size_t)SSIZE_MAX) {
		/* $covered{$ (manually) */
		errno = EOVERFLOW;
		return -1;
		/* $covered}$ */
	}
	return (ssize_t)concat_state.len;

	/* $covered{$ (since we have covered gotos to this label) */
eoverflow:
	errno = EOVERFLOW;
	goto fail;
	/* $covered}$ */
einval:
	errno = EINVAL;
fail:
	saved_errno = errno;
	if (phrase_scratches[0u]) {
		librecrypt_wipe(phrase_scratches[0u], phrase_scratch_sizes[0u]);
		free(phrase_scratches[0u]);
	}
	if (phrase_scratches[1u]) {
		librecrypt_wipe(phrase_scratches[1u], phrase_scratch_sizes[1u]);
		free(phrase_scratches[1u]);
	}
	if (settings_scratch) {
		librecrypt_wipe_str(settings_scratch);
		free(settings_scratch);
	}
	errno = saved_errno;
	return -1;
}


#else


/* Mainly tested via librecrypt_hash_binary, librecrypt_hash, and librecrypt_crypt */


#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
NONSTRING static const char elut[256u] = MAKE_ENCODING_LUT(ALPHABET);
#undef ALPHABET

static const unsigned char dlut[256u] = {
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
add1_is_algorithm(const char *settings, size_t len)
{
	if (len >= sizeof("$add1$") - 1u)
		if (!strncmp(settings, "$add1$", sizeof("$add1$") - 1u))
			return 1u;
	return 0u;
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
add1_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
          const char *settings, size_t prefix, LIBRECRYPT_CONTEXT *ctx)
{
	size_t i;

	(void) settings;
	(void) prefix;
	(void) ctx;

	for (i = 0u; i < 8u && i < size; i++) {
		out_buffer[i] = '\0';
		if (i < len)
			out_buffer[i] = (char)(unsigned char)((unsigned)(unsigned char)phrase[i] + 1u);
	}

	return 0;
}

static const struct librecrypt_algorithm rot4_algo = {
	.is_algorithm = &rot4_is_algorithm,
	.hash = &rot4_hash,
	.encoding_lut = elut,
	.decoding_lut = dlut,
	.hash_size = 8u,
	.flexible_hash_size = 0,
	.strict_pad = 1,
	.pad = '#'
};

static const struct librecrypt_algorithm add1_algo = {
	.is_algorithm = &add1_is_algorithm,
	.hash = &add1_hash,
	.encoding_lut = elut,
	.decoding_lut = dlut,
	.hash_size = 8u,
	.flexible_hash_size = 0,
	.strict_pad = 1,
	.pad = '#'
};


int
main(void)
{
#define SALT "saltSALTsaltSALTsaltSALTsaltSALTsaltSALT"
#define LARGE "99999999999999999999999999999999999999999999999999999999999999999999999999"
#define X2(X) X">"X
#define X3(X) X">"X">"X
#define X4(X) X">"X">"X">"X

	char buf[1024];
	char buf1[sizeof(buf)];
	char buf2[sizeof(buf)];
	char buf3[sizeof(buf)];
	char sbuf[160];
	size_t i, n;
	ssize_t r, r1, r1b, r1c, r2, r3;
	LIBRECRYPT_CONTEXT *ctx = NULL;
	struct librecrypt_algorithm custom[] = {rot4_algo, add1_algo};

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

start_over:

	errno = 0;
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, "$~no~such~algorithm~$", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == ENOSYS);

	errno = 0;
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, "$~no~such~algorithm~$*100$", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == ENOSYS);

#if defined(SUPPORT_ARGON2ID) && defined(SUPPORT_ARGON2_V1_3)
# define ARGON2ID_PREFIX "$argon2id$v=19$m=8,t=1,p=1$"
# define ARGON2ID_STR ARGON2ID_PREFIX SALT"$*32"

	CANARY_FILL(buf);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), "hello", 5u, "!"ARGON2ID_STR, ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == ENOSYS);
	CANARY_CHECK(buf, 0u);

	CANARY_FILL(buf);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), "hello", 5u, ARGON2ID_PREFIX"*"LARGE"$", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == ENOMEM);
	CANARY_CHECK(buf, sizeof(ARGON2ID_PREFIX"*"));

	r = librecrypt_hash_(NULL, 0u, "hello", 5u, ARGON2ID_PREFIX"*1000$", ctx, ASCII_CRYPT);
	EXPECT(r > 0);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, ARGON2ID_PREFIX"*1000$", ctx, ASCII_CRYPT) == r);
	for (i = 0u; i <= sizeof(sbuf); i++) {
		CANARY_FILL(sbuf);
		EXPECT(librecrypt_hash_(sbuf, i, NULL, 0u, ARGON2ID_PREFIX"*1000$", ctx, ASCII_CRYPT) == r);
		CANARY_X_CHECK(sbuf, MIN(i, (size_t)r), MIN(i, 32u));
	}

	if (libtest_have_custom_malloc()) {
		/* target if-statement in zero_generator, using alloc failure as guarding;
		 * however librecrypt_realise_salts should return ERANGE, which
		 * librecrypt_hash_ coverts to ENOMEM */
		libtest_set_alloc_failure_in(1u);
		r = (ssize_t)snprintf(buf, sizeof(buf), "%s*%zu$", ARGON2ID_PREFIX, (size_t)SSIZE_MAX + 1u);
		assert(r > 0 && r < (ssize_t)sizeof(buf));
		errno = 0;
		EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, buf, ctx, ASCII_CRYPT) == -1);
		EXPECT(errno == ENOMEM);
		libtest_set_alloc_failure_in(0u);

		/* target settings_scratch */
		errno = 0;
		libtest_set_alloc_failure_in(1u);
		EXPECT(librecrypt_hash_(NULL, 0u, "hello", 5u, ARGON2ID_PREFIX"*1000$", ctx, ASCII_CRYPT) == -1);
		EXPECT(errno == ENOMEM);
		EXPECT(libtest_get_alloc_failure_in() == 0u);

		/* target phrase_scratches */
		errno = 0;
		libtest_set_alloc_failure_in(1u);
		EXPECT(librecrypt_hash_(buf, sizeof(buf), "hello", 5u, X2(ARGON2ID_STR), ctx, ASCII_CRYPT) == -1);
		EXPECT(errno == ENOMEM);
		EXPECT(libtest_get_alloc_failure_in() == 0u);

		/* target *algo->hash */
		errno = 0;
		libtest_set_alloc_failure_in(2u);
		EXPECT(librecrypt_hash_(buf, sizeof(buf), "hello", 5u, X2(ARGON2ID_STR), ctx, ASCII_CRYPT) == -1);
		EXPECT(errno == ENOMEM);
		EXPECT(libtest_get_alloc_failure_in() == 0u);

		/* target deallocation of settings_scratch */
		errno = 0;
		libtest_set_alloc_failure_in(2u);
		EXPECT(librecrypt_hash_(buf, 1u, "hello", 5u, ARGON2ID_PREFIX"*1000$>"ARGON2ID_STR, ctx, ASCII_CRYPT) == -1);
		EXPECT(errno == ENOMEM);
		EXPECT(libtest_get_alloc_failure_in() == 0u);

		/* target deallocation of phrase_scratches[1] */
		libtest_set_alloc_failure_in(SIZE_MAX);
		EXPECT(librecrypt_hash_(buf, 1u, "hello", 5u, X3(ARGON2ID_STR), ctx, ASCII_CRYPT) > 0);
		n = SIZE_MAX - libtest_get_alloc_failure_in();
		errno = 0;
		libtest_set_alloc_failure_in(n);
		EXPECT(librecrypt_hash_(buf, 1u, "hello", 5u, X3(ARGON2ID_STR), ctx, ASCII_CRYPT) == -1);
		EXPECT(errno == ENOMEM);
		EXPECT(libtest_get_alloc_failure_in() == 0u);

	}

	CANARY_FILL(buf1);
	memset(buf1, 99, sizeof(buf1));
	r1 = librecrypt_hash_(buf1, sizeof(buf1), NULL, 0u, X2(ARGON2ID_STR), ctx, ASCII_CRYPT);
	EXPECT(r1 > 0);
	EXPECT(r1 > 2 * (ssize_t)sizeof(ARGON2ID_STR));
	r1b = librecrypt_hash_(buf, sizeof(buf), NULL, 0u, X3(ARGON2ID_STR), ctx, ASCII_CRYPT);
	EXPECT(r1b > 0);
	EXPECT(r1b == r1 + 1 * (ssize_t)sizeof(ARGON2ID_STR));
	r1c = librecrypt_hash_(buf, sizeof(buf), NULL, 0u, X4(ARGON2ID_STR), ctx, ASCII_CRYPT);
	EXPECT(r1c > 0);
	EXPECT(r1c == r1 + 2 * (ssize_t)sizeof(ARGON2ID_STR));

	CANARY_FILL(buf2);
	EXPECT((r2 = librecrypt_hash_(buf2, sizeof(buf2), NULL, 0u, X2(ARGON2ID_STR), ctx, ASCII_HASH)) > 0);
	EXPECT(librecrypt_hash_(buf, sizeof(buf), NULL, 0u, X3(ARGON2ID_STR), ctx, ASCII_HASH) == r2);
	EXPECT(librecrypt_hash_(buf, sizeof(buf), NULL, 0u, X4(ARGON2ID_STR), ctx, ASCII_HASH) == r2);
	EXPECT(r2 < r1);

	CANARY_FILL(buf3);
	EXPECT((r3 = librecrypt_hash_(buf3, sizeof(buf3), NULL, 0u, X2(ARGON2ID_STR), ctx, BINARY_HASH)) > 0);
	EXPECT(librecrypt_hash_(buf, sizeof(buf), NULL, 0u, X3(ARGON2ID_STR), ctx, BINARY_HASH) == r3);
	EXPECT(librecrypt_hash_(buf, sizeof(buf), NULL, 0u, X4(ARGON2ID_STR), ctx, BINARY_HASH) == r3);
	EXPECT(r3 < r2);

	assert((size_t)r1 < sizeof(buf) - 11u);
	for (i = (size_t)r1 + 11u; i < SIZE_MAX; i--) {
		if (i <= (size_t)r1 + 10u) {
			CANARY_C_FILL(88, buf);
			EXPECT(librecrypt_hash_(buf, i, NULL, 0u, X2(ARGON2ID_STR), ctx, ASCII_CRYPT) == r1);
			if (i) {
				n = MIN(i - 1u, (size_t)r1);
				EXPECT(!memcmp(buf, buf1, n));
				EXPECT(buf[n] == '\0');
			}
			CANARY_X_CHECK(buf, MIN(i, (size_t)r1), MIN(i, 32u));
		}
		if (i <= (size_t)r2 + 10u) {
			CANARY_C_FILL(88, buf);
			EXPECT(librecrypt_hash_(buf, i, NULL, 0u, X2(ARGON2ID_STR), ctx, ASCII_HASH) == r2);
			if (i) {
				n = MIN(i - 1u, (size_t)r2);
				EXPECT(!memcmp(buf, buf2, n));
				EXPECT(buf[n] == '\0');
			}
			CANARY_X_CHECK(buf, MIN(i, (size_t)r2), MIN(i, 32u));
		}
		if (i <= (size_t)r3 + 10u) {
			CANARY_C_FILL(88, buf);
			EXPECT(librecrypt_hash_(buf, i, NULL, 0u, X2(ARGON2ID_STR), ctx, BINARY_HASH) == r3);
			EXPECT(!memcmp(buf, buf3, MIN(i, (size_t)r3)));
			CANARY_X_CHECK(buf, MIN(i, (size_t)r3), MIN(i, 32u));
		}
	}

	CANARY_X_CHECK(buf1, (size_t)r1, 32u);
	CANARY_X_CHECK(buf2, (size_t)r2, 32u);
	CANARY_X_CHECK(buf3, (size_t)r3, 32u);

	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X2(ARGON2ID_STR), ctx, ASCII_CRYPT) == r1);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X3(ARGON2ID_STR), ctx, ASCII_CRYPT) == r1b);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X4(ARGON2ID_STR), ctx, ASCII_CRYPT) == r1c);

	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X2(ARGON2ID_STR), ctx, ASCII_HASH) == r2);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X3(ARGON2ID_STR), ctx, ASCII_HASH) == r2);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X4(ARGON2ID_STR), ctx, ASCII_HASH) == r2);

	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X2(ARGON2ID_STR), ctx, BINARY_HASH) == r3);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X3(ARGON2ID_STR), ctx, BINARY_HASH) == r3);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, X4(ARGON2ID_STR), ctx, BINARY_HASH) == r3);
#endif

	if (!ctx) {
		ctx = librecrypt_create_context();
		assert(ctx != NULL);
		goto start_over;
	}

	librecrypt_set_custom_algorithms(ctx, custom, ELEMSOF(custom));

	errno = 0;
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, "$rot4$*8", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);

	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, "$rot4$", ctx, ASCII_CRYPT) == (ssize_t)sizeof("$rot4$") - 1 + 12);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, "$rot4$", ctx, ASCII_HASH) == 12);
	EXPECT(librecrypt_hash_(NULL, 0u, NULL, 0u, "$rot4$", ctx, BINARY_HASH) == 8);

#define MSG "\x12\x23\x34\x45\x56\x67\x78\x89", 8u

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$", ctx, BINARY_HASH) == 8);
	assert(sizeof(buf) >= 8u);
	EXPECT(!memcmp(buf, "\x21\x32\x43\x54\x65\x76\x87\x98", 8u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$", ctx, ASCII_HASH) == 12);
	assert(sizeof(buf) >= 12u);
	EXPECT(!memcmp(buf, "ITJDVGV2h5g#", 12u + sizeof("")));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$", ctx, ASCII_CRYPT) == (ssize_t)sizeof("$rot4$") - 1 + 12);
	assert(sizeof(buf) >= sizeof("$rot4$") + 12u);
	EXPECT(!memcmp(buf, "$rot4$ITJDVGV2h5g#", sizeof("$rot4$") + 12u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$add1$", ctx, BINARY_HASH) == 8);
	assert(sizeof(buf) >= 8u);
	EXPECT(!memcmp(buf, "\x13\x24\x35\x46\x57\x68\x79\x8A", 8u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$add1$", ctx, ASCII_HASH) == 12);
	assert(sizeof(buf) >= 12u);
	EXPECT(!memcmp(buf, "EyQ1RldoeYo#", 12u + sizeof("")));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$add1$", ctx, ASCII_CRYPT) == (ssize_t)sizeof("$add1$") - 1 + 12);
	assert(sizeof(buf) >= sizeof("$add1$") + 12u);
	EXPECT(!memcmp(buf, "$add1$EyQ1RldoeYo#", sizeof("$add1$") + 12u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$>$add1$", ctx, BINARY_HASH) == 8);
	assert(sizeof(buf) >= 8u);
	EXPECT(!memcmp(buf, "\x22\x33\x44\x55\x66\x77\x88\x99", 8u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$>$add1$", ctx, ASCII_HASH) == 12);
	assert(sizeof(buf) >= 12u);
	EXPECT(!memcmp(buf, "IjNEVWZ3iJk#", 12u + sizeof("")));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$>$add1$", ctx, ASCII_CRYPT) == (ssize_t)sizeof("$rot4$>$add1$") - 1 + 12);
	assert(sizeof(buf) >= sizeof("$rot4$>$add1$") + 12u);
	EXPECT(!memcmp(buf, "$rot4$>$add1$IjNEVWZ3iJk#", sizeof("$rot4$>$add1$") + 12u));

	custom[0].flexible_hash_size = 1;
	custom[1].flexible_hash_size = 1;

	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA", ctx, BINARY_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA", ctx, ASCII_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#A", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#~", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAA#", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);

	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA##", ctx, BINARY_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA###", ctx, ASCII_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA####", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#####", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#", ctx, BINARY_HASH) == 8);
	assert(sizeof(buf) >= 8u);
	EXPECT(!memcmp(buf, "\x21\x32\x43\x54\x65\x76\x87\x98", 8u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#", ctx, ASCII_HASH) == 12);
	assert(sizeof(buf) >= 12u);
	EXPECT(!memcmp(buf, "ITJDVGV2h5g#", 12u + sizeof("")));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#", ctx, ASCII_CRYPT) == (ssize_t)sizeof("$rot4$") - 1 + 12);
	assert(sizeof(buf) >= sizeof("$rot4$") + 12u);
	EXPECT(!memcmp(buf, "$rot4$ITJDVGV2h5g#", sizeof("$rot4$") + 12u));

	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAA##", ctx, BINARY_HASH) == 7);
	EXPECT(!memcmp(buf, "\x21\x32\x43\x54\x65\x76\x87", 7u));
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAA###", ctx, BINARY_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAA####", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);

	custom[0].pad = 0;
	custom[1].pad = 0;

	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#", ctx, BINARY_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#", ctx, ASCII_HASH) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_hash_(buf, sizeof(buf), MSG, "$rot4$AAAAAAAAAAA#", ctx, ASCII_CRYPT) == -1);
	EXPECT(errno == EINVAL);

#undef msg

	librecrypt_free_context(ctx);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
