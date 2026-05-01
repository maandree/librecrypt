/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


static ssize_t
zero_generator(void *out, size_t n, void *user)
{
	(void) user;
	if (n > (size_t)SSIZE_MAX)
		n = (size_t)SSIZE_MAX;
	memset(out, 0, n);
	return (ssize_t)n;
}


static int
has_asterisk_encoded_salt(const char *settings)
{
	const char *asterisk;
	/* Check whether there is an asterisk */
	asterisk = strchr(settings, '*');
	if (!asterisk)
		return 0;
	/* Check that the first asterisk is not part of the hash result
	 * (would specify hash size) rather than be a salt */
	return !!strchr(&asterisk[1u], LIBRECRYPT_HASH_COMPOSITION_DELIMITER);
}


ssize_t
librecrypt_hash_(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                 const char *settings, void *reserved, enum action action)
{
	const struct algorithm *algo;
	ssize_t (*rng)(void *out, size_t n, void *user) = NULL;
	char *settings_scratch = NULL;
	char *phrase_scratches[2] = {NULL, NULL};
	size_t phrase_scratch_sizes[2] = {0u, 0u};
	size_t i, n, ascii_len, min, prefix, ret = 0u;
	size_t hash_size, digit, quotient, remainder;
	int has_next, phrase_scratch_i = 0;
	ssize_t r_len;
	int r;
	void *new;

	/* Ensure the reserved parameter is NULL */
	if (reserved != NULL)
		goto einval;

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
		if (!size)
			rng = &zero_generator;

		/* Generate the salts */
		r_len = librecrypt_realise_salts(out_buffer, size, settings, rng, NULL);
		if (r_len < 0) {
			if (errno == ERANGE)
				errno = ENOMEM;
			return -1;
		} else if ((size_t)r_len >= size) {
			settings_scratch = malloc((size_t)r_len + 1u);
			if (!settings_scratch)
				return -1;
			if (librecrypt_realise_salts(settings_scratch, (size_t)r_len + 1u, settings, rng, NULL) != r_len)
				abort();
			settings = settings_scratch;
		}
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
	algo = librecrypt_find_first_algorithm_(settings, n);
	if (!algo) {
		errno = ENOSYS;
		goto fail;
	}

	/* Get length of algorithm configuration text sans hash size */
	prefix = 0u;
	for (i = 0u; i < n; i++)
		if (settings[i] == LIBRECRYPT_HASH_COMPOSITION_DELIMITER)
			prefix = i + 1u;
	/* TODO "_" is a prefix that is being used */
	if (!algo->flexible_hash_size && prefix != n)
		goto einval;

	/* Get hash size */
	if (!algo->flexible_hash_size) {
		/* fixed */
		hash_size = algo->hash_size;
	} else if (prefix == n) {
		/* default */
		hash_size = algo->hash_size;
	} else if (settings[prefix] == '*') {
		/* hash length encoded */
		i = prefix + 1u;
		hash_size = 0u;
		for (; i < n; i++) {
			if ('0' > settings[i] || settings[i] > '9')
				goto einval;
			digit = (size_t)(settings[i] - '0');
			if (hash_size > (SIZE_MAX - digit) / 10u)
				goto einval;
			hash_size *= 10u;
			hash_size += digit;
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
			if (i - prefix % 4u)
				goto einval;
			if (i - prefix - hash_size >= 4u)
				goto einval;
		}
		if (i != n)
			goto einval;
		quotient = hash_size / 4u;
		remainder = hash_size % 4u;
		if (remainder == 1u)
			goto einval;
		hash_size = quotient * 3u + (remainder ? remainder - 1u : 0u);
	}

	/* For `librecrypt_crypt`: copy hash configurations to output */
	if (action == ASCII_CRYPT) {
		if (has_next) {
			/* Include hash length specification */
			prefix = n;
		}
		min = size ? size - 1u < prefix ? size - 1u : prefix : 0u;
		size -= min;
		memcpy(out_buffer, settings, min);
		out_buffer = &out_buffer[min];
		ret += prefix;
	}

	/* Unless output is fully truncated, ensure scratch for intermediate hash is large enough */
	if (size && phrase_scratch_sizes[phrase_scratch_i] < hash_size) {
		librecrypt_wipe(phrase_scratches[phrase_scratch_i], phrase_scratch_sizes[phrase_scratch_i]);
		new = realloc(phrase_scratches[phrase_scratch_i], hash_size);
		if (!new) {
			free(phrase_scratches[phrase_scratch_i]);
			phrase_scratches[phrase_scratch_i] = NULL;
			phrase_scratch_sizes[phrase_scratch_i] = 0u;
			goto fail;
		}
		phrase_scratches[phrase_scratch_i] = new;
		phrase_scratch_sizes[phrase_scratch_i] = hash_size;
	}

	/* Calculate intermediate or final hash */
	if (has_next) {
		/* Intermediate hash: write to scratch */
	hash_to_scratch:
		r = (*algo->hash)(size ? phrase_scratches[phrase_scratch_i] : NULL,
		                  size ? phrase_scratch_sizes[phrase_scratch_i] : 0u,
		                  phrase, len, settings, n, reserved);
	} else if (action == BINARY_HASH) {
		/* Final hash in binary: write immediate to output */
	hash_to_output:
		r = (*algo->hash)(out_buffer, size, phrase, len, settings, n, reserved);
	} else if (size < hash_size) {
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
			ret += hash_size;
		} else if (!size) {
			/* ASCII hash but not output: just calculate the
			 * ASCII length and add it to the return value */
			ascii_len = hash_size % 3u;
			if (ascii_len) {
				if (algo->pad && algo->strict_pad)
					ascii_len = 4u; /* padding to for bytes */
				else
					ascii_len += 1u; /* 3n+m bytes: 4n+m+1 chars, unless m=0 */
			}
			ascii_len += hash_size / 3u * 4u;
			goto include_ascii;
		} else {
			/* ASCII output: convert from binary to ASCII,
			 * and add ASCII length to the return value */
			ascii_len = librecrypt_encode(out_buffer, size,
			                              size < hash_size ? phrase_scratches[phrase_scratch_i] : out_buffer,
			                              hash_size, algo->encoding_lut, algo->strict_pad ? algo->pad : '\0');
	include_ascii:
			min = size ? size - 1u < ascii_len ? size - 1u : ascii_len : 0u;
			out_buffer = &out_buffer[min];
			size -= min;
			ret += ascii_len;
		}
	} else {
		/* Intermediate hash: */

		/* Swap scratches, so that the intermediate output
		 * becomes the next algorithm's input, but use NULL if output is
		 * truncated (measure only) */
		phrase = size ? phrase_scratches[phrase_scratch_i] : NULL;
		phrase_scratch_i ^= 1;
		len = hash_size;

		/* Seek past the algorithm settings */
		settings = &settings[n];
		/* and the '>' */
		settings++;

		/* For `librecrypt_crypt`: add '>' to the password hash string */
		if (action == ASCII_CRYPT) {
			ret += 1u;
			if (size) {
				*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
				size -= 1u;
			}
		}

		/* Calculate the hash, from the intermediate output */
		goto next;
	}

	/* Erase and deallocate scratch memory */
	librecrypt_wipe(phrase_scratches[0u], phrase_scratch_sizes[0u]);
	librecrypt_wipe(phrase_scratches[1u], phrase_scratch_sizes[1u]);
	librecrypt_wipe_str(settings_scratch);
	free(phrase_scratches[0u]);
	free(phrase_scratches[1u]);
	free(settings_scratch);

	/* NUL-terminate output if it is a string (`out_buffer` is offset at every write to it) */
	if (size && action != BINARY_HASH)
		out_buffer[0] = '\0';

	return (ssize_t)ret;

einval:
	errno = EINVAL;
fail:
	librecrypt_wipe(phrase_scratches[0u], phrase_scratch_sizes[0u]);
	librecrypt_wipe(phrase_scratches[1u], phrase_scratch_sizes[1u]);
	librecrypt_wipe_str(settings_scratch);
	free(phrase_scratches[0u]);
	free(phrase_scratches[1u]);
	free(settings_scratch);
	return -1;
}


#else


/* Tested via librecrypt_hash_binary, librecrypt_hash, and librecrypt_crypt */
CONST int main(void) { return 0; }


#endif
