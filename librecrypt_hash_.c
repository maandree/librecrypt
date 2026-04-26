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


ssize_t
librecrypt_hash_(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                 const char *settings, void *reserved, enum action action)
{
	const struct algorithm *algo;
	ssize_t (*rng)(void *out, size_t n, void *user) = NULL;
	char *settings_scratch = NULL;
	char *phrase_scratches[2] = {NULL, NULL};
	size_t phrase_scratch_sizes[2] = {0u, 0u};
	size_t n, ascii_len, min, prefix, ret = 0u;
	int has_next, phrase_scratch_i = 0;
	ssize_t r_len;
	int r;
	void *new;

	if (reserved != NULL) {
		errno = EINVAL;
		return -1;
	}

	if (!size)
		rng = &zero_generator;

	if (strchr(settings, '*')) {
		if (action != ASCII_CRYPT) {
			errno = EINVAL;
			return -1;
		}
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
	has_next = 0;
	for (n = 0u; settings[n]; n++) {
		if (settings[n] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER) {
			has_next = 1;
			break;
		}
	}

	algo = librecrypt_find_first_algorithm_(settings, n);
	if (!algo) {
		errno = ENOSYS;
		goto fail;
	}

	prefix = (*algo->get_prefix)(settings, n);
	if (has_next && prefix < n) {
		errno = EINVAL;
		goto fail;
	}

	if (action == ASCII_CRYPT) {
		min = size ? size - 1u < prefix ? size - 1u : prefix : 0u;
		size -= min;
		memcpy(out_buffer, settings, min);
		out_buffer = &out_buffer[min];
		ret += prefix;
	}

	if (size && phrase_scratch_sizes[phrase_scratch_i] < algo->hash_size) {
		librecrypt_wipe(phrase_scratches[phrase_scratch_i], phrase_scratch_sizes[phrase_scratch_i]);
		new = realloc(phrase_scratches[phrase_scratch_i], algo->hash_size);
		if (!new) {
			free(phrase_scratches[phrase_scratch_i]);
			phrase_scratches[phrase_scratch_i] = NULL;
			phrase_scratch_sizes[phrase_scratch_i] = 0u;
			goto fail;
		}
		phrase_scratches[phrase_scratch_i] = new;
		phrase_scratch_sizes[phrase_scratch_i] = algo->hash_size;
	}

	if (has_next) {
	hash_to_scratch:
		r = (*algo->hash)(size ? phrase_scratches[phrase_scratch_i] : NULL,
		                  size ? phrase_scratch_sizes[phrase_scratch_i] : 0u,
		                  phrase, len, settings, prefix, reserved);
	} else if (action == BINARY_HASH) {
	hash_to_output:
		r = (*algo->hash)(out_buffer, size, phrase, len, settings, prefix, reserved);
	} else if (size < algo->hash_size) {
		goto hash_to_scratch;
	} else {
		goto hash_to_output;
	}
	if (r < 0)
		goto fail;

	if (!has_next) {
		if (action == BINARY_HASH) {
			ret += algo->hash_size;
		} else if (!size) {
			ascii_len = algo->hash_size % 3u;
			if (ascii_len) {
				if (algo->pad && algo->strict_pad)
					ascii_len = 4u;
				else
					ascii_len += 1u;
			}
			ascii_len += algo->hash_size / 3u * 4u;
			goto include_ascii;
		} else {
			ascii_len = librecrypt_encode(out_buffer, size,
			                              size < algo->hash_size ? phrase_scratches[phrase_scratch_i] : out_buffer,
			                              algo->hash_size, algo->encoding_lut, algo->strict_pad ? algo->pad : '\0');
	include_ascii:
			min = size ? size - 1u < ascii_len ? size - 1u : ascii_len : 0u;
			out_buffer = &out_buffer[min];
			size -= min;
			ret += ascii_len;
		}
	} else {
		phrase = size ? phrase_scratches[phrase_scratch_i] : NULL;
		phrase_scratch_i ^= 1;
		len = algo->hash_size;

		settings = &settings[n];
		if (action == ASCII_CRYPT) {
			ret += 1u;
			if (size) {
				*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
				size -= 1u;
			}
		}
		settings++;
		goto next;
	}

	librecrypt_wipe(phrase_scratches[0u], phrase_scratch_sizes[0u]);
	librecrypt_wipe(phrase_scratches[1u], phrase_scratch_sizes[1u]);
	librecrypt_wipe_str(settings_scratch);
	free(phrase_scratches[0u]);
	free(phrase_scratches[1u]);
	free(settings_scratch);

	if (size && action != BINARY_HASH)
		out_buffer[0] = '\0';
	return (ssize_t)ret;

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
