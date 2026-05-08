/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wformat-truncation=" /* we rely on snprintf(3) doing truncation */
#endif


ssize_t
librecrypt_add_algorithm(char *out_buffer, size_t size, char *augend, const char *restrict augment, void *reserved)
{
	size_t prefix1, prefix2, min, ret, len, phraselen;
	size_t hashsize1, hashsize2;
	char *phrase, pad;
	int strict_pad, r_int, nul_term;
	const unsigned char *lut;
	ssize_t r;

#define COPY_PREFIX()\
	do {\
		min = prefix1 < size ? prefix1 : size;\
		if (out_buffer != augend)\
			memmove(out_buffer, augend, min);\
		out_buffer = &out_buffer[min];\
		size -= min;\
	} while (0)

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

	/* If `augend` specifies as hash size rather than a hash, include it as the prefix */
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
			COPY_PREFIX();
			if (size) {
				*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
				size -= 1u;
			}
			min = prefix2 < size ? prefix2 : size;
			memcpy(out_buffer, augment, min);
			if (hashsize2) {
				r_int = snprintf(&out_buffer[min], size + 1u, "*%zu", hashsize2);
				if (r_int < 2)
					abort();
				ret += (size_t)r_int;
			} else {
				out_buffer[min] = '\0';
			}
		} else {
			r_int = snprintf(NULL, 0, "*%zu", hashsize2);
			if (r_int < 2)
				abort();
			ret += (size_t)r_int;
		}
		return (ssize_t)ret;
	}

	/* Measure size of hash size specification for `augend` */
	if (hashsize1) {
		r_int = snprintf(NULL, 0, "*%zu", hashsize1);
		if (r_int < 2)
			abort();
	} else {
		r_int = 0;
	}

	/* Measure `augent` and '>' in output */
	ret = prefix1 + (size_t)r_int + 1u;

	/* Decode the hash from base-64 to binary */
	if (size <= ret + prefix2 + 1u) {
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
		r = librecrypt_decode(NULL, 0, &augend[prefix1], len, lut, pad, strict_pad);
		if (r <= 0) {
			if (!r)
				abort();
			return -1;
		}
		phraselen = (size_t)r;

		/* Decode old hash from ASCII to binary */
		phrase = malloc(phraselen);
		if (!phrase)
			return -1;
		if (librecrypt_decode(phrase, phraselen, &augend[prefix1], len, lut, pad, strict_pad) != r)
			abort();
	}

	/* Chain the hash algorithms: write `augent` */
	COPY_PREFIX();
	if (hashsize1 && size)
		if (snprintf(out_buffer, size + 1u, "*%zu", hashsize1) != r_int)
			abort();

	/* Chain the hash algorithms: write '>' */
	if (size) {
		*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
		size -= 1u;
	}

	/* Chain the hash algorithms: write `augment` and hash */
	r = librecrypt_crypt(out_buffer, size + (nul_term ? 1u : 0u), phrase, phraselen, augment, reserved);
	if (r <= 0) {
		librecrypt_wipe(phrase, phraselen);
		free(phrase);
		if (!r)
			abort();
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
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
/* TODO test */
