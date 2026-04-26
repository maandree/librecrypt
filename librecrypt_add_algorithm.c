/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_add_algorithm(char *out_buffer, size_t size, char *augend, const char *restrict augment, void *reserved)
{
	size_t prefix1 = librecrypt_settings_prefix(augend);
	size_t prefix2, min, ret, len, phraselen;
	char *phrase, pad;
	int strict_pad;
	const unsigned char *lut;
	ssize_t r;

#define COPY_PREFIX()\
	do {\
		size -= 1u;\
		min = prefix1 < size ? prefix1 : size;\
		if (out_buffer != augend)\
			memmove(out_buffer, augend, min);\
		out_buffer = &out_buffer[min];\
		size -= min;\
		if (size) {\
			*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;\
			size -= 1u;\
		}\
	} while (0)

	if (!augend[prefix1]) {
		prefix2 = librecrypt_settings_prefix(augment);
		ret = prefix1 + 1u + prefix2;
		if (size) {
			COPY_PREFIX();
			min = prefix2 < size ? prefix2 : size;
			memcpy(out_buffer, augment, min);
			out_buffer[min] = '\0';
		}
		return (ssize_t)ret;
	}

	if (size <= prefix1 + 2u) {
		phrase = NULL;
		phraselen = 0u;
	} else {
		lut = librecrypt_get_encoding(augend, strlen(augend), &pad, &strict_pad, 1);
		if (!lut)
			return -1;

		len = strlen(&augend[prefix1]);
		r = librecrypt_decode(NULL, 0, &augend[prefix1], len, lut, pad, strict_pad);
		if (r <= 0) {
			if (!r)
				abort();
			return -1;
		}
		phraselen = (size_t)r;
		phrase = malloc(phraselen);
		if (!phrase)
			return -1;
		if (librecrypt_decode(phrase, phraselen, &augend[prefix1], len, lut, pad, strict_pad) != r)
			abort();
	}

	COPY_PREFIX();
	ret = prefix1 + 1u;
	r = librecrypt_crypt(out_buffer, size + 1u, phrase, phraselen, augment, reserved);
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

	return 0;
}


#endif
/* TODO test */
