/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_realise_salts(char *restrict out_buffer, size_t size, const char *settings,
                         ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	const char *lut;
	char pad;
	int strict_pad, nul_term = 0;
	size_t i, min, nasterisks, prefix, ret = 0u;
	size_t count, digit, q, r, left, mid, right;

	/* If we are doing output, it should be NUL-terminated */
	if (size) {
		nul_term = 1;
		size -= 1u;
	}

	/* For each chained algorithm */
	while (*settings) {
		/* Get the number of '*' that are not in the result
		 * (hash size specification), and also length of
		 * the algorithm configuration, so we can identify
		 * the algorithm next and get its binary data encoding
		 * format (just calling librecrypt_get_encoding on the
		 * entire string would get it for the last algorithm
		 * in the chain) */
		nasterisks = 0u;
		count = 0u;
		for (prefix = 0u; settings[prefix]; prefix++) {
			if (settings[prefix] == LIBRECRYPT_HASH_COMPOSITION_DELIMITER)
				nasterisks = count;
			else if (settings[prefix] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;
			else if (settings[prefix] == '*')
				count += 1u;
		}

		/* Get binary data encoding format */
		lut = librecrypt_get_encoding(settings, prefix, &pad, &strict_pad, 0);
		if (!lut)
			return -1;
		pad = strict_pad ? pad : '\0';

		/* Process each asterisk-encoded salt */
		while (nasterisks--) {
			/* Copy text before next '*' */
			for (i = 0u; settings[i] != '*'; i++);
			min = i < size ? i : size;
			memcpy(out_buffer, settings, min);
			size -= min;
			settings = &settings[i];
			ret += i;

			/* Skip past the '*' */
			settings++;

			/* If the '*' is not followed by an unsigned,
			 * decimal integer include it literally */
			if ('0' > settings[1u] || settings[1u] > '9') {
				if (size) {
					*out_buffer++ = '*';
					size -= 1u;
				}
				ret += 1u;
				continue;
			}

			/* Parse encoded integer */
			count = 0u;
			while ('0' <= *settings && *settings <= '9') {
				digit = (size_t)(*settings++ - '0');
				if (count > ((size_t)SSIZE_MAX - digit) / 10u)
					goto erange;
				count *= 10u;
				count += digit;
			}

			/* Get number of random base-64 characters to generated,
			 * and the number of padding characters to append */
			/* 1 byte (8 bits) requires 2 base-64 characters (12 bits, 4 bits extra),
			 * 2 bytes (16 bits) requires 3 base-64 characters (18 bits, 2 bits extra), and
			 * 3 bytes (25 bits) requires 4 base-64 characters (24 bits) exactly */
			q = count / 3u;
			r = count % 3u;
			/* Full alphabet */
			left = q * 4u + r;
			/* Partial alphabet (extra bits are encoded as 0) */
			mid = r ? 1u : 0u;
			/* Padding: r==0: no padding,
			 *          r==1: 2 base-64 characters, so 2 padding characters,
			 *          r==2: 3 base-64 characters, so 1 padding characters */
			right = (r && pad) ? 3u - r : 0u;
			/* Get total length */
			if (q > ((size_t)SSIZE_MAX - right) / 4u)
				goto erange;
			ret += left + mid + right;

			/* Make sure we don't write more random characters than
			 * we have room for; we add `mid` into `left` so we have
			 * one variable for all random characters */
			left += mid;
			if (left > size) {
				left = 0u;
				mid = 0u;
			}

			/* Write random characters */
			if (librecrypt_fill_with_random_(out_buffer, left, rng, user))
				return -1;
			for (i = 0u; i < left; i++)
				out_buffer[i] = lut[((unsigned char *)out_buffer)[i]];
			if (mid) {
				i = left - 1u;
				out_buffer[i] = lut[((unsigned char *)out_buffer)[i] & (r == 1u ? ~15u : ~3u)];
			}
			out_buffer = &out_buffer[left];
			size -= left;

			/* Write padding charaters */
			right = right < size ? right : size;
			for (i = 0u; i < right; i++)
				out_buffer[right] = pad;
			out_buffer = &out_buffer[right];
			size -= right;
		}

		/* Copy remainder of the algorithm configuration, and the '>' if intermediate */
		for (i = 0u; settings[i];)
			if (settings[i++] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;
		min = i < size ? i : size;
		memcpy(out_buffer, settings, min);
		size -= min;
		settings = &settings[i];
		ret += i;
	}

	/* NUL-terminate the output if we were doing output */
	if (nul_term)
		*out_buffer = '\0';

	/* Return the number of written bytes (excluding NUL byte):
	 * the length of the new password hash string, but ensure
	 * the new salts where not so large that our return value
	 * is out of range */
	if (ret > (size_t)SSIZE_MAX)
		goto erange;
	return (ssize_t)ret;

erange:
	errno = ERANGE;
	return -1;
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
