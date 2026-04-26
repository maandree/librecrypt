/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_realise_salts(char *restrict out_buffer, size_t size, const char *settings,
                         ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	const char *lut;
	char pad;
	int strict_pad, has_asterisk, nul_term = 0;
	size_t i, j, n, min, ret = 0u;
	size_t count, digit, q, r, left, mid, right;

	if (size) {
		nul_term = 1;
		size -= 1u;
	}

	for (;;) {
		for (; *settings == LIBRECRYPT_ALGORITHM_LINK_DELIMITER; settings++) {
			if (size) {
				*out_buffer++ = LIBRECRYPT_ALGORITHM_LINK_DELIMITER;
				size -= 1u;
			}
			ret += 1u;
		}

		if (!*settings)
			break;

		has_asterisk = 0;
		for (n = 0u; settings[n] && settings[n] != LIBRECRYPT_ALGORITHM_LINK_DELIMITER; n++)
			if (settings[n] == '*')
				has_asterisk = 1;

		if (!has_asterisk) {
			min = size < n ? size : n;
			memcpy(out_buffer, settings, min);
			out_buffer += min;
			settings = &settings[n];
			ret += n;
			continue;
		}

		if (*settings == '*') {
			errno = EINVAL;
			return -1;
		}

		lut = librecrypt_get_encoding(settings, n, &pad, &strict_pad, 0);
		if (!lut)
			return -1;
		pad = strict_pad ? pad : '\0';

		for (i = 0; i < n;) {
			if (settings[i] != '*') {
				if (size) {
					*out_buffer++ = settings[i];
					size -= 1u;
				}
				ret += 1u;
				i++;
				continue;
			}

			if (++i == n) {
				if (size) {
					*out_buffer++ = '*';
					size -= 1u;
				}
				ret += 1u;
				break;
			}
			if ('0' > settings[i] || settings[i] > '9') {
				if (size) {
					*out_buffer++ = '*';
					size -= 1u;
				}
				ret += 1u;
				continue;
			}

			count = 0;
			for (; i < n && '0' <= settings[i] && settings[i] <= '9'; i++) {
				digit = (size_t)(settings[i] - '0');
				if (count > ((size_t)SSIZE_MAX - digit) / 10u)
					goto erange;
				count *= 10u;
				count += digit;
			}

			q = count / 3u;
			r = count % 3u;
			mid = r ? r + 1u : 0u;
			right = (!r ? 0u : pad ? 4u : r + 1u);
			if (q > ((size_t)SSIZE_MAX - right) / 4u)
				goto erange;
			left = q * 4u;
			ret += left + mid + right;

			left += mid;
			if (left > size) {
				left = size;
				mid = 0;
			}
			if (librecrypt_fill_with_random_(out_buffer, left, rng, user))
				return -1;
			for (j = 0; j < left; j++)
				out_buffer[j] = lut[((unsigned char *)out_buffer)[j]];
			if (mid)
				out_buffer[j] = lut[((unsigned char *)out_buffer)[j] & (r == 1u ? ~15u : ~3u)];
			out_buffer = &out_buffer[left];
			size -= left;

			if (right > size)
				right = size;
			for (j = 0; j < right; j++)
				out_buffer[right] = pad;
			out_buffer = &out_buffer[right];
			size -= right;
		}
	}

	if (nul_term)
		*out_buffer = '\0';
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

	return 0;
}


#endif
/* TODO test */
