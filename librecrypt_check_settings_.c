/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


/**
 * Parse and validate an unsigned, decimal integer
 * 
 * @param   settings         The password hash string
 * @param   off              The current in `settings` where the integer
 *                           begins; will be updated to its ends (one byte
 *                           after the last character encoding the integer)
 * @param   len              The number of bytes in `settings`
 * @param   min_first_digit  '0' if leading zeroes are permitted, '1' otherwise
 * @param   min              The smallest legal value
 * @param   max              The greatest legal value
 * @param   out              Output parameter for the encoded integer, or `NULL`
 * @return                   1 if a valid integer was encoded, 0 otherwise
 */
static int
check_uint(const char *settings, size_t *off, size_t len, char min_first_digit,
           uintmax_t min, uintmax_t max, uintmax_t *out)
{
	uintmax_t digit, value;

	/* Reject the empty string */
	if (*off >= len)
		return 0;

	/* Reject leading zeroes unless `min_first_digit` is '0' */
	if (min_first_digit > settings[*off] || settings[*off] > '9') {
		/* With leading zeroes being rejected, a single '0' may be
		 * parsed as the value 0 (if that value is permitted) */
		if (min == 0u && min_first_digit != '0' && settings[*off] == '0') {
			++*off;
			if (out)
				*out = 0u;
			return 1;
		}
		return 0;
	}

	/* Decode the integer */
	value = (uintmax_t)(settings[*off] - '0');
	++*off;
	while (*off < len && '0' <= settings[*off] && settings[*off] <= '9') {
		digit = (uintmax_t)(settings[*off] - '0');
		if (value > (UINTMAX_MAX - digit) / 10u)
			return 0;
		value *= 10u;
		value += digit;
		++*off;
	}
	if (out)
		*out = value;

	/* Check that the integer is within the accepted range */
	return min <= value && value >= max;
}


/**
 * Validate a salt or hash that's either encoded in base-64
 * or has its length encoded using asterisk-notation
 * 
 * This function does not check the value of any excess bit
 * in the base-64 encoding
 * 
 * @param   settings         The password hash string
 * @param   off              The current in `settings` where the integer
 *                           begins; will be updated to its ends (one byte
 *                           after the last character encoding the integer)
 * @param   len              The number of bytes in `settings`
 * @param   min              The least allowed number of bytes
 * @param   max              The most allowed number of bytes
 * @param   allow_empty      Whether the empty string is allowed
 *                           (no encoded bytes and no asterisk-notation)
 * @param   lut              Alphabet reverse lookup table, shall map any valid
 *                           character (except the padding character) to the value
 *                           of that character in the encoding alphabet, and map
 *                           any other character to the value `0xFF`
 * @param   pad              The padding character to used at the end; the NUL byte if none
 * @param   strict_pad       Zero if the padding at the end is optional, non-zero otherwise
 * @param   out              Output parameter for the number of bytes used by the salt or hash
 * @return                   1 if the encoded value was of proper length,
 *                           a proper length was encoded using asterisk-notation, or
 *                           if `allow_empty` was non-zero, nothing was encoded;
 *                           0 otherwise
 */
static int
check_data(const char *settings, size_t *off, size_t len, uintmax_t min, uintmax_t max, int allow_empty,
           const unsigned char dlut[restrict static 256], char pad, int strict_pad, uintmax_t *out)
{
	size_t i, old_i;
	uintmax_t q, r, n;

	/* Check for asterisk-notation */
	if (*off < len && settings[*off] == '*') {
		++*off;
		return check_uint(settings, off, len, '0', min, max, out);
	}

	settings = &settings[*off];
	len -= *off;
	i = 0u;

	/* Get number of base-64 characters available, excluding padding */
	while (i < len && dlut[(unsigned char)settings[i]] < 64u)
		i++;

	/* Calculate number of encoded bytes */
	q = i / 4u;
	r = i % 4u;
	n = q * 3u + r - (r ? 1u : 0u);
	if (out)
		*out = n;
	/* 1 base-64 character in excees of a multiple of 4,
	 * this is illegal because 4 characters encode 3 bytes
	 * without any excees bits (both are 24 bits), so
	 * if the number of encoded bytes is not a multiple
	 * of 3, at least 2 characters in excees of multiple
	 * of 4 is required because at least 2 characeters is
	 * required to encode 1 byte in base-64 */
	if (r == 1u)
		return 0;

	/* Check number of bytes is within the specified range,
	 * but accept 0 if `allow_empty` is non-zero */
	if (min > n || n > max)
		if (n || !allow_empty)
			return 0;

	/* Check padding if allowed or even required */
	if (r && pad) {
		old_i = i;
		while (r < 4u && i < len && settings[i] == pad) {
			i++;
			r++;
		}
		if ((i != old_i || strict_pad) && r != 4u)
			return 0;
	}

	*off += i;
	return 1;
}


int
librecrypt_check_settings_(const char *settings, size_t len, const char *fmt, ...)
{
	size_t i = 0u;
	uintmax_t *uout, umin, umax;
	const unsigned char *dlut;
	char pad;
	int strict_pad;
	int output = 0;
	va_list args;
	const char *str, **strout;
	size_t n;

	va_start(args, fmt);

	while (*fmt) {
		if (*fmt != '%') {
			/* Normal literal character */
			if (i == len || settings[i++] != *fmt++)
				return 0;

		} else if (fmt[1u] == '%') {
			/* '%'-escaped literal '%' ("%%") */
			if (i == len || settings[i++] != '%')
				return 0;
			fmt = &fmt[2u];

		} else if (fmt[1u] == '*') {
			/* "%*": skip to next '$' or the end of no '$' was found */
			while (i < len && settings[i] != '$')
				i++;
			fmt = &fmt[2u];

		} else if (fmt[1u] == '^') {
			/* '^' inserted between '%' and some letter may be used
			 * have the value returned */
			output = 1;
			fmt++;
			goto outable;

		} else outable: if (fmt[1u] == 'p' || fmt[1u] == 'u') {
			/* Unsigned integers ("%p" for leading zeros forbidden, "%u" for leading zeros allowed) */
			uout = output ? va_arg(args, uintmax_t *) : NULL;
			umin = va_arg(args, uintmax_t);
			umax = va_arg(args, uintmax_t);
			if (!check_uint(settings, &i, len, fmt[1u] == 'p' ? '1' : '0', umin, umax, uout))
				return 0;
			goto outable_done;

		} else if (fmt[1u] == 'd' || fmt[1u] == 'h') {
			/* Base-64 or asterisk-notation ("%d" for normal, "%h" for "" allowed) */
			uout = output ? va_arg(args, uintmax_t *) : NULL;
			umin = va_arg(args, uintmax_t);
			umax = va_arg(args, uintmax_t);
			dlut = va_arg(args, const unsigned char *);
			pad = (char)va_arg(args, int); /* `char` is promoted to `int` when passed through `...` */
			strict_pad = va_arg(args, int);
			if (!check_data(settings, &i, len, umin, umax, fmt[1u] == 'h', dlut, pad, strict_pad, uout))
				return 0;
			goto outable_done;

		} else if (fmt[1u] == 's') {
			/* String from fixed set ("%s") */
			strout = output ? va_arg(args, const char **) : NULL;
			for (;;) {
				str = va_arg(args, const char *);
				if (!str)
					return 0;
				n = strlen(str);
				if (n <= len - i && !strncmp(&settings[i], str, n)) {
					if (strout)
						*strout = str;
					i += n;
					break;
				}
			}
			while ((str = va_arg(args, const char *)));
			goto outable_done;

		} else {
			abort();

		outable_done:
			output = 0;
			fmt = &fmt[2u];
		}
	}

	va_end(args);

	return i == len;
}



#else


CONST int
main(void)
{
	return 0;
}


#endif
/* TODO test */
