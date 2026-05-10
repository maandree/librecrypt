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
	return min <= value && value <= max;
}


/**
 * Validate and returns a salt or hash that's either encoded
 * in base-64 or has its length encoded using asterisk-notation
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
 * @param   strout           Output parameter for the beginning of the base-64 text,
 *                           set to `NULL` if asterisk-notation is used
 * @param   lenout           Output parameter for the number of bytes in `*strout`, or if
 *                           `*strout` is set to `NULL`, the asterisk-encoded number;
 *                           however if `strout` is `NULL`, the number bytes used by
 *                           the salt or hash (when in raw binary format) is stored
 * @return                   1 if the encoded value was of proper length,
 *                           a proper length was encoded using asterisk-notation, or
 *                           if `allow_empty` was non-zero, nothing was encoded;
 *                           0 otherwise
 */
static int
check_data(const char *settings, size_t *off, size_t len, uintmax_t min, uintmax_t max, int allow_empty,
           const unsigned char dlut[restrict static 256], char pad, int strict_pad,
           const char **strout, uintmax_t *lenout)
{
	size_t i, old_i;
	uintmax_t q, r, n;

	/* Check for asterisk-notation */
	if (*off < len && settings[*off] == '*') {
		++*off;
		if (strout)
			*strout = NULL;
		return check_uint(settings, off, len, '0', min, max, lenout);
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
	if (!strout && lenout)
		*lenout = n;
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

	/* Return the base-64 encoding */
	if (strout) {
		*strout = settings;
		*lenout = (uintmax_t)i;
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

		} else if (fmt[1u] == '&' && (fmt[2u] == 'b' || fmt[2u] == 'h')) {
			/* Like "%b"/"%h" except output pointer to base-64 text or decodes asterisk-notation */
			strout = va_arg(args, const char **);
			uout = va_arg(args, uintmax_t *);
			fmt++;
			goto plain_bh;

		} else outable: if (fmt[1u] == 'p' || fmt[1u] == 'u') {
			/* Unsigned integers ("%p" for leading zeros forbidden, "%u" for leading zeros allowed) */
			uout = output ? va_arg(args, uintmax_t *) : NULL;
			umin = va_arg(args, uintmax_t);
			umax = va_arg(args, uintmax_t);
			if (!check_uint(settings, &i, len, fmt[1u] == 'p' ? '1' : '0', umin, umax, uout))
				return 0;
			goto outable_done;

		} else if (fmt[1u] == 'b' || fmt[1u] == 'h') {
			/* Base-64 or asterisk-notation ("%b" for normal, "%h" for "" allowed) */
			strout = NULL;
			uout = output ? va_arg(args, uintmax_t *) : NULL;
		plain_bh:
			umin = va_arg(args, uintmax_t);
			umax = va_arg(args, uintmax_t);
			dlut = va_arg(args, const unsigned char *);
			pad = (char)va_arg(args, int); /* `char` is promoted to `int` when passed through `...` */
			strict_pad = va_arg(args, int);
			if (!check_data(settings, &i, len, umin, umax, fmt[1u] == 'h', dlut, pad, strict_pad, strout, uout))
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
			abort(); /* $covered$ */

		outable_done:
			output = 0;
			fmt = &fmt[2u];
		}
	}

	va_end(args);

	return i == len;
}



#else


#define RANGE(A, B) (uintmax_t)(A), (uintmax_t)(B)
#define BASE64(A, B) RANGE(A, B), lut, pad, strict_pad


static unsigned char lut[256];


static void
check_asterisk(char pad, int strict_pad)
{
	uintmax_t u, u2;
	const char *s, *s2;

	EXPECT(librecrypt_check_settings_("*012", 4u, "%b", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*200", 4u, "%b", BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%b", BASE64(100, 200)) == 0);
	EXPECT(librecrypt_check_settings_("*0", 2u, "%b", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*00", 3u, "%b", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("", 0u, "%b", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("", 0u, "%b", BASE64(5, 100)) == 0);

	EXPECT(librecrypt_check_settings_("*012.", 5u, "%b.", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*012-", 5u, "%b.", BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%b.", BASE64(0, 100)) == 0);

	EXPECT(librecrypt_check_settings_("*2*5", 4u, "%b%b", BASE64(2, 2), BASE64(5, 5)) == 1);
	EXPECT(librecrypt_check_settings_("*2*4", 4u, "%b%b", BASE64(2, 2), BASE64(5, 5)) == 0);

	EXPECT(librecrypt_check_settings_("*012", 4u, "%h", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*200", 4u, "%h", BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%h", BASE64(100, 200)) == 0);
	EXPECT(librecrypt_check_settings_("*0", 2u, "%h", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*00", 3u, "%h", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("", 0u, "%h", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("", 0u, "%h", BASE64(5, 100)) == 1);

	EXPECT(librecrypt_check_settings_("*012.", 5u, "%h.", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*012-", 5u, "%h.", BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%h.", BASE64(0, 100)) == 0);

	EXPECT(librecrypt_check_settings_("*2*5", 4u, "%h%h", BASE64(2, 2), BASE64(5, 5)) == 1);
	EXPECT(librecrypt_check_settings_("*2*4", 4u, "%h%h", BASE64(2, 2), BASE64(5, 5)) == 0);

	u = 0u;
	EXPECT(librecrypt_check_settings_("*012", 4u, "%^b", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 12u);
	EXPECT(librecrypt_check_settings_("*200", 4u, "%^b", &u, BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%^b", &u, BASE64(100, 200)) == 0);
	u = 99u;
	EXPECT(librecrypt_check_settings_("*0", 2u, "%^b", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("*00", 3u, "%^b", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("", 0u, "%^b", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	EXPECT(librecrypt_check_settings_("", 0u, "%^b", &u, BASE64(5, 100)) == 0);

	EXPECT(librecrypt_check_settings_("*012.", 5u, "%^b.", &u, BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*012-", 5u, "%^b.", &u, BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%^b.", &u, BASE64(0, 100)) == 0);

	u = u2 = 99u;
	EXPECT(librecrypt_check_settings_("*2*5", 4u, "%^b%^b", &u, BASE64(2, 2), &u2, BASE64(5, 5)) == 1);
	EXPECT(u == 2u);
	EXPECT(u2 == 5u);
	EXPECT(librecrypt_check_settings_("*2*4", 4u, "%^b%^b", &u, BASE64(2, 2), &u2, BASE64(5, 5)) == 0);

	u = 0u;
	EXPECT(librecrypt_check_settings_("*012", 4u, "%^h", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 12u);
	EXPECT(librecrypt_check_settings_("*200", 4u, "%^h", &u, BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%^h", &u, BASE64(100, 200)) == 0);
	u = 99u;
	EXPECT(librecrypt_check_settings_("*0", 2u, "%^h", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("*00", 3u, "%^h", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("", 0u, "%^h", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("", 0u, "%^h", &u, BASE64(5, 100)) == 1);
	EXPECT(u == 0u);

	EXPECT(librecrypt_check_settings_("*012.", 5u, "%^h.", &u, BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("*012-", 5u, "%^h.", &u, BASE64(0, 100)) == 0);
	EXPECT(librecrypt_check_settings_("*012", 4u, "%^h.", &u, BASE64(0, 100)) == 0);

	u = u2 = 99u;
	EXPECT(librecrypt_check_settings_("*2*5", 4u, "%^h%^h", &u, BASE64(2, 2), &u2, BASE64(5, 5)) == 1);
	EXPECT(u == 2u);
	EXPECT(u2 == 5u);
	EXPECT(librecrypt_check_settings_("*2*4", 4u, "%^h%^h", &u, BASE64(2, 2), &u2, BASE64(5, 5)) == 0);

	s = "";
	u = 99u;
	EXPECT(librecrypt_check_settings_("*5.", 3, "%&b.", &s, &u, BASE64(2, 100)) == 1);
	EXPECT(s == NULL);
	EXPECT(u == 5u);

	s = "";
	u = 99u;
	EXPECT(librecrypt_check_settings_("*5", 2, "%&b", &s, &u, BASE64(2, 100)) == 1);
	EXPECT(s == NULL);
	EXPECT(u == 5u);

	EXPECT(librecrypt_check_settings_("*5", 2, "%&b", &s, &u, BASE64(1, 4)) == 0);
	EXPECT(librecrypt_check_settings_("*5", 2, "%&b", &s, &u, BASE64(6, 9)) == 0);

	s = s2 = "";
	u = u2 = 99u;
	EXPECT(librecrypt_check_settings_("*5*10", 5, "%&b%&b", &s, &u, BASE64(2, 100), &s2, &u2, BASE64(2, 100)) == 1);
	EXPECT(s == NULL);
	EXPECT(u == 5u);
	EXPECT(s2 == NULL);
	EXPECT(u2 == 10u);

	EXPECT(librecrypt_check_settings_("*", 1u, "%b", BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*", 1u, "%h", BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*", 1u, "%^b", &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*", 1u, "%^h", &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*", 1u, "%&b", &s, &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*", 1u, "%&h", &s, &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*x", 2u, "%b", BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*x", 2u, "%h", BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*x", 2u, "%^b", &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*x", 2u, "%^h", &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*x", 2u, "%&b", &s, &u, BASE64(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("*x", 2u, "%&h", &s, &u, BASE64(0, 10)) == 0);
}


static void
check_base64(char pad, int strict_pad)
{
	uintmax_t u;
	const char *s;

	EXPECT(librecrypt_check_settings_("", 0u, "%b", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("", 0u, "%b", BASE64(1, 100)) == 0);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%b", BASE64(3, 3)) == 1);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%b", BASE64(4, 4)) == 0);

	EXPECT(librecrypt_check_settings_("", 0u, "%h", BASE64(0, 100)) == 1);
	EXPECT(librecrypt_check_settings_("", 0u, "%h", BASE64(1, 100)) == 1);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%h", BASE64(3, 3)) == 1);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%h", BASE64(4, 4)) == 0);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%h", BASE64(2, 2)) == 0);

	u = 99u;
	EXPECT(librecrypt_check_settings_("", 0u, "%^b", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	EXPECT(librecrypt_check_settings_("", 0u, "%^b", &u, BASE64(1, 100)) == 0);
	u = 99u;
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%^b", &u, BASE64(3, 3)) == 1);
	EXPECT(u == 3u);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%^b", &u, BASE64(4, 4)) == 0);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%^b", &u, BASE64(2, 2)) == 0);

	u = 99u;
	EXPECT(librecrypt_check_settings_("", 0u, "%^h", &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("", 0u, "%^h", &u, BASE64(1, 100)) == 1);
	EXPECT(u == 0u);
	u = 99u;
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%^h", &u, BASE64(3, 3)) == 1);
	EXPECT(u == 3u);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%^h", &u, BASE64(4, 4)) == 0);
	EXPECT(librecrypt_check_settings_("abcd", 4u, "%^h", &u, BASE64(2, 2)) == 0);

	s = NULL;
	u = 99u;
	EXPECT(librecrypt_check_settings_("_", 1u, "_%&b", &s, &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	EXPECT(s && !strcmp(s, ""));
	EXPECT(librecrypt_check_settings_("_", 1u, "_%&b", &s, &u, BASE64(1, 100)) == 0);
	s = NULL;
	u = 99u;
	EXPECT(librecrypt_check_settings_("_abcd", 5u, "_%&b", &s, &u, BASE64(3, 3)) == 1);
	EXPECT(u == 4u);
	EXPECT(s && !strcmp(s, "abcd"));
	EXPECT(librecrypt_check_settings_("_abcd", 5u, "_%&b", &s, &u, BASE64(4, 4)) == 0);
	EXPECT(librecrypt_check_settings_("_abcd", 5u, "_%&b", &s, &u, BASE64(2, 2)) == 0);

	s = NULL;
	u = 99u;
	EXPECT(librecrypt_check_settings_("_", 1u, "_%&h", &s, &u, BASE64(0, 100)) == 1);
	EXPECT(u == 0u);
	EXPECT(s && !strcmp(s, ""));
	s = NULL;
	u = 99u;
	EXPECT(librecrypt_check_settings_("_", 1u, "_%&h", &s, &u, BASE64(1, 100)) == 1);
	EXPECT(u == 0u);
	EXPECT(s && !strcmp(s, ""));
	s = NULL;
	u = 99u;
	EXPECT(librecrypt_check_settings_("_abcd", 5u, "_%&h", &s, &u, BASE64(3, 3)) == 1);
	EXPECT(u == 4u);
	EXPECT(s && !strcmp(s, "abcd"));
	EXPECT(librecrypt_check_settings_("_abcd", 5u, "_%&h", &s, &u, BASE64(4, 4)) == 0);
	EXPECT(librecrypt_check_settings_("_abcd", 5u, "_%&h", &s, &u, BASE64(2, 2)) == 0);

	u = 99u;
	EXPECT(librecrypt_check_settings_("_abcd_", 6u, "_%&b_", &s, &u, BASE64(3, 3)) == 1);
	EXPECT(u == 4u);
	EXPECT(s && !strcmp(s, "abcd_"));
	u = 99u;
	EXPECT(librecrypt_check_settings_("_abcd_", 6u, "_%&h_", &s, &u, BASE64(3, 3)) == 1);
	EXPECT(u == 4u);
	EXPECT(s && !strcmp(s, "abcd_"));

	u = 99u;
	EXPECT(librecrypt_check_settings_("abcdabcd", 8u, "%&b", &s, &u, BASE64(6, 6)) == 1);
	EXPECT(u == 8u);
	EXPECT(s && strlen(s) == u);

	u = 99u;
	EXPECT(librecrypt_check_settings_("abcdabcd", 8u, "%&h", &s, &u, BASE64(6, 6)) == 1);
	EXPECT(u == 8u);
	EXPECT(s && strlen(s) == u);

	EXPECT(librecrypt_check_settings_("abcda", 5u, "%&b", &s, &u, BASE64(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("abcda---", 8u, "%&b", &s, &u, BASE64(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("abcda---", 8u, "%&b---", &s, &u, BASE64(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("abcda", 5u, "%&h", &s, &u, BASE64(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("abcda---", 8u, "%&h", &s, &u, BASE64(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("abcda---", 8u, "%&h---", &s, &u, BASE64(1, 10)) == 0);

	if (pad && strict_pad) {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%&b", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%&h", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%&b", &s, &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%&h", &s, &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&b", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&h", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&b", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&h", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&b--", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&h--", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&b-", &s, &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&h-", &s, &u, BASE64(5, 5)) == 0);
	} else if (pad) {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%&b", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%&h", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%&b", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%&h", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&b", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&h", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&b", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&h", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&b--", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&h--", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&b-", &s, &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&h-", &s, &u, BASE64(5, 5)) == 0);
	} else {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%&b", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%&h", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%&b", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%&h", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&b", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&h", &s, &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&b", &s, &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&h", &s, &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&b--", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%&h--", &s, &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&b-", &s, &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%&h-", &s, &u, BASE64(5, 5)) == 1);
	}

	if (pad && strict_pad) {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%^b", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%^h", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%^b", &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%^h", &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^b", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^h", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^b", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^h", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^b--", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^h--", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^b-", &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^h-", &u, BASE64(5, 5)) == 0);
	} else if (pad) {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%^b", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%^h", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%^b", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%^h", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^b", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^h", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^b", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^h", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^b--", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^h--", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^b-", &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^h-", &u, BASE64(5, 5)) == 0);
	} else {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%^b", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%^h", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%^b", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%^h", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^b", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^h", &u, BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^b", &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^h", &u, BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^b--", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%^h--", &u, BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^b-", &u, BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%^h-", &u, BASE64(5, 5)) == 1);
	}

	if (pad && strict_pad) {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%b", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%h", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%b", BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%h", BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%b", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%h", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%b", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%h", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%b--", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%h--", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%b-", BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%h-", BASE64(5, 5)) == 0);
	} else if (pad) {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%b", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%h", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%b", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%h", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%b", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%h", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%b", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%h", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%b--", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%h--", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%b-", BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%h-", BASE64(5, 5)) == 0);
	} else {
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%b", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab", 6u, "%h", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%b", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc", 7u, "%h", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%b", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%h", BASE64(4, 4)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%b", BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%h", BASE64(5, 5)) == 0);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%b--", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdab--", 8u, "%h--", BASE64(4, 4)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%b-", BASE64(5, 5)) == 1);
		EXPECT(librecrypt_check_settings_("abcdabc-", 8u, "%h-", BASE64(5, 5)) == 1);
	}
}


static int discarded_int;

int
main(void)
{
	const char *s, *s2;
	uintmax_t u, u2;

	SET_UP_ALARM();
	INIT_TEST_ABORT();
	INIT_RESOURCE_TEST();

	memset(lut, 255, sizeof(lut));
	lut['a'] = lut['b'] = lut['c'] = lut['d'] = 0;

	EXPECT(librecrypt_check_settings_("", 0u, "") == 1);
	EXPECT(librecrypt_check_settings_("hej", 3u, "hej") == 1);
	EXPECT(librecrypt_check_settings_("hej", 2u, "hej") == 0);
	EXPECT(librecrypt_check_settings_("hej", 4u, "hej") == 0);
	EXPECT(librecrypt_check_settings_("tja", 3u, "hej") == 0);

	EXPECT(librecrypt_check_settings_("%", 1u, "%%") == 1);
	EXPECT(librecrypt_check_settings_("%", 0u, "%%") == 0);

	EXPECT(librecrypt_check_settings_("hello", 5u, "%*") == 1);
	EXPECT(librecrypt_check_settings_("hello$world", 11u, "%*$world") == 1);
	EXPECT(librecrypt_check_settings_("hello$world", 11u, "%*$WORLD") == 0);

	EXPECT(librecrypt_check_settings_("hej.", 4u, "%s.", "hej", "tja", NULL) == 1);
	EXPECT(librecrypt_check_settings_("tja.", 4u, "%s.", "hej", "tja", NULL) == 1);
	EXPECT(librecrypt_check_settings_("bye.", 4u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("hej-", 4u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("tja-", 4u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("bye-", 4u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("hej.", 3u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("tja.", 3u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("bye.", 3u, "%s.", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("hej.", 3u, "%s", "hej", "tja", NULL) == 1);
	EXPECT(librecrypt_check_settings_("tja.", 3u, "%s", "hej", "tja", NULL) == 1);
	EXPECT(librecrypt_check_settings_("bye.", 3u, "%s", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("hej.", 4u, "%s", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("tja.", 4u, "%s", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("bye.", 4u, "%s", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_(".", 1u, "%s.", "hej", "tja", "", NULL) == 1);
	EXPECT(librecrypt_check_settings_("tja.", 4u, "%s.", "hej", "tja", "", NULL) == 1);
	EXPECT(librecrypt_check_settings_("tja.", 4u, "%s.", "", "hej", "tja", NULL) == 0);
	EXPECT(librecrypt_check_settings_("tja.", 4u, "%s.", NULL) == 0);

	EXPECT(librecrypt_check_settings_("hejsan", 1u, "%s", "hej", NULL) == 0);
	EXPECT(librecrypt_check_settings_("hejsan", 3u, "%s", "hej", NULL) == 1);
	EXPECT(librecrypt_check_settings_("hejsan", 6u, "%s", "hej", NULL) == 0);

	s = NULL;
	EXPECT(librecrypt_check_settings_("hej.", 4u, "%^s.", &s, "hej", "tja", "", NULL) == 1);
	EXPECT(s && !strcmp(s, "hej"));
	s = NULL;
	EXPECT(librecrypt_check_settings_("tja.", 4u, "%^s.", &s, "hej", "tja", "", NULL) == 1);
	EXPECT(s && !strcmp(s, "tja"));
	s = NULL;
	EXPECT(librecrypt_check_settings_(".", 1u, "%^s.", &s, "hej", "tja", "", NULL) == 1);
	EXPECT(s && !strcmp(s, ""));

	EXPECT(librecrypt_check_settings_("10.", 3u, "%p.", RANGE(1, 10)) == 1);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%p.", RANGE(10, 20)) == 1);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%p.", RANGE(1, 20)) == 1);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%p.", RANGE(1, 9)) == 0);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%p.", RANGE(11, 20)) == 0);
	EXPECT(librecrypt_check_settings_("0.", 2u, "%p.", RANGE(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("0.", 2u, "%p.", RANGE(0, 10)) == 1);
	EXPECT(librecrypt_check_settings_("00.", 3u, "%p.", RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("010.", 4u, "%p.", RANGE(1, 10)) == 0);

	EXPECT(librecrypt_check_settings_("10.", 3u, "%u.", RANGE(1, 10)) == 1);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%u.", RANGE(10, 20)) == 1);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%u.", RANGE(1, 20)) == 1);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%u.", RANGE(1, 9)) == 0);
	EXPECT(librecrypt_check_settings_("10.", 3u, "%u.", RANGE(11, 20)) == 0);
	EXPECT(librecrypt_check_settings_("0.", 2u, "%u.", RANGE(1, 10)) == 0);
	EXPECT(librecrypt_check_settings_("0.", 2u, "%u.", RANGE(0, 10)) == 1);
	EXPECT(librecrypt_check_settings_("00.", 3u, "%u.", RANGE(0, 10)) == 1);
	EXPECT(librecrypt_check_settings_("010.", 4u, "%u.", RANGE(1, 10)) == 1);

	u = 99u;
	EXPECT(librecrypt_check_settings_("10.", 3u, "%^p.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 10u);
	EXPECT(librecrypt_check_settings_("15.", 3u, "%^p.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 15u);
	EXPECT(librecrypt_check_settings_("0.", 2u, "%^p.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 0u);

	u = 99u;
	EXPECT(librecrypt_check_settings_("10.", 3u, "%^u.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 10u);
	EXPECT(librecrypt_check_settings_("15.", 3u, "%^u.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 15u);
	EXPECT(librecrypt_check_settings_("0.", 2u, "%^u.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 0u);
	EXPECT(librecrypt_check_settings_("010.", 4u, "%^u.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 10u);
	EXPECT(librecrypt_check_settings_("015.", 4u, "%^u.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 15u);
	EXPECT(librecrypt_check_settings_("00.", 3u, "%^u.", &u, RANGE(0, 100)) == 1);
	EXPECT(u == 0u);

	EXPECT(librecrypt_check_settings_("10.15.", 6u, "%u.%u.", RANGE(1, 10), RANGE(11, 20)) == 1);
	EXPECT(librecrypt_check_settings_("10.10.", 6u, "%u.%u.", RANGE(1, 10), RANGE(11, 20)) == 0);
	EXPECT(librecrypt_check_settings_("15.10.", 6u, "%u.%u.", RANGE(1, 10), RANGE(11, 20)) == 0);

	u = 99u;
	u2 = 99u;
	EXPECT(librecrypt_check_settings_("10.15.", 6u, "%^u.%^u.", &u, RANGE(1, 10), &u2, RANGE(11, 20)) == 1);
	EXPECT(u == 10u);
	EXPECT(u2 == 15u);

	EXPECT(librecrypt_check_settings_("", 0u, "%p", RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("a", 1u, "%p", RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("", 0u, "%u", RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("a", 1u, "%u", RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("", 0u, "%^p", &u, RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("a", 1u, "%^p", &u, RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("", 0u, "%^u", &u, RANGE(0, 10)) == 0);
	EXPECT(librecrypt_check_settings_("a", 1u, "%^u", &u, RANGE(0, 10)) == 0);

	EXPECT(librecrypt_check_settings_("hej.hello.", 10u, "%s.%s.", "hej", NULL, "hello", NULL) == 1);
	EXPECT(librecrypt_check_settings_("hello.hej.", 10u, "%s.%s.", "hej", NULL, "hello", NULL) == 0);

	EXPECT(librecrypt_check_settings_("hejsan", 1u, "%^s", &s, "hej", NULL) == 0);
	s = NULL;
	EXPECT(librecrypt_check_settings_("hejsan", 3u, "%^s", &s, "hej", NULL) == 1);
	EXPECT(s && !strcmp(s, "hej"));
	EXPECT(librecrypt_check_settings_("hejsan", 6u, "%^s", &s, "hej", NULL) == 0);

	s = NULL;
	s2 = NULL;
	EXPECT(librecrypt_check_settings_("hej.hello.", 10u, "%^s.%^s.", &s, "x", "hej", NULL, &s2, "y", "hello", NULL) == 1);
	EXPECT(s && !strcmp(s, "hej"));
	EXPECT(s2 && !strcmp(s2, "hello"));

	s = NULL;
	s2 = NULL;
	EXPECT(librecrypt_check_settings_("x.y.", 4u, "%^s.%^s.", &s, "x", "hej", NULL, &s2, "y", "hello", NULL) == 1);
	EXPECT(s && !strcmp(s, "x"));
	EXPECT(s2 && !strcmp(s2, "y"));

	check_asterisk('-', 0);
	check_asterisk('-', 1);
	check_asterisk('\0', 0);
	check_asterisk('\0', 1);

	check_base64('-', 0);
	check_base64('-', 1);
	check_base64('\0', 0);
	check_base64('\0', 1);

#define S(STR) (STR), (sizeof(STR) - 1u)
#define LARGE "999999999999999999999999999999999999999"
	EXPECT(librecrypt_check_settings_(S(LARGE LARGE LARGE LARGE), "%p", RANGE(0, UINTMAX_MAX)) == 0);

	EXPECT_ABORT(discarded_int = librecrypt_check_settings_("", 0u, "%\xFF", 0, 0, 0, 0, 0, 0, 0));

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
