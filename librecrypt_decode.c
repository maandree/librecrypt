/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_decode(void *out_buffer, size_t size, const char *ascii, size_t len,
                  const unsigned char lut[restrict static 256], char pad, int strict_pad)
{
	const unsigned char *str = (const unsigned char *)ascii;
	unsigned char *data = out_buffer;
	unsigned char a, b, c, d;
	size_t n = 0u;

	/* For as many multiple of 4 input characters as available,
	 * it can be coded into multiples of 3 bytes (or less if
	 * padding is used), however we need to check that the output
	 * buffer is large enough. Even if `size` is 0, we need read
	 * all characters to ensure that they only use the valid
	 * characters in the encoding alphabet or that padding is
	 * used correct — we want to validate the string, and we do
	 * not support padding in the middle (it is technically
	 * doable, but there is no reason it would ever be used) */
	for(; len >= 4u; str += 4u) {
		len -= 4u;

		a = lut[str[0u]];
		b = lut[str[1u]];
		if ((a | b) == 0xFFu)
			goto einval;
		if (n < size)
			data[n] = (unsigned char)((a << 2) | (b >> 4));
		n++;

		c = lut[str[2u]];
		if (c == 0xFFu) {
			if (len || !pad || str[2u] != pad || str[3u] != pad)
				goto einval;
			break;
		}
		if (n < size)
			data[n] = (unsigned char)((b << 4u) | (c >> 2u));
		n++;

		d = lut[str[3u]];
		if (d == 0xFFu) {
			if (len || !pad || str[3u] != pad)
				goto einval;
			break;
		}
		if (n < size)
			data[n] = (unsigned char)((c << 6) | (d >> 0));
		n++;
	}

	/* If the number of input characters was not a multiple of
	 * four, the string is invalid if padding was required
	 * (`strict_pad` is ignored if `pad` is the NUL byte) */
	if (len && pad && strict_pad)
		goto einval;

	/* Decode the remainder of the input, which shouldn't
	 * contain any padding since it is less than 4 bytes,
	 * and padding is done to multiples of 4 bytes */
	switch (len) {
	case 0u:
		/* 0 characters left over, there was nothing left, and we are done */
		goto out;

	case 1u:
		/* 1 character left over, this is invalid as at least 2 base-64
		 * characters is required to encode at least 1 byte */
		goto einval;

	default:
		/* 2 or 3 characters left over */

		a = lut[str[0u]];
		b = lut[str[1u]];
		if ((a | b) == 0xFFu)
			goto einval;
		if (n < size)
			data[n] = (unsigned char)((a << 2) | (b >> 4));
		n++;
		if (len == 2u)
			break;

		c = lut[str[2u]];
		if (c == 0xFFu) {
			if (!pad)
				goto einval;
			if (str[2u] != pad)
				goto einval;
			break;
		}
		if (n < size)
			data[n] = (unsigned char)((b << 4u) | (c >> 2u));
		n++;
		break;
	}

out:
	return (ssize_t)n;

einval:
	errno = EINVAL;
	return -1;
}


#else


static const unsigned char lut[256u] = {
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


#define CHECK(BINARY, ASCII, PAD)\
	check((BINARY), sizeof(BINARY) - 1u, (ASCII PAD), sizeof(ASCII) - 1u, sizeof(ASCII PAD) - 1u)


static int check_good_padding = 1;


static void
check(const char *binary, size_t binary_len, const char *ascii, size_t unpadded_len, size_t padded_len)
{
	char buf[16u];
	size_t i, j;

	/* Internal test check */
	assert(binary_len <= sizeof(buf));

	/* Internal test check */
	if (check_good_padding) {
		assert(padded_len % 4u == 0u);
		assert(padded_len / 4u == (unpadded_len + 3u) / 4u);
	}
	assert(padded_len >= unpadded_len);

	/* Test no output and without padding */
	EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '\0', 0) == (ssize_t)binary_len);
	EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '\0', 1) == (ssize_t)binary_len);
	EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '=', 0) == (ssize_t)binary_len);
	if (padded_len == unpadded_len) {
		EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '=', 1) == (ssize_t)binary_len);
	} else {
		/* illegal combination: padding missing but required */
		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '=', 1) == -1);
		EXPECT(errno == EINVAL);
	}

	/* Test no output and with padding */
	if (padded_len != unpadded_len) {
		/* illegal combinations: padding present no padding character defined (padded with illegal characters) */
		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '\0', 0) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '\0', 1) == -1);
		EXPECT(errno == EINVAL);
	}
	EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '=', 0) == (ssize_t)binary_len);
	if (check_good_padding)
		EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '=', 1) == (ssize_t)binary_len);

	/* Test output, with and without truncation */
	for (i = 0u; i < sizeof(buf); i++) {
		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_decode(buf, i, ascii, unpadded_len, lut, '\0', 0) == (ssize_t)binary_len);
		j = i < binary_len ? i : binary_len;
		EXPECT(!memcmp(buf, binary, j));
		for (; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);

		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_decode(buf, i, ascii, unpadded_len, lut, '\0', 1) == (ssize_t)binary_len);
		j = i < binary_len ? i : binary_len;
		EXPECT(!memcmp(buf, binary, j));
		for (; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);

		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_decode(buf, i, ascii, unpadded_len, lut, '=', 0) == (ssize_t)binary_len);
		j = i < binary_len ? i : binary_len;
		EXPECT(!memcmp(buf, binary, j));
		for (; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);

		if (padded_len == unpadded_len) {
			memset(buf, 99, sizeof(buf));
			EXPECT(librecrypt_decode(buf, i, ascii, unpadded_len, lut, '=', 1) == (ssize_t)binary_len);
			j = i < binary_len ? i : binary_len;
			EXPECT(!memcmp(buf, binary, j));
			for (; j < sizeof(buf); j++)
				EXPECT(buf[j] == 99);
		} else {
			errno = 0;
			EXPECT(librecrypt_decode(buf, i, ascii, unpadded_len, lut, '=', 1) == -1);
			EXPECT(errno == EINVAL);

			errno = 0;
			EXPECT(librecrypt_decode(buf, i, ascii, padded_len, lut, '\0', 0) == -1);
			EXPECT(errno == EINVAL);

			errno = 0;
			EXPECT(librecrypt_decode(buf, i, ascii, padded_len, lut, '\0', 1) == -1);
			EXPECT(errno == EINVAL);
		}

		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_decode(buf, i, ascii, padded_len, lut, '=', 0) == (ssize_t)binary_len);
		j = i < binary_len ? i : binary_len;
		EXPECT(!memcmp(buf, binary, j));
		for (; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);

		if (check_good_padding) {
			memset(buf, 99, sizeof(buf));
			EXPECT(librecrypt_decode(buf, i, ascii, padded_len, lut, '=', 1) == (ssize_t)binary_len);
			j = i < binary_len ? i : binary_len;
			EXPECT(!memcmp(buf, binary, j));
			for (; j < sizeof(buf); j++)
				EXPECT(buf[j] == 99);
		}

	}
}


int
main(void)
{
	int i;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* Normal test cases */
	check_good_padding = 1;
	CHECK("", "", "");
	CHECK("\x00", "AA", "==");
	CHECK("\x00\x00", "AAA", "=");
	CHECK("\x00\x00\x00", "AAAA", "");
	CHECK("12345678", "MTIzNDU2Nzg", "=");
	CHECK("testtest", "dGVzdHRlc3Q", "=");
	CHECK("zy[]y21 !", "enlbXXkyMSAh", "");
	CHECK("{~|~}~~~\x7f\x7f", "e358fn1+fn5/fw", "==");

	/* Bad but acceptable case */
	check_good_padding = 0;
	CHECK("\x00", "AA", "=");

	/* Test illegal characters, and 1 non-value character with
	 * 3 pad characeters (illegal since at least 2 base-64
	 * characters are needed to encode at least 1 byte) */
	check_good_padding = 1;
	for (i = 0; i <= 1; i++) {
		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "AA=*", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "AA*=", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "AA**", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "A===", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "A", 1u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "====", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "A*==", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "*A==", 4u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "A*", 2u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "*A", 2u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "=", 1u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "==", 2u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "=A", 2u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "AA*", 3u, lut, '=', i) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, "AA*", 3u, lut, '\0', i) == -1);
		EXPECT(errno == EINVAL);
	}

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
