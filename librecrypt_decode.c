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

	if (len && strict_pad && pad)
		goto einval;

	switch (len) {
	case 0u:
		goto out;
	case 1u:
		goto einval;

	default:
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
			if (!pad || str[2u] != pad)
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


static void
check(const char *binary, size_t binary_len, const char *ascii, size_t unpadded_len, size_t padded_len)
{
	char buf[16u];
	size_t i, j;

	assert(binary_len <= sizeof(buf));

	assert(padded_len % 4u == 0u);
	assert(padded_len / 4u == (unpadded_len + 3u) / 4u);
	assert(padded_len >= unpadded_len);

	EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '\0', 0) == (ssize_t)binary_len);
	EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '\0', 1) == (ssize_t)binary_len);
	EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '=', 0) == (ssize_t)binary_len);

	if (padded_len == unpadded_len) {
		EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '=', 1) == (ssize_t)binary_len);
	} else {
		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, ascii, unpadded_len, lut, '=', 1) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '\0', 0) == -1);
		EXPECT(errno == EINVAL);

		errno = 0;
		EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '\0', 1) == -1);
		EXPECT(errno == EINVAL);
	}

	EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '=', 0) == (ssize_t)binary_len);
	EXPECT(librecrypt_decode(NULL, 0u, ascii, padded_len, lut, '=', 1) == (ssize_t)binary_len);

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

		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_decode(buf, i, ascii, padded_len, lut, '=', 1) == (ssize_t)binary_len);
		j = i < binary_len ? i : binary_len;
		EXPECT(!memcmp(buf, binary, j));
		for (; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);

	}
}


int
main(void)
{
	int i;

	SET_UP_ALARM();

	CHECK("", "", "");
	CHECK("\x00", "AA", "==");
	CHECK("\x00\x00", "AAA", "=");
	CHECK("\x00\x00\x00", "AAAA", "");
	CHECK("12345678", "MTIzNDU2Nzg", "=");
	CHECK("testtest", "dGVzdHRlc3Q", "=");
	CHECK("zy[]y21 !", "enlbXXkyMSAh", "");
	CHECK("{~|~}~~~\x7f\x7f", "e358fn1+fn5/fw", "==");

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
	}

	return 0;
}


#endif
