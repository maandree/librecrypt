/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif


#define O1(I1, I2, I3) ((I1) >> 2)
#define O2(I1, I2, I3) (((I1) << 4) | ((I2) >> 4))
#define O3(I1, I2, I3) (((I2) << 2) | ((I3) >> 6))
#define O4(I1, I2, I3) (I3)


size_t
librecrypt_encode(char *out_buffer, size_t size, const void *binary, size_t len,
                  const char lut[restrict static 256], char pad)
{
	const unsigned char *data = binary;
	unsigned char a, b, c;
	size_t q, r, i, j, n;

	q = len / 3u;
	r = len % 3u;
	n = q * 4u + (!r ? 0u : pad ? 4u : r + 1u);

	if (!size)
		return n;

	size -= 1u;
	out_buffer[n < size ? n : size] = '\0';

	if (r == 1u) {
		a = data[q * 3u + 0u];
		switch (size > q * 4u ? size - q * 4u : 0u) { /* fall-through */
		default:
			if (pad)
				out_buffer[q * 4u + 3u] = pad;
		case 3u:
			if (pad)
				out_buffer[q * 4u + 2u] = pad;
		case 2u:
			out_buffer[q * 4u + 1u] = lut[O2(a, 0, 0) & 255];
		case 1u:
			out_buffer[q * 4u + 0u] = lut[O1(a, 0, 0) & 255];
		case 0u:
			break;
		}
	} else if (r == 2u) {
		a = data[q * 3u + 0u];
		b = data[q * 3u + 1u];
		switch (size > q * 4u ? size - q * 4u : 0u) { /* fall-through */
		default:
			if (pad)
				out_buffer[q * 4u + 3u] = pad;
		case 3u:
			out_buffer[q * 4u + 2u] = lut[O3(a, b, 0) & 255];
		case 2u:
			out_buffer[q * 4u + 1u] = lut[O2(a, b, 0) & 255];
		case 1u:
			out_buffer[q * 4u + 0u] = lut[O1(a, b, 0) & 255];
		case 0u:
			break;
		}
	}

	i = q * 4u;
	j = q * 3u;
	if (i > size) {
		q = size / 4u;
		r = size % 4u;
		i = q * 4u;
		j = q * 3u;
		c = data[j + 2u];
		b = data[j + 1u];
		a = data[j + 0u];
		switch (r) { /* fall-through */
		case 3u:
			out_buffer[i + 2u] = lut[O3(a, b, c) & 255];
		case 2u:
			out_buffer[i + 1u] = lut[O2(a, b, c) & 255];
		case 1u:
			out_buffer[i + 0u] = lut[O1(a, b, c) & 255];
		default:
			break;
		}
	}
	while (i) {
		i -= 4u;
		j -= 3u;
		c = data[j + 2u];
		b = data[j + 1u];
		a = data[j + 0u];
		out_buffer[i + 3u] = lut[O4(a, b, c) & 255];
		out_buffer[i + 2u] = lut[O3(a, b, c) & 255];
		out_buffer[i + 1u] = lut[O2(a, b, c) & 255];
		out_buffer[i + 0u] = lut[O1(a, b, c) & 255];
	}

	return n;
}


#else


NONSTRING static const char lut[256u] = MAKE_ENCODING_LUT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");


#define CHECK(BINARY, ASCII)\
	check((BINARY), sizeof(BINARY) - 1u, (ASCII), sizeof(ASCII) - 1u)


static void
check(const char *binary, size_t binary_len, const char *ascii, size_t ascii_len)
{
	size_t padded_ascii_len = ascii_len;
	char buf[256u];
	size_t i, j, n;

	if (padded_ascii_len & 3u) {
		padded_ascii_len |= 3u;
		padded_ascii_len += 1u;
	}
	assert(padded_ascii_len % 4u == 0u);
	assert(padded_ascii_len / 4u == (ascii_len + 3u) / 4u);
	assert(padded_ascii_len >= ascii_len);

	EXPECT(librecrypt_encode(NULL, 0u, binary, binary_len, lut, '\0') == ascii_len);
	EXPECT(librecrypt_encode(buf, 0u, binary, binary_len, lut, '\0') == ascii_len);

	EXPECT(librecrypt_encode(NULL, 0u, binary, binary_len, lut, '=') == padded_ascii_len);
	EXPECT(librecrypt_encode(buf, 0u, binary, binary_len, lut, '=') == padded_ascii_len);

	for (i = 0u; i <= ascii_len; i++) {
		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_encode(buf, i + 1u, binary, binary_len, lut, '\0') == ascii_len);
		EXPECT(!memcmp(buf, ascii, i));
		EXPECT(buf[i] == '\0');
		for (j = i + 1u; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);
	}

	for (i = 0u; i <= padded_ascii_len; i++) {
		memset(buf, 99, sizeof(buf));
		EXPECT(librecrypt_encode(buf, i + 1u, binary, binary_len, lut, '=') == padded_ascii_len);
		j = i < ascii_len ? i : ascii_len;
		n = i < padded_ascii_len ? i : padded_ascii_len;
		EXPECT(!memcmp(buf, ascii, j));
		for (; j < n; j++)
			EXPECT(buf[j] == '=');
		EXPECT(buf[j++] == '\0');
		for (; j < sizeof(buf); j++)
			EXPECT(buf[j] == 99);
	}
}


int
main(void)
{
	SET_UP_ALARM();
	CHECK("", "");
	CHECK("\x00", "AA");
	CHECK("\x00\x00", "AAA");
	CHECK("\x00\x00\x00", "AAAA");
	CHECK("12345678", "MTIzNDU2Nzg");
	CHECK("testtest", "dGVzdHRlc3Q");
	CHECK("zy[]y21 !", "enlbXXkyMSAh");
	CHECK("{~|~}~~~\x7f\x7f", "e358fn1+fn5/fw");
	return 0;
}


#endif
