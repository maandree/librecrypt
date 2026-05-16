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

	/* 1 byte (8 bits) requires 2 base-64 characters (12 bits),
	 * 2 bytes (16 bits) requires 3 base-64 characters (18 bits), and
	 * 3 bytes (24 bits) requires 4 base-64 characters (24 bits) exactly */
	q = len / 3u;
	r = len % 3u;
	n = !r ? 0u : pad ? 4u : r + 1u;
	if (q > (SIZE_MAX - n) / 4u) {
		errno = EOVERFLOW;
		return SIZE_MAX;
	}
	n += q * 4u;

	/* Just return the encoding length if no output is requested */
	if (!size)
		return n;

	/* We right backwards to ensure `out_buffer` and `binary` may alias each other
	 * (the output is at least as long as the input (actually always longer
	 * unless `len` is 0)) */

	/* NUL-terminate output */
	size -= 1u;
	out_buffer[MIN(n, size)] = '\0';

	/* Deal with situation where number of bytes is not divisible
	 * byte there, and set excess bits to 0; padding characters are
	 * appended if required (they are probably optional since padding
	 * is only useful to allow base-64 strings to be concatenated) */
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

	/* Encode multiples of 3 bytes as multiples of 4 ASCII characters, */
	i = q * 4u;
	j = q * 3u;
	/* however, first we may have to truncate the output to a non-multiple
	 * of 4 ASCII characters the output buffer is too small, */
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
	/* then we can efficiently write the multiple of 4 characters */
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
# ifndef FUZZ


NONSTRING static const char lut[256u] = MAKE_ENCODING_LUT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");


#define phony librecrypt_test_phony__
extern void *volatile librecrypt_test_phony__;
void *volatile librecrypt_test_phony__ = (void *)(uintptr_t)4096u;


#define CHECK(BINARY, ASCII)\
	check((BINARY), sizeof(BINARY) - 1u, (ASCII), sizeof(ASCII) - 1u)


static void
check(const char *binary, size_t binary_len, const char *ascii, size_t ascii_len)
{
	size_t padded_ascii_len = ascii_len;
	char buf[256u];
	size_t i, j, n;

	/* Check internal test correctness */
	if (padded_ascii_len & 3u) {
		padded_ascii_len |= 3u;
		padded_ascii_len += 1u;
	}
	assert(padded_ascii_len % 4u == 0u);
	assert(padded_ascii_len / 4u == (ascii_len + 3u) / 4u);
	assert(padded_ascii_len >= ascii_len);

	/* Check length-only request without padding */
	EXPECT(librecrypt_encode(NULL, 0u, binary, binary_len, lut, '\0') == ascii_len);
	EXPECT(librecrypt_encode(buf, 0u, binary, binary_len, lut, '\0') == ascii_len);

	/* Check length-only request with padding */
	EXPECT(librecrypt_encode(NULL, 0u, binary, binary_len, lut, '=') == padded_ascii_len);
	EXPECT(librecrypt_encode(buf, 0u, binary, binary_len, lut, '=') == padded_ascii_len);

	/* Check encoding requests, with and without truncation, without padding */
	for (i = 0u; i <= ascii_len; i++) {
		CANARY_FILL(buf);
		EXPECT(librecrypt_encode(buf, i + 1u, binary, binary_len, lut, '\0') == ascii_len);
		EXPECT(!memcmp(buf, ascii, i));
		EXPECT(buf[i] == '\0');
		CANARY_CHECK(buf, i + 1u);
	}

	/* Check encoding requests, with and without truncation, with padding */
	for (i = 0u; i <= padded_ascii_len; i++) {
		CANARY_FILL(buf);
		EXPECT(librecrypt_encode(buf, i + 1u, binary, binary_len, lut, '=') == padded_ascii_len);
		j = MIN(i, ascii_len);
		n = MIN(i, padded_ascii_len);
		EXPECT(!memcmp(buf, ascii, j));
		for (; j < n; j++)
			EXPECT(buf[j] == '=');
		EXPECT(buf[j++] == '\0');
		CANARY_CHECK(buf, j);
	}
}


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	CHECK("", "");
	CHECK("\x00", "AA");
	CHECK("\x00\x00", "AAA");
	CHECK("\x00\x00\x00", "AAAA");
	CHECK("12345678", "MTIzNDU2Nzg");
	CHECK("testtest", "dGVzdHRlc3Q");
	CHECK("zy[]y21 !", "enlbXXkyMSAh");
	CHECK("{~|~}~~~\x7f\x7f", "e358fn1+fn5/fw");

#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wstringop-overflow="
#endif

	EXPECT(librecrypt_encode(NULL, 0u, phony, (SIZE_MAX - 3u) / 4u * 3u + 1u, lut, '\0') == SIZE_MAX - 1u);
	errno = 0;
	EXPECT(librecrypt_encode(NULL, 0u, phony, (SIZE_MAX - 3u) / 4u * 3u + 2u, lut, '\0') == SIZE_MAX);
	EXPECT(errno == 0);
	errno = 0;
	EXPECT(librecrypt_encode(NULL, 0u, phony, (SIZE_MAX - 3u) / 4u * 3u + 3u, lut, '\0') == SIZE_MAX);
	EXPECT(errno == EOVERFLOW);

#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif

	STOP_RESOURCE_TEST();
	return 0;
}


# else


extern volatile size_t discarded_return_value;
volatile size_t discarded_return_value;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const static char lut[256];
	char *out_buffer;
	size_t out_size;
	char pad;
	size_t r;

	if (size < 3u)
		return 0;

	out_size = ((size_t)data[0u] << 8) | (size_t)data[1u];
	if (out_size) {
		out_buffer = malloc(out_size);
		assert(out_buffer != NULL);
	} else {
		out_buffer = NULL;
	}
	pad = data[2u];

	discarded_return_value = librecrypt_encode(out_buffer, out_size, &data[3u], size - 3u, lut, pad);

	free(out_buffer);
	return 0;
}


# endif
#endif
