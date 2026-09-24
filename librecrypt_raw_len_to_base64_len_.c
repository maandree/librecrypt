/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline int librecrypt_raw_len_to_base64_len_(size_t raw_len, int padded, size_t *ascii_len_out);


#else


#define CHECK(IN, PADDED, OUT)\
	do {\
		size_t out = SIZE_MAX;\
		assert(librecrypt_raw_len_to_base64_len_((IN), (PADDED), &out) == 1);\
		assert(out == (OUT));\
	} while (0)


int
main(void)
{
	size_t i, in_off = 0u, out_off = 0u;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	for (i = 0; i < 8u; i++) {
		CHECK(in_off + 0u, 0, out_off + 0u);
		CHECK(in_off + 1u, 0, out_off + 2u);
		CHECK(in_off + 2u, 0, out_off + 3u);

		CHECK(in_off + 0u, 1, out_off + 0u);
		CHECK(in_off + 1u, 1, out_off + 4u);
		CHECK(in_off + 2u, 1, out_off + 4u);

		in_off += 3u;
		out_off += 4u;
	}

	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 4u, 0, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 3u, 0, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 2u, 0, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 1u, 0, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 0u, 0, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 1u, 0, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 2u, 0, &(size_t){0}) == 1);

	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 3u, 0, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 4u, 0, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 5u, 0, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 6u, 0, &(size_t){0}) == 0);

	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 4u, 1, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 3u, 1, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 2u, 1, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u - 1u, 1, &(size_t){0}) == 1);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 0u, 1, &(size_t){0}) == 1);

	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 1u, 1, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 2u, 1, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 3u, 1, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 4u, 1, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 5u, 1, &(size_t){0}) == 0);
	assert(librecrypt_raw_len_to_base64_len_(SIZE_MAX / 4u * 3u + 6u, 1, &(size_t){0}) == 0);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
