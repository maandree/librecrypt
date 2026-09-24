/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline int librecrypt_base64_len_to_raw_len_(size_t ascii_len, size_t *raw_len_out);


#else


#define CHECK_GOOD(IN, OUT)\
	do {\
		size_t out = SIZE_MAX;\
		assert(librecrypt_base64_len_to_raw_len_((IN), &out) == 1);\
		assert(out == (OUT));\
	} while (0)


#define CHECK_BAD(IN)\
	do {\
		size_t out;\
		assert(librecrypt_base64_len_to_raw_len_((IN), &out) == 0);\
	} while (0)


int
main(void)
{
	size_t i, in_off = 0u, out_off = 0u;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	for (i = 0u; i < 8u; i++) {
		CHECK_GOOD(in_off + 0u, out_off + 0u);
		CHECK_BAD(in_off + 1u);
		CHECK_GOOD(in_off + 2u, out_off + 1u);
		CHECK_GOOD(in_off + 3u, out_off + 2u);
		in_off += 4u;
		out_off += 3u;
	}

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
