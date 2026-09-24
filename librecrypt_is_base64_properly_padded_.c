/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline int librecrypt_is_base64_properly_padded_(size_t unpadded_len, size_t padded_len);


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	assert(librecrypt_is_base64_properly_padded_(0u, 0u) == 1);
	assert(librecrypt_is_base64_properly_padded_(0u, 1u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 2u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 3u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 4u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 5u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 6u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 7u) == 0);
	assert(librecrypt_is_base64_properly_padded_(0u, 8u) == 0);

	assert(librecrypt_is_base64_properly_padded_(2u, 2u) == 0);
	assert(librecrypt_is_base64_properly_padded_(2u, 3u) == 0);
	assert(librecrypt_is_base64_properly_padded_(2u, 4u) == 1);
	assert(librecrypt_is_base64_properly_padded_(2u, 5u) == 0);
	assert(librecrypt_is_base64_properly_padded_(2u, 6u) == 0);
	assert(librecrypt_is_base64_properly_padded_(2u, 7u) == 0);
	assert(librecrypt_is_base64_properly_padded_(2u, 8u) == 0);

	assert(librecrypt_is_base64_properly_padded_(3u, 3u) == 0);
	assert(librecrypt_is_base64_properly_padded_(3u, 4u) == 1);
	assert(librecrypt_is_base64_properly_padded_(3u, 5u) == 0);
	assert(librecrypt_is_base64_properly_padded_(3u, 6u) == 0);
	assert(librecrypt_is_base64_properly_padded_(3u, 7u) == 0);
	assert(librecrypt_is_base64_properly_padded_(3u, 8u) == 0);

	assert(librecrypt_is_base64_properly_padded_(4u, 4u) == 1);
	assert(librecrypt_is_base64_properly_padded_(4u, 5u) == 0);
	assert(librecrypt_is_base64_properly_padded_(4u, 6u) == 0);
	assert(librecrypt_is_base64_properly_padded_(4u, 7u) == 0);
	assert(librecrypt_is_base64_properly_padded_(4u, 8u) == 0);

	assert(librecrypt_is_base64_properly_padded_(6u, 6u) == 0);
	assert(librecrypt_is_base64_properly_padded_(6u, 7u) == 0);
	assert(librecrypt_is_base64_properly_padded_(6u, 8u) == 1);

	assert(librecrypt_is_base64_properly_padded_(7u, 7u) == 0);
	assert(librecrypt_is_base64_properly_padded_(7u, 8u) == 1);

	assert(librecrypt_is_base64_properly_padded_(8u, 8u) == 1);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
