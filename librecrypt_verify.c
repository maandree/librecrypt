/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_verify(const char *phrase, size_t len, const char *settings, void *reserved)
{
	char *hash = NULL;
	size_t size = 0u;
	size_t off;
	ssize_t n;
	int ret, err;

	n = librecrypt_hash_(NULL, 0u, phrase, len, settings, reserved, ASCII_HASH);
	if (n < 0) {
		if (errno == EOVERFLOW)
			errno = ENOMEM;
		return -1;
	}

	off = librecrypt_settings_prefix(hash, NULL, reserved);
	if (hash[off] == '*') {
		if ('0'> hash[off + 1u] || hash[off + 1u] > '9') {
			errno = EINVAL;
			return -1;
		}
	}

	size = (size_t)n + 128u; /* a little extra so the hasher don't need to allocate output scratch */
	hash = malloc(size);
	if (!hash)
		return -1;

	n = librecrypt_hash_(hash, size, phrase, len, settings, reserved, ASCII_HASH);
	if (n < 0) {
		err = errno;
		librecrypt_wipe(hash, size);
		free(hash);
		if (err == EOVERFLOW)
			err = ENOMEM;
		errno = err;
		return -1;
	}
	if ((size_t)n > size)
		abort();

	ret = librecrypt_equal(hash, &settings[off]);
	librecrypt_wipe(hash, size);
	free(hash);
	return ret;
}


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* TODO test */

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
