/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len, const char *settings, void *reserved)
{
	return librecrypt_hash_(out_buffer, size, phrase, len, settings, reserved, ASCII_HASH);
}


#else


int
main(void)
{
	SET_UP_ALARM();

	return 0;
}


#endif
/* TODO test */
