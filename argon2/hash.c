/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST

#include <libar2.h>
#include <libar2simplified.h>


int
librecrypt__argon2__hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                         const char *settings, size_t prefix, void *reserved)
{
	/* TODO implement */
	(void) out_buffer;
	(void) size;
	(void) phrase;
	(void) len;
	(void) settings;
	(void) prefix;
	(void) reserved;
	return 0;
}


#else


CONST int
main(void)
{
	return 0;
}


#endif
/* TODO test */
