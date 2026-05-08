/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_decompose_chain1(char *hash);


#else


#define CHECK(IN, OUT, N)\
	do {\
		assert(sizeof(IN) <= sizeof(buf));\
		assert(sizeof(IN) == sizeof(OUT));\
		stpcpy(buf, (IN));\
		n = librecrypt_decompose_chain1(buf);\
		EXPECT(n == (N));\
		EXPECT(n == librecrypt_chain_length(IN));\
		EXPECT(!memcmp(buf, (OUT), sizeof(IN)));\
	} while (0)


int
main(void)
{
	char buf[64u];
	size_t n;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* Check each '>' was replaced with NUL, and number
	 * of '>' plus 1 (number of algorithms) was returned */
	CHECK("", "", 1u);
	CHECK(">", "\0", 2u);
	CHECK("a$b>c$d>e$f", "a$b\0c$d\0e$f", 3u);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
