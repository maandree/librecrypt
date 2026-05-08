/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
# pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif


static void
explicit(unsigned char r)
{
	(void) r;
#if defined(__GNUC__)
	__asm__ volatile ("" :: "g" (r) : "memory");
#endif
}


void (*volatile librecrypt_explicit_____)(unsigned char) = &explicit;


int
librecrypt_equal_binary(const void *a, const void *b, size_t len)
{
	const unsigned char *x = a;
	const unsigned char *y = b;
	size_t i;
	unsigned char r = 0u;

	/* For each character pair XOR is zero on and only on equality,
	 * bitwise OR of all XORs remain 0 if and only if all where equal */
	for (i = 0u; i < len; i++)
		r = (unsigned char)(r | (*x++ ^ *y++));

	/* Prevent compiler from returning early */
	(*librecrypt_explicit_____)(r);

	return r ? 0 : 1;
}


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	EXPECT(librecrypt_equal_binary("", "", 0u) == 1);
	EXPECT(librecrypt_equal_binary("", "", 1u) == 1);
	EXPECT(librecrypt_equal_binary("a", "", 1u) == 0);
	EXPECT(librecrypt_equal_binary("", "a", 1u) == 0);
	EXPECT(librecrypt_equal_binary("a", "a", 1u) == 1);
	EXPECT(librecrypt_equal_binary("a", "a", 2u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdef", 6u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "Abcdef", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "AbCdef", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abCdef", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abCdeF", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdeF", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "xbcdef", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "xbxdef", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abxdef", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abxdex", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 6u) == 0);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 5u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 4u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 3u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 2u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 1u) == 1);
	EXPECT(librecrypt_equal_binary("abcdef", "abcdex", 0u) == 1);
	EXPECT(librecrypt_equal_binary(NULL, NULL, 0u) == 1);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
