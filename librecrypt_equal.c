/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline int librecrypt_equal(const char *a, const char *b);


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	EXPECT(librecrypt_equal("", "") == 1);
	EXPECT(librecrypt_equal("", "a") == 0);
	EXPECT(librecrypt_equal("a", "") == 0);
	EXPECT(librecrypt_equal("a", "b") == 0);
	EXPECT(librecrypt_equal("a", "a") == 1);
	EXPECT(librecrypt_equal("abcdef", "Abcdef") == 0);
	EXPECT(librecrypt_equal("abcdef", "ABcdef") == 0);
	EXPECT(librecrypt_equal("abcdef", "aBcdef") == 0);
	EXPECT(librecrypt_equal("abcdef", "abCdef") == 0);
	EXPECT(librecrypt_equal("abcdef", "abCdeF") == 0);
	EXPECT(librecrypt_equal("abcdef", "abcdeF") == 0);
	EXPECT(librecrypt_equal("abcdef", "abcdex") == 0);
	EXPECT(librecrypt_equal("abcdef", "abcxef") == 0);
	EXPECT(librecrypt_equal("abcdef", "xbcdef") == 0);
	EXPECT(librecrypt_equal("abcdef", "abcdef") == 1);
	EXPECT(librecrypt_equal("abcdef", "abcdefg") == 0);
	EXPECT(librecrypt_equal("abcdefg", "abcdef") == 0);
	EXPECT(librecrypt_equal("abcdef", "") == 0);
	EXPECT(librecrypt_equal("", "abcdef") == 0);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
