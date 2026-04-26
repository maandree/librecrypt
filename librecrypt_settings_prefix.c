/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_settings_prefix(const char *hash);


#else


#define CHECK(PREFIX, SUFFIX)\
	do {\
		EXPECT(librecrypt_settings_prefix(PREFIX SUFFIX) == sizeof(PREFIX) - 1u);\
		EXPECT(librecrypt_settings_prefix(PREFIX) == sizeof(PREFIX) - 1u);\
	} while (0)


int
main(void)
{
	SET_UP_ALARM();
	CHECK("", "result");
	CHECK(">", "double-des result");
	CHECK("$", "x");
	CHECK("y$", "x");
	CHECK("y>", "x");
	CHECK("a$b$c>d$e$", "x");
	CHECK("a$b$c>", "x");
	return 0;
}


#endif
