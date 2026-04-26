/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline void librecrypt_wipe_str(char *string);


#else


#define CHECK(TEXT)\
	do {\
		memset(buf, 0, sizeof(buf));\
		stpcpy(buf, (TEXT));\
		assert(!strcmp(buf, (TEXT)));\
		librecrypt_wipe_str(buf);\
		for (i = 0u; i < sizeof(buf); i++)\
			EXPECT(!buf[i]);\
	} while (0)


int
main(void)
{
	char buf[64u];
	size_t i;
	SET_UP_ALARM();
	librecrypt_wipe_str(NULL);
	CHECK("");
	CHECK("hello");
	CHECK("hello developer");
	CHECK("  hello developer  ");
	CHECK("\1  hello developer  \1");
	return 0;
}


#endif
