/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline char *librecrypt_next_algorithm(char **hash);


#else


static void
testcase_1(void)
{
	char hash[] = ">a$b>c$d>e$f$";
	char *s = hash, *a;

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s != NULL);
	EXPECT(!strcmp(a, ""));
	EXPECT(!strcmp(s, "a$b>c$d>e$f$"));

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s != NULL);
	EXPECT(!strcmp(a, "a$b"));
	EXPECT(!strcmp(s, "c$d>e$f$"));

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s != NULL);
	EXPECT(!strcmp(a, "c$d"));
	EXPECT(!strcmp(s, "e$f$"));

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s == NULL);
	EXPECT(!strcmp(a, "e$f$"));

	EXPECT(librecrypt_next_algorithm(&s) == NULL);
	EXPECT(s == NULL);
}


static void
testcase_2(void)
{
	char hash[] = "a$b>c$d>e$f$>";
	char *s = hash, *a;

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s != NULL);
	EXPECT(!strcmp(a, "a$b"));
	EXPECT(!strcmp(s, "c$d>e$f$>"));

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s != NULL);
	EXPECT(!strcmp(a, "c$d"));
	EXPECT(!strcmp(s, "e$f$>"));

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s != NULL);
	EXPECT(!strcmp(a, "e$f$"));
	EXPECT(!strcmp(s, ""));

	EXPECT((a = librecrypt_next_algorithm(&s)));
	EXPECT(s == NULL);
	EXPECT(!strcmp(a, ""));

	EXPECT(librecrypt_next_algorithm(&s) == NULL);
	EXPECT(s == NULL);
}


int
main(void)
{
	SET_UP_ALARM();
	testcase_1();
	testcase_2();
	return 0;
}


#endif
