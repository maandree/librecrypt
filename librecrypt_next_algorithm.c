/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline char *librecrypt_next_algorithm(char **hash);


#else
# ifndef FUZZ


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
	EXPECT(s == NULL); /* state is set to NULL when done */
	EXPECT(!strcmp(a, "e$f$"));

	/* Check librecrypt_next_algorithm when done returns NULL without changing state */
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
	EXPECT(s == NULL); /* state is set to NULL when done */
	EXPECT(!strcmp(a, ""));

	/* Check librecrypt_next_algorithm when done returns NULL without changing state */
	EXPECT(librecrypt_next_algorithm(&s) == NULL);
	EXPECT(s == NULL);
}


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	testcase_1();
	testcase_2();

	STOP_RESOURCE_TEST();
	return 0;
}


# else


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *hash, *orig, *r;
	size_t sum = 0u, len;
	hash = malloc(size + 1u);
	assert(hash);
	orig = hash;
	memcpy(hash, data, size);
	hash[size] = '\0';
	len = strlen(hash);
	for (;;) {
		r = librecrypt_next_algorithm(&hash);
		if (!r)
			break;
		sum += strlen(r) + 1u;
	}
	EXPECT(sum == len + 1u);
	free(orig);
	return 0;
}


# endif
#endif
