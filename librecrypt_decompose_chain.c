/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_decompose_chain(char *hash, char **chain_out_array, size_t size);


#else


#define HASH_1 "a$b"

#define HASH_2_A  "a$b"
#define HASH_2_B  "c$d"
#define HASH_2_C  "e$f"
#define HASH_2_BC HASH_2_B">"HASH_2_C
#define HASH_2    HASH_2_A">"HASH_2_BC

#define HASH_3_A     ""
#define HASH_3_B    "a$b"
#define HASH_3_C    "c$d"
#define HASH_3_D    "e$f"
#define HASH_3_E     ""
#define HASH_3_DE    HASH_3_D">"HASH_3_E
#define HASH_3_CDE   HASH_3_C">"HASH_3_DE
#define HASH_3_BCDE  HASH_3_B">"HASH_3_CDE
#define HASH_3       HASH_3_A">"HASH_3_BCDE


#define NULL_OUT(ARRAY)\
	do {\
		for (i = 0u; i < ELEMSOF(ARRAY); i++)\
			(ARRAY)[i] = NULL;\
	} while (0)


int
main(void)
{
	char buf[64u];
	char *chain[10u];
	size_t i;

	SET_UP_ALARM();

	/* Check HASH_1 with different sizes of `chain` */
	stpcpy(buf, HASH_1);
	EXPECT(librecrypt_decompose_chain(buf, chain, 0u) == 1u);
	EXPECT(!strcmp(buf, HASH_1));
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 1u) == 1u);
	EXPECT(!strcmp(buf, HASH_1));
	EXPECT(chain[0u] == buf);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, ELEMSOF(chain)) == 1u);
	EXPECT(!strcmp(buf, HASH_1));
	EXPECT(chain[0u] == buf);

	/* Check HASH_2 with different sizes of `chain` */
	stpcpy(buf, HASH_2);
	EXPECT(librecrypt_decompose_chain(buf, chain, 0u) == 3u);
	EXPECT(!strcmp(buf, HASH_2));
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 1u) == 3u);
	EXPECT(!strcmp(buf, HASH_2));
	EXPECT(chain[0u] == buf);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 2u) == 3u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_2_A));
	EXPECT(!strcmp(chain[1u], HASH_2_BC));
	stpcpy(buf, HASH_2);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, ELEMSOF(chain)) == 3u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] != NULL);
	EXPECT(chain[3u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_2_A));
	EXPECT(!strcmp(chain[1u], HASH_2_B));
	EXPECT(!strcmp(chain[2u], HASH_2_C));

	/* Check HASH_3 with different sizes of `chain` */
	stpcpy(buf, HASH_3);
	EXPECT(librecrypt_decompose_chain(buf, chain, 0u) == 5u);
	EXPECT(!strcmp(buf, HASH_3));
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 1u) == 5u);
	EXPECT(!strcmp(buf, HASH_3));
	EXPECT(chain[0u] == buf);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 2u) == 5u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_3_A));
	EXPECT(!strcmp(chain[1u], HASH_3_BCDE));
	stpcpy(buf, HASH_3);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 3u) == 5u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] != NULL);
	EXPECT(chain[3u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_3_A));
	EXPECT(!strcmp(chain[1u], HASH_3_B));
	EXPECT(!strcmp(chain[2u], HASH_3_CDE));
	stpcpy(buf, HASH_3);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 4u) == 5u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] != NULL);
	EXPECT(chain[3u] != NULL);
	EXPECT(chain[4u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_3_A));
	EXPECT(!strcmp(chain[1u], HASH_3_B));
	EXPECT(!strcmp(chain[2u], HASH_3_C));
	EXPECT(!strcmp(chain[3u], HASH_3_DE));
	stpcpy(buf, HASH_3);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 5u) == 5u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] != NULL);
	EXPECT(chain[3u] != NULL);
	EXPECT(chain[4u] != NULL);
	EXPECT(chain[5u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_3_A));
	EXPECT(!strcmp(chain[1u], HASH_3_B));
	EXPECT(!strcmp(chain[2u], HASH_3_C));
	EXPECT(!strcmp(chain[3u], HASH_3_D));
	EXPECT(!strcmp(chain[4u], HASH_3_E));
	stpcpy(buf, HASH_3);
	NULL_OUT(chain);
	EXPECT(librecrypt_decompose_chain(buf, chain, 6u) == 5u);
	EXPECT(chain[0u] != NULL);
	EXPECT(chain[1u] != NULL);
	EXPECT(chain[2u] != NULL);
	EXPECT(chain[3u] != NULL);
	EXPECT(chain[4u] != NULL);
	EXPECT(chain[5u] == NULL);
	EXPECT(!strcmp(chain[0u], HASH_3_A));
	EXPECT(!strcmp(chain[1u], HASH_3_B));
	EXPECT(!strcmp(chain[2u], HASH_3_C));
	EXPECT(!strcmp(chain[3u], HASH_3_D));
	EXPECT(!strcmp(chain[4u], HASH_3_E));

	return 0;
}


#endif
