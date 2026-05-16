/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_chain_length(const char *hash);


#else
# ifndef FUZZ


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* Check returns number of '>' plus 1 */
	EXPECT(librecrypt_chain_length("") == 1u);
	EXPECT(librecrypt_chain_length("a$b") == 1u);
	EXPECT(librecrypt_chain_length(">") == 2u);
	EXPECT(librecrypt_chain_length(">>") == 3u);
	EXPECT(librecrypt_chain_length("a$b>c$d>e$f") == 3u);
	EXPECT(librecrypt_chain_length("a$b>c$d>e$f>") == 4u);
	EXPECT(librecrypt_chain_length(">a$b>c$d>e$f>") == 5u);

	STOP_RESOURCE_TEST();
	return 0;
}


# else


extern volatile size_t discarded_return_value;
volatile size_t discarded_return_value;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *hash;
	hash = malloc(size + 1u);
	assert(hash);
	memcpy(hash, data, size);
	hash[size] = '\0';
	discarded_return_value = librecrypt_chain_length(hash);
	free(hash);
	return 0;
}


# endif
#endif
