/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_chain_length(const char *hash);


#else


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


#endif
