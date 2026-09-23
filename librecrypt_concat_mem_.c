/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline void librecrypt_concat_mem_(struct concat_state *state, const char *text, size_t len);


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* TODO test */

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
