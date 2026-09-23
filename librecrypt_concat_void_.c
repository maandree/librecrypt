/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_concat_void_(struct concat_state *state, size_t len);


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
