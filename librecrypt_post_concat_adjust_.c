/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline int librecrypt_post_concat_adjust_(struct concat_state *state, size_t len);


#else


int
main(void)
{
	char buf[4];
	struct concat_state state = {buf, sizeof(buf), 0u};

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	assert(librecrypt_post_concat_adjust_(&state, 2u) == 0);
	assert(state.buf == &buf[2u]);
	assert(state.size == 2u);
	assert(state.len == 2u);
	assert(librecrypt_post_concat_adjust_(&state, 5u) == 0);
	assert(state.buf == &buf[3u]);
	assert(state.size == 1u);
	assert(state.len == 7u);

	state = (struct concat_state){buf, sizeof(buf), SIZE_MAX};
	assert(librecrypt_post_concat_adjust_(&state, 1u) == -1);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
