/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline void librecrypt_concat_mem_(struct concat_state *state, const char *text, size_t len);


#else


int
main(void)
{
	char buf[5];
	struct concat_state state = {buf, sizeof(buf), 0u};

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	memset(buf, 'x', sizeof(buf));

	librecrypt_concat_mem_(&state, "abcdef", 6u);
	assert(!memcmp(buf, "abcd\0", sizeof(buf)));
	assert(state.buf == &buf[4u]);
	assert(state.size == 1u);
	assert(state.len == 6u);
	librecrypt_concat_mem_(&state, "z", 1u);
	assert(!memcmp(buf, "abcd\0", sizeof(buf)));
	assert(state.len == 7u);

	state = (struct concat_state){NULL, 0u, 0u};
	librecrypt_concat_mem_(&state, "abc", 3u);
	assert(state.len == 3u);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
