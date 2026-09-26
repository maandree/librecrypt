/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline void librecrypt_concat_str_(struct concat_state *state, const char *restrict text);


#else


int
main(void)
{
	char buf[5];
	struct concat_state state = {buf, sizeof(buf), 0u};

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	memset(buf, 'x', sizeof(buf));

	librecrypt_concat_str_(&state, "ab");
	librecrypt_concat_str_(&state, "cdef");
	assert(!memcmp(buf, "abcd\0", sizeof(buf)));
	assert(state.buf == &buf[4u]);
	assert(state.size == 1u);
	assert(state.len == 6u);

	state = (struct concat_state){NULL, 0u, 0u};
	librecrypt_concat_str_(&state, "abc");
	assert(state.len == 3u);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
