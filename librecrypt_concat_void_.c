/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline size_t librecrypt_concat_void_(struct concat_state *state, size_t len);


#else


int
main(void)
{
	char buf[4];
	struct concat_state state = {buf, sizeof(buf), 0u};

	SET_UP_ALARM();
	INIT_TEST_ABORT();
	INIT_RESOURCE_TEST();

	memset(buf, 'x', sizeof(buf));

	assert(librecrypt_concat_void_(&state, 2u) == 2u);
	assert(state.buf == &buf[2u]);
	assert(state.size == 2u);
	assert(state.len == 2u);
	assert(!memcmp(buf, "xx\0x", sizeof(buf)));
	assert(librecrypt_concat_void_(&state, 5u) == 1u);
	assert(state.buf == &buf[3u]);
	assert(state.size == 1u);
	assert(state.len == 7u);
	assert(!memcmp(buf, "xx\0\0", sizeof(buf)));

	state = (struct concat_state){NULL, 0u, 0u};
	assert(librecrypt_concat_void_(&state, 5u) == 0u);
	assert(state.buf == NULL);
	assert(state.size == 0u);
	assert(state.len == 5u);

	state = (struct concat_state){NULL, 0u, SIZE_MAX};
	EXPECT_ABORT(state.size = librecrypt_concat_void_(&state, 1u));

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
