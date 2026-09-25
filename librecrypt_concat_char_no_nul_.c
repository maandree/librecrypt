/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline void librecrypt_concat_char_no_nul_(struct concat_state *state, char c);


#else


int
main(void)
{
	char buf[3];
	struct concat_state state = {buf, sizeof(buf), 0u};

	SET_UP_ALARM();
	INIT_TEST_ABORT();
	INIT_RESOURCE_TEST();

	memset(buf, 'x', sizeof(buf));

	librecrypt_concat_char_no_nul_(&state, 'a');
	librecrypt_concat_char_no_nul_(&state, 'b');
	librecrypt_concat_char_no_nul_(&state, 'c');
	librecrypt_concat_char_no_nul_(&state, 'd');
	assert(!memcmp(buf, "abx", sizeof(buf)));
	assert(state.buf == &buf[2u]);
	assert(state.size == 1u);
	assert(state.len == 4u);

	state = (struct concat_state){NULL, 0u, 0u};
	librecrypt_concat_char_no_nul_(&state, 'a');
	assert(state.len == 1u);

	state = (struct concat_state){NULL, 0u, SIZE_MAX};
	EXPECT_ABORT(librecrypt_concat_char_no_nul_(&state, 'a'));

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
