/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


size_t
libtest_get_alloc_failure_in(void)
{
	return libtest_malloc_fail_in;
}


#else


int
main(void)
{
	EXPECT(libtest_malloc_fail_in == 0u);
	EXPECT(libtest_get_alloc_failure_in() == 0u);
	EXPECT(libtest_get_alloc_failure_in() == 0u);
	EXPECT(libtest_malloc_fail_in == 0u);
	libtest_malloc_fail_in = 4u;
	EXPECT(libtest_get_alloc_failure_in() == 4u);
	EXPECT(libtest_get_alloc_failure_in() == 4u);
	EXPECT(libtest_malloc_fail_in == 4u);
	return 0;
}


#endif
