/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
libtest_set_alloc_failure_in(size_t n)
{
	libtest_malloc_fail_in = n;
}


#else


int
main(void)
{
	EXPECT(libtest_malloc_fail_in == 0u);
	libtest_set_alloc_failure_in(4u);
	EXPECT(libtest_malloc_fail_in == 4u);
	libtest_set_alloc_failure_in(4u);
	EXPECT(libtest_malloc_fail_in == 4u);
	libtest_set_alloc_failure_in(0u);
	EXPECT(libtest_malloc_fail_in == 0u);
	libtest_set_alloc_failure_in(0u);
	EXPECT(libtest_malloc_fail_in == 0u);
	return 0;
}


#endif
