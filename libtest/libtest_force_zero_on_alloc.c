/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
libtest_force_zero_on_alloc(int v)
{
	libtest_zero_on_alloc = v;
}


#else


int
main(void)
{
	SET_UP_ALARM();

	EXPECT(libtest_zero_on_alloc == 0);
	libtest_force_zero_on_alloc(1);
	EXPECT(libtest_zero_on_alloc == 1);
	libtest_force_zero_on_alloc(0);
	EXPECT(libtest_zero_on_alloc == 0);

	return 0;
}


#endif
