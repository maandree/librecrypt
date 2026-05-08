/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
libtest_expect_zeroed_on_free(int v)
{
	libtest_expect_zeroed = v;
}


#else


int
main(void)
{
	SET_UP_ALARM();

	EXPECT(libtest_expect_zeroed == 0);
	libtest_expect_zeroed_on_free(1);
	EXPECT(libtest_expect_zeroed == 1);
	libtest_expect_zeroed_on_free(0);
	EXPECT(libtest_expect_zeroed == 0);

	return 0;
}


#endif
