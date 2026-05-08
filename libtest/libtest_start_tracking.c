/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
libtest_start_tracking(void)
{
	libtest_malloc_accept_leakage = 0;
}


#else


int
main(void)
{
	SET_UP_ALARM();

	EXPECT(libtest_malloc_accept_leakage == 1);
	libtest_start_tracking();
	EXPECT(libtest_malloc_accept_leakage == 0);

	return 0;
}


#endif
