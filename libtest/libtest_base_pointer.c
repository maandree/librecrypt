/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


extern inline void **libtest_base_pointer(void *);


#else


CONST int
main(void)
{
	/* This one isn't that simple to test, but it works if other tests work :) */
	return 0;
}


#endif
