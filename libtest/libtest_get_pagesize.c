/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


size_t
libtest_get_pagesize(void)
{
	long int r;
	int saved_errno = errno;
	if ((r = sysconf(_SC_PAGESIZE)) <= 0)
		if ((r = sysconf(_SC_PAGE_SIZE)) <= 0)
			r = 4096L;
	errno = saved_errno;
	return (size_t)r;
}


#else


int
main(void)
{
	SET_UP_ALARM();

#ifdef __linux__
	errno = 0;
	EXPECT(libtest_get_pagesize() == 4096u);
	EXPECT(!errno);
#endif

	return 0;
}


#endif
