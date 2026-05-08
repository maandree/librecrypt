/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#ifndef WITH_BACKTRACE
# if defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wattributes"
# endif
CONST
#endif
void
libtest_dump_stack(const char *indent)
{
#ifndef WITH_BACKTRACE
	(void) indent;
#else
	libtest_print_backtrace(stderr, indent, 1u, NULL);
#endif
}


#else


CONST int
main(void)
{
	/* How would one even test this, and what would be the point? */
	return 0;
}


#endif
