/* See LICENSE file for copyright and license details. */
#include "common.h"
extern int libtest_suppress_leak_output;
#ifndef TEST


int libtest_suppress_leak_output = 0;


static int
check_no_memory_leaks(void)
{
	struct meminfo *mem;
	int no_leaks = 1;

	SPINLOCK(libtest_allocs_list_spinlock);

	if (!libtest_allocs_list_inited)
		goto out;

	libtest_kill_malloc_tracking++;
	libtest_malloc_internal_usage++;
	for (mem = libtest_allocs_head.next; mem->next; mem = mem->next) {
		if (mem->accept_leakage)
			continue;
		no_leaks = 0;
		if (libtest_suppress_leak_output)
			continue;
		fprintf(stderr, "Memory leak: %p (alloc-size=%zu)\n",
		        mem->usable_area, mem->requested_alloc_size);
#ifdef WITH_BACKTRACE
		if (mem->backtrace)
			libtest_print_backtrace(stderr, "\tat ", 0u, mem->backtrace);
#endif
		fflush(stderr);
	}
	libtest_malloc_internal_usage--;
	libtest_kill_malloc_tracking--;

out:
	SPINUNLOCK(libtest_allocs_list_spinlock);
	return no_leaks;
}


int
libtest_check_no_leaks(void)
{
	/* TODO check file descriptor leaks */
	return check_no_memory_leaks();
}


#else


int
main(void)
{
	void *p;

	SET_UP_ALARM();

	libtest_start_tracking();
	assert(p = malloc(1u));
	libtest_suppress_leak_output = 1;
	EXPECT(!libtest_check_no_leaks());
	libtest_suppress_leak_output = 0;
	free(p);
	libtest_stop_tracking();
	EXPECT(libtest_check_no_leaks());

	return 0;
}


#endif
