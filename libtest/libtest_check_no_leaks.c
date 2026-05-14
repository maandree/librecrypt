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
			libtest_print_backtrace(stderr, NULL, "\tat ", 0u, mem->backtrace, NULL);
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
	int r = 1;
	r &= libtest_fd_tracking(-1);
	r &= check_no_memory_leaks();
	return r;
}


#else


#define p libtest_ptr___
extern unsigned char *volatile p;
unsigned char *volatile p;


int
main(void)
{
#ifdef WITH_BACKTRACE
	int fd1, fd2;
#endif

	SET_UP_ALARM();

#ifdef WITH_BACKTRACE
	fd1 = dup(STDERR_FILENO);
	assert(fd1 >= 0 || errno == EBADF);
	assert(fd1 != STDERR_FILENO);
	if (fd1 >= 0) {
		close(STDERR_FILENO);
		fd2 = open("/dev/null", O_WRONLY);
		assert(fd2 >= 0);
		if (fd2 != STDERR_FILENO) {
			assert(dup2(fd2, STDERR_FILENO) == STDERR_FILENO);
			close(fd2);
		}
	}
	libtest_print_backtrace(stderr, "", "", 0u, NULL, NULL);
	if (fd1 >= 0) {
		assert(dup2(fd1, STDERR_FILENO) == STDERR_FILENO);
		close(fd1);
	}
#endif

	libtest_start_tracking();
	assert(!libtest_kill_malloc_tracking);
	p = malloc(1u);
	assert(p);
	libtest_suppress_leak_output = 1;
	*p = 0;
	atomic_thread_fence(memory_order_seq_cst);
	EXPECT(!libtest_check_no_leaks());
	atomic_thread_fence(memory_order_seq_cst);
	libtest_suppress_leak_output = 0;
	free(p);
	libtest_stop_tracking();
	atomic_thread_fence(memory_order_seq_cst);
	EXPECT(libtest_check_no_leaks());

	return 0;
}


#endif
