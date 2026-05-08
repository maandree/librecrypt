/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


void
libtest_free(void *ptr, enum libtest_zero_check zero_checking)
{
	struct meminfo *mem;
	int saved_errno = errno;
	int unmap_err, memory_zeroed;
	uint8_t *usable_area;
	size_t i;
#ifdef WITH_BACKTRACE
	static _Thread_local int inside_free = 0;
#endif

	/* free(3) can be called with NULL */
	if (!ptr)
		return;

	/* Optionally print out trace */
#ifdef WITH_BACKTRACE
	if (!inside_free && getenv("PRETRACE_FREE")) {
		inside_free = 1;
		fprintf(stderr, "Deallocating: %p\n", ptr);
		libtest_print_backtrace(stderr, "\tat ", 0u, NULL);
		fflush(stderr);
		inside_free = 0;
	}
#endif

	/* Get the start of the allocation, which
	 * is where the book-keeping is located */
	mem = GET_MEMINFO(ptr);

	/* It is illegal to use free(3) on memory allocated with mmap(3)/mmap(2) */
	assert(mem->origin != FROM_MMAP_FILE);
	assert(mem->origin != FROM_MMAP_ANON);

	/* Delist allocation */
	if (!libtest_kill_malloc_tracking) {
		SPINLOCK(libtest_allocs_list_spinlock);
		mem->prev->next = mem->next;
		mem->next->prev = mem->prev;
		SPINUNLOCK(libtest_allocs_list_spinlock);
	}

	/* Check memory is zeroed */
	if (zero_checking && libtest_expect_zeroed && !mem->accept_leakage) {
		usable_area = mem->usable_area;
		memory_zeroed = 1;
		for (i = 0u; i < mem->usable_alloc_size; i++) {
			if (usable_area[i]) {
				memory_zeroed = 0;
				break;
			}
		}
		assert(memory_zeroed);
	}

	/* Optionally print out trace */
#ifdef WITH_BACKTRACE
	if (!inside_free && getenv("TRACE_MALLOC")) {
		inside_free = 1;
		fprintf(stderr, "Memory deallocated: %p\n (alloc-size=%zu, real-size=%zu)",
		        ptr, mem->requested_alloc_size, mem->real_alloc_size);
		if (getenv("TRACE_FREE") && !getenv("PRETRACE_FREE"))
			libtest_print_backtrace(stderr, "\tat ", 0u, NULL);
		fflush(stderr);
		inside_free = 0;
	}
#endif

	/* Deallocate memory */
	unmap_err = libtest_real_munmap(mem, mem->real_alloc_size);
	assert(!unmap_err);

	errno = saved_errno;
}


#else


CONST int
main(void)
{
	/* Tested via alloc.c */
	return 0;
}


#endif
