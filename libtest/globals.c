/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


volatile int libtest_malloc_is_custom = -1;
volatile int libtest_calloc_is_custom = -1;
volatile int libtest_realloc_is_custom = -1;
volatile int libtest_reallocarray_is_custom = -1;
volatile int libtest_valloc_is_custom = -1;
volatile int libtest_pvalloc_is_custom = -1;
volatile int libtest_memalign_is_custom = -1;
volatile int libtest_aligned_alloc_is_custom = -1;
volatile int libtest_posix_memalign_is_custom = -1;
volatile int libtest_malloc_usable_size_is_custom = -1;
volatile int libtest_free_is_custom = -1;
volatile int libtest_free_sized_is_custom = -1;
volatile int libtest_free_aligned_sized_is_custom = -1;
volatile int libtest_strdup_is_custom = -1;
volatile int libtest_strndup_is_custom = -1;
volatile int libtest_wcsdup_is_custom = -1;
volatile int libtest_wcsndup_is_custom = -1;
volatile int libtest_memdup_is_custom = -1;
volatile int libtest_mmap_is_custom = -1;
volatile int libtest_munmap_is_custom = -1;
volatile int libtest_mremap_is_custom = -1;

volatile int libtest_pretend_allocation_successful = 0;

struct meminfo libtest_allocs_head;
struct meminfo libtest_allocs_tail;
int libtest_allocs_list_inited = 0;
atomic_flag libtest_allocs_list_spinlock = ATOMIC_FLAG_INIT;
void *libtest_pretend_list[128];
size_t libtest_npretends = 0u;

_Thread_local int libtest_zero_on_alloc = 0;
_Thread_local int libtest_expect_zeroed = 0;
_Thread_local int libtest_malloc_accept_leakage = 1;

_Thread_local size_t libtest_malloc_internal_usage = 0u;
_Thread_local size_t libtest_kill_malloc_tracking = 0u;
_Thread_local size_t libtest_malloc_fail_in = 0u;


#else


CONST int
main(void)
{
	/* There isn't really anything to test here */
	return 0;
}


#endif
