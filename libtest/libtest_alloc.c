/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(WITH_BACKTRACE) && defined(__GNUC__)
# pragma GCC diagnostic ignored "-Walloca"
#endif


static _Thread_local int inside_mmap_anon = 0;


static void
meminfo_fixup(struct meminfo *meminfo)
{
	if (meminfo->alignment_type == DEFAULT_ALIGNMENT)
		meminfo->requested_alignment = _Alignof(max_align_t);
	else if (meminfo->alignment_type == PAGE_ALIGNMENT)
		meminfo->requested_alignment = libtest_get_pagesize();

        meminfo->actual_alignment = meminfo->requested_alignment;
        meminfo->accept_leakage = !!libtest_malloc_accept_leakage;

	if (libtest_zero_on_alloc)
		meminfo->initialised_on_alloc |= !meminfo->accept_leakage;
}


static int
add_or_enomem(size_t *augend, size_t augment)
{
	if (*augend > SIZE_MAX - augment) {
		errno = ENOMEM;
		return -1;
	}
	*augend += augment;
	return 0;
}


static void *
mmap_anon(size_t size)
{
	void *ptr;
	inside_mmap_anon = 1;
	ptr = libtest_real_mmap(NULL, size,
	                        PROT_READ | PROT_WRITE,
	                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED,
	                        -1, 0);
	inside_mmap_anon = 0;
	return ptr == MAP_FAILED ? NULL : ptr;
}


static void *
try_alloc(struct meminfo *meminfo)
{
	static _Thread_local int recursion_guard = 0;
	void *base_ptr, *ret_ptr;
	size_t misalignment;
	size_t bookkeeping;
	int saved_errno;
#ifdef WITH_BACKTRACE
	size_t backtrace_realignment = 0u; /* initialised to make clang(1) happy */
	size_t i, backtrace_n;
	unw_cursor_t cursor;
	unw_context_t context;
	unw_word_t rip;
        struct partial {
		uintptr_t rips[8];
		struct partial *next;
	} *current, head;
#endif

	assert(!inside_mmap_anon);

	saved_errno = errno;
	meminfo_fixup(meminfo);
	meminfo->accept_leakage |= libtest_malloc_internal_usage > 0;

	/* Get backtrace (have to do it now to calculate `backtrace_n` for allocation) */
#ifdef WITH_BACKTRACE
	backtrace_n = 0u;
	if (!libtest_malloc_accept_leakage && !libtest_malloc_internal_usage) {
		libtest_malloc_internal_usage++;
		if (unw_getcontext(&context) || unw_init_local(&cursor, &context))
			goto skip_backtrace;
		for (current = &head, i = 0u; unw_step(&cursor) > 0; i++) {
			if (i % ELEMSOF(current->rips) == 0u)
				current = current->next = alloca(sizeof(*current));
			if (unw_get_reg(&cursor, UNW_REG_IP, &rip))
				goto skip_backtrace;
			current->rips[i % ELEMSOF(current->rips)] = (uintptr_t)rip;
		}
		backtrace_n = i;
	skip_backtrace:
		libtest_malloc_internal_usage--;
	}
#endif

	/* Calculate required alloction size */
	meminfo->real_alloc_size = meminfo->requested_alloc_size;
	if (add_or_enomem(&meminfo->real_alloc_size, sizeof(struct meminfo)) ||
	    add_or_enomem(&meminfo->real_alloc_size, _Alignof(void *) + sizeof(void *)) ||
	    add_or_enomem(&meminfo->real_alloc_size, meminfo->actual_alignment))
		return NULL;
#ifdef WITH_BACKTRACE
	if (backtrace_n) {
		misalignment = sizeof(struct meminfo) % _Alignof(struct backtrace);
		backtrace_realignment = misalignment ? _Alignof(struct backtrace) - misalignment : 0u;
		if (add_or_enomem(&meminfo->real_alloc_size, backtrace_realignment) ||
		    add_or_enomem(&meminfo->real_alloc_size, offsetof(struct backtrace, trace)) ||
		    add_or_enomem(&meminfo->real_alloc_size, backtrace_n * sizeof(Dwarf_Addr)))
			return NULL;
	}
#endif
	bookkeeping = meminfo->real_alloc_size - meminfo->requested_alloc_size;
	bookkeeping -= meminfo->actual_alignment;

	/* Allocate memory */
	if (!libtest_malloc_internal_usage) {
		if (libtest_malloc_fail_in && !--libtest_malloc_fail_in) {
			errno = ENOMEM;
			return NULL;
		}
	}
	base_ptr = mmap_anon(meminfo->real_alloc_size);
	if (!base_ptr)
		return NULL;
	if (meminfo->initialised_on_alloc)
		memset(base_ptr, 0, meminfo->real_alloc_size);
	ret_ptr = &((char *)base_ptr)[bookkeeping];

	/* Save backtrace */
#ifdef WITH_BACKTRACE
	if (backtrace_n) {
		meminfo->backtrace = (void *)&((char *)base_ptr)[sizeof(struct meminfo) + backtrace_realignment];
		meminfo->backtrace->n = backtrace_n;
		for (current = &head, i = 0u; i < backtrace_n; i++) {
			if (i % ELEMSOF(current->rips) == 0u)
				current = current->next;
			meminfo->backtrace->trace[i] = current->rips[i % ELEMSOF(current->rips)];
		}
	} else {
		meminfo->backtrace = NULL;
	}
#endif

	/* Fix alignment */
	misalignment = (size_t)(uintptr_t)ret_ptr % meminfo->actual_alignment;
	if (misalignment)
		ret_ptr = &((char *)ret_ptr)[meminfo->actual_alignment - misalignment];

	/* Store usable size */
	meminfo->usable_alloc_size = meminfo->real_alloc_size;
	meminfo->usable_alloc_size -= (size_t)((char *)ret_ptr - (char *)base_ptr);

	/* See CEVEATS section in mmap(2) */
	if (meminfo->usable_alloc_size > PTRDIFF_MAX) {
		assert(!libtest_real_munmap(base_ptr, meminfo->real_alloc_size));
		errno = ENOMEM;
		return NULL;
	}

	/* Store book-keeping */
	meminfo->usable_area = ret_ptr;
	memcpy(base_ptr, meminfo, sizeof(*meminfo));
	BASE_POINTER(ret_ptr) = base_ptr;
	meminfo = base_ptr;

	/* Track allocation */
	if (!libtest_kill_malloc_tracking) {
		assert(!recursion_guard);
		recursion_guard = 1;
		SPINLOCK(libtest_allocs_list_spinlock);
		if (!libtest_allocs_list_inited) {
			libtest_allocs_head.prev = NULL;
			libtest_allocs_head.next = &libtest_allocs_tail;
			libtest_allocs_tail.prev = &libtest_allocs_head;
			libtest_allocs_tail.next = NULL;
			libtest_allocs_list_inited = 1;
		}
		libtest_allocs_tail.prev->next = meminfo;
		meminfo->prev = libtest_allocs_tail.prev;
		meminfo->next = &libtest_allocs_tail;
		libtest_allocs_tail.prev = meminfo;
		SPINUNLOCK(libtest_allocs_list_spinlock);
		recursion_guard = 0;
	}

	/* Optionally print out trace */
#ifdef WITH_BACKTRACE
	if (meminfo->backtrace && !libtest_malloc_internal_usage && getenv("TRACE_MALLOC")) {
		libtest_malloc_internal_usage++;
		fprintf(stderr, "Memory allocated: %p (alloc-size=%zu, real-size=%zu, leak-allowed=%i)\n",
		        ret_ptr, meminfo->requested_alloc_size, meminfo->real_alloc_size, meminfo->accept_leakage);
		libtest_print_backtrace(stderr, NULL, "\tat ", 0u, NULL, NULL);
		fflush(stderr);
		libtest_malloc_internal_usage--;
	}
#endif

	errno = saved_errno;
	return ret_ptr;
}


void *
libtest_alloc(struct meminfo *meminfo)
{
	void *ptr;
	size_t reqsize;
	ptr = try_alloc(meminfo);
	if (!ptr && libtest_pretend_allocation_successful) {
		reqsize = meminfo->requested_alloc_size;
		meminfo->requested_alloc_size = 0u;
		ptr = try_alloc(meminfo);
		assert(ptr != NULL);
		meminfo->requested_alloc_size = reqsize;
		GET_MEMINFO(ptr)->requested_alloc_size = reqsize;
		SPINLOCK(libtest_allocs_list_spinlock);
		if (libtest_npretends >= ELEMSOF(libtest_pretend_list))
			SPINUNLOCK(libtest_allocs_list_spinlock);
		assert(libtest_npretends < ELEMSOF(libtest_pretend_list));
		libtest_pretend_list[libtest_npretends++] = ptr;
		SPINUNLOCK(libtest_allocs_list_spinlock);
	}
	return ptr;
}


void *
(memset)(void *s, int c, size_t n)
{
	unsigned char *us = s, uc = (unsigned char)c;
	size_t i;

	SPINLOCK(libtest_allocs_list_spinlock);
	for (i = 0u; i < libtest_npretends; i++) {
		if (libtest_pretend_list[i] == s) {
			/* We only do this for pointers in the pretend list
			 * because we must know that it is actually a
			 * pointer created with libtest_alloc, and not
			 * mmap(2) or stack-allocated or statically
			 * allocated buffer; and that's why libtest_pretend_list
			 * exist instead of being inferred or a flag. */
			if (n > GET_MEMINFO(s)->usable_alloc_size)
				n = GET_MEMINFO(s)->usable_alloc_size;
			break;
		}
	}
	SPINUNLOCK(libtest_allocs_list_spinlock);

	for (i = 0u; i < n; i++)
		us[i] = uc;

	return us;
}



#else


CONST int
main(void)
{
	/* Tested via alloc.c */
	return 0;
}


#endif
