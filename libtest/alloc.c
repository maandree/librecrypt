/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


static void *
common_malloc(size_t n, enum memory_origin origin)
{
	struct meminfo meminfo;

	assert(n);

	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.requested_alloc_size = n;
	meminfo.alignment_type = DEFAULT_ALIGNMENT;
	meminfo.initialised_on_alloc = 0;
	meminfo.origin = origin;

	return libtest_alloc(&meminfo);
}


static void *
common_realloc(void *old_ptr, size_t new_n, enum memory_origin origin)
{
	void *new_ptr;
	size_t old_n;

	assert(new_n);
	if (!old_ptr)
		return common_malloc(new_n, origin);

	assert(GET_MEMINFO(old_ptr)->requested_alignment <= _Alignof(max_align_t));

	new_ptr = common_malloc(new_n, origin); /* always change the pointer */
	if (!new_ptr)
		return NULL;

	new_n = GET_MEMINFO(new_ptr)->usable_alloc_size;
	old_n = GET_MEMINFO(old_ptr)->usable_alloc_size;
	memcpy(new_ptr, old_ptr, new_n < old_n ? new_n : old_n);
	libtest_free(old_ptr, DO_NOT_REQUIRE_ZEROED);

	return new_ptr;
}


static void *
common_memalign(size_t alignment, size_t size, enum memory_origin origin)
{
	struct meminfo meminfo;

	assert(size);
	assert(alignment);
	assert(!(alignment & (alignment - 1u)));

	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.requested_alloc_size = size;
	meminfo.alignment_type = CUSTOM_ALIGNMENT;
	meminfo.requested_alignment = alignment;
	meminfo.initialised_on_alloc = 0;
	meminfo.origin = origin;

	return libtest_alloc(&meminfo);
}


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wmissing-prototypes"
#endif


void *
(malloc)(size_t n)
{
	libtest_malloc_is_custom = 1;
	assert(libtest_have_custom_free());

	return common_malloc(n, FROM_MALLOC);
}


void *
(calloc)(size_t n, size_t m)
{
	struct meminfo meminfo;

	libtest_calloc_is_custom = 1;
	assert(libtest_have_custom_free());

	assert(n);
	assert(m);

	if (n > SIZE_MAX / m) {
		errno = ENOMEM;
		return NULL;
	}
	n *= m;

	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.requested_alloc_size = n;
	meminfo.alignment_type = DEFAULT_ALIGNMENT;
	meminfo.initialised_on_alloc = 1;
	meminfo.origin = FROM_CALLOC;

	return libtest_alloc(&meminfo);
}


void *
(realloc)(void *old_ptr, size_t new_n)
{
	libtest_realloc_is_custom = 1;
	assert(libtest_have_custom_free());

	return common_realloc(old_ptr, new_n, FROM_REALLOC);
}


void *
(reallocarray)(void *old_ptr, size_t new_n, size_t new_m)
{
	libtest_reallocarray_is_custom = 1;
	assert(libtest_have_custom_free());

	assert(new_n);
	assert(new_m);

	if (new_n > SIZE_MAX / new_m) {
		errno = ENOMEM;
		return NULL;
	}

	return common_realloc(old_ptr, new_n * new_m, FROM_REALLOCARRAY);
}


void *
(valloc)(size_t size)
{
	struct meminfo meminfo;

	libtest_valloc_is_custom = 1;
	assert(libtest_have_custom_free());

	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.requested_alloc_size = size;
	meminfo.alignment_type = PAGE_ALIGNMENT;
	meminfo.initialised_on_alloc = 0;
	meminfo.origin = FROM_VALLOC;

	return libtest_alloc(&meminfo);
}


void *
(pvalloc)(size_t size)
{
	struct meminfo meminfo;
	void *ptr;
	size_t pagesize;

	libtest_pvalloc_is_custom = 1;
	assert(libtest_have_custom_free());

	pagesize = libtest_get_pagesize();
	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.requested_alloc_size = size + (pagesize - size % pagesize) % pagesize;
	meminfo.alignment_type = PAGE_ALIGNMENT;
	meminfo.initialised_on_alloc = 0;
	meminfo.origin = FROM_PVALLOC;

	ptr = libtest_alloc(&meminfo);
	if (ptr)
		GET_MEMINFO(ptr)->requested_alloc_size = size;
	return ptr;
}


void *
(memalign)(size_t alignment, size_t size)
{
	libtest_memalign_is_custom = 1;
	assert(libtest_have_custom_free());

	return common_memalign(alignment, size, FROM_MEMALIGN);
}


void *
(aligned_alloc)(size_t alignment, size_t size)
{
	libtest_aligned_alloc_is_custom = 1;
	assert(libtest_have_custom_free());

	assert(alignment);
	assert(!(size % alignment));

	return common_memalign(alignment, size, FROM_ALIGNED_ALLOC);
}


int
(posix_memalign)(void **memptr, size_t alignment, size_t size)
{
	struct meminfo meminfo;
	int err, saved_errno = errno;
	void *ptr;

	libtest_posix_memalign_is_custom = 1;
	assert(libtest_have_custom_free());

	assert(size);
	assert(alignment);
	assert(!(alignment & (alignment - 1u)));
	assert(!(alignment & (sizeof(void *) - 1u)));

	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.requested_alloc_size = size;
	meminfo.alignment_type = CUSTOM_ALIGNMENT;
	meminfo.requested_alignment = alignment;
	meminfo.initialised_on_alloc = 0;
	meminfo.origin = FROM_POSIX_MEMALIGN;

	ptr = libtest_alloc(&meminfo);
	err = ptr ? 0 : errno;
	if (!err)
		*memptr = ptr;

	errno = saved_errno;
	return err;
}


PURE
size_t
(malloc_usable_size)(void *ptr)
{
	libtest_malloc_usable_size_is_custom = 1;
	assert(libtest_have_custom_malloc());

	return ptr ? GET_MEMINFO(ptr)->usable_alloc_size : 0u;
}


void
(free)(void *ptr)
{
	libtest_free_is_custom = 1;

	if (ptr) {
		struct meminfo *meminfo;
		meminfo = GET_MEMINFO(ptr);
		if (!meminfo->accept_leakage) {
			assert(meminfo->origin != FROM_VALLOC);
			assert(meminfo->origin != FROM_PVALLOC);
		}
	}

	libtest_free(ptr, REQUIRE_ZEROED);
}


void
(free_sized)(void *ptr, size_t size)
{
	libtest_free_sized_is_custom = 1;

	if (ptr) {
		struct meminfo *meminfo;
		meminfo = GET_MEMINFO(ptr);
		assert(meminfo->alignment_type == DEFAULT_ALIGNMENT);
		assert(meminfo->requested_alloc_size == size);
	}

	libtest_free(ptr, REQUIRE_ZEROED);
}


void
(free_aligned_sized)(void *ptr, size_t alignment, size_t size)
{
	libtest_free_aligned_sized_is_custom = 1;

	if (ptr) {
		struct meminfo *meminfo;
		meminfo = GET_MEMINFO(ptr);
		assert(meminfo->alignment_type == CUSTOM_ALIGNMENT);
		assert(meminfo->requested_alloc_size == size);
		assert(meminfo->requested_alignment == alignment);
	}

	libtest_free(ptr, REQUIRE_ZEROED);
}


#else


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wredundant-decls"
#endif


void *(malloc)(size_t n);
void *(calloc)(size_t n, size_t m);
void *(realloc)(void *old_ptr, size_t new_n);
void *(reallocarray)(void *old_ptr, size_t new_n, size_t new_m);
void *(valloc)(size_t size);
void *(pvalloc)(size_t size);
void *(memalign)(size_t alignment, size_t size);
void *(aligned_alloc)(size_t alignment, size_t size);
int (posix_memalign)(void **memptr, size_t alignment, size_t size);
size_t (malloc_usable_size)(void *ptr);
void (free)(void *ptr);
void (free_sized)(void *ptr, size_t size);
void (free_aligned_sized)(void *ptr, size_t alignment, size_t size);


static void
fill_memory(uint8_t *mem, size_t n)
{
	size_t i;
	for (i = 0u; i < n; i++)
		mem[i] = (uint8_t)i;
}


static int
check_memory(uint8_t *mem, size_t filled, size_t zeroed)
{
	size_t i;
	uint8_t bad = 0;
	for (i = 0u; i < filled; i++)
		bad |= (uint8_t)(mem[i] ^ (uint8_t)i);
	for (i = filled; i < filled + zeroed; i++)
		bad |= mem[i];
	return !bad;
}


#define p libtest_p___
extern void *volatile p;
void *volatile p;


static void
check(int use_free)
{
	void *q;

	p = malloc(10u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 10u);
	assert(malloc_usable_size(p) >= 10u);
	if (use_free)
		free(p);
	else
		free_sized(p, 10u);

	p = calloc(3u, 4u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 12u);
	assert(malloc_usable_size(p) >= 12u);
	if (use_free)
		free(p);
	else
		free_sized(p, 12u);

	p = realloc(NULL, 5u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 5u);
	assert(malloc_usable_size(p) >= 5u);
	fill_memory(p, 5u);

	p = realloc(p, 9u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 9u);
	assert(malloc_usable_size(p) >= 9u);
	assert(check_memory(p, 5u, 4u));

	p = realloc(p, 3u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 3u);
	assert(malloc_usable_size(p) >= 3u);
	assert(check_memory(p, 3u, 0u));
	if (use_free)
		free(p);
	else
		free_sized(p, 3u);

	p = reallocarray(NULL, 3u, 10u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 30u);
	assert(malloc_usable_size(p) >= 30u);
	fill_memory(p, 30u);

	p = reallocarray(p, 10u, 10u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 100u);
	assert(malloc_usable_size(p) >= 100u);
	assert(check_memory(p, 30u, 70u));

	p = reallocarray(p, 5u, 10u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)p % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 50u);
	assert(malloc_usable_size(p) >= 50u);
	assert(check_memory(p, 30u, 20u));
	if (use_free)
		free(p);
	else
		free_sized(p, 50u);

	p = memalign(2u, 7u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == 2u);
	assert((uintptr_t)p % 2u == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 7u);
	assert(malloc_usable_size(p) >= 7u);
	if (use_free)
		free(p);
	else
		free_aligned_sized(p, 2u, 7u);

	p = aligned_alloc(2u, 4u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == 2u);
	assert((uintptr_t)p % 2u == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 4u);
	assert(malloc_usable_size(p) >= 4u);
	if (use_free)
		free(p);
	else
		free_aligned_sized(p, 2u, 4u);

	assert(!posix_memalign(&q, sizeof(void *), 11u));
	p = q;
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == sizeof(void *));
	assert((uintptr_t)p % 2u == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 11u);
	assert(malloc_usable_size(p) >= 11u);
	if (use_free)
		free(p);
	else
		free_aligned_sized(p, sizeof(void *), 11u);
}


int
main(void)
{
	size_t pagesize;

	SET_UP_ALARM();

	libtest_start_tracking();

	check(1);
	check(0);

	pagesize = libtest_get_pagesize();

	libtest_stop_tracking();

	p = valloc(6u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == pagesize);
	assert((uintptr_t)p % (uintptr_t)pagesize == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 6u);
	assert(malloc_usable_size(p) >= 6u);
	/* cannot be free(3)ed */

	p = pvalloc(8u);
	assert(p);
	assert(GET_MEMINFO(p)->requested_alignment == pagesize);
	assert((uintptr_t)p % (uintptr_t)pagesize == 0u);
	assert(GET_MEMINFO(p)->requested_alloc_size == 8u);
	assert(malloc_usable_size(p) >= pagesize);
	/* cannot be free(3)ed */

	assert(libtest_check_no_leaks());
	return 0;

	/* TODO test failures */
}


#endif
