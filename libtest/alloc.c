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
	assert(libtest_have_custom_free_sized());

	return common_malloc(n, FROM_MALLOC);
}


void *
(calloc)(size_t n, size_t m)
{
	struct meminfo meminfo;

	libtest_calloc_is_custom = 1;
	assert(libtest_have_custom_free());
	assert(libtest_have_custom_free_sized());

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
	assert(libtest_have_custom_free_sized());

	return common_realloc(old_ptr, new_n, FROM_REALLOC);
}


void *
(reallocarray)(void *old_ptr, size_t new_n, size_t new_m)
{
	libtest_reallocarray_is_custom = 1;
	assert(libtest_have_custom_free());
	assert(libtest_have_custom_free_sized());

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
	assert(libtest_have_custom_free_aligned_sized());

	return common_memalign(alignment, size, FROM_MEMALIGN);
}


void *
(aligned_alloc)(size_t alignment, size_t size)
{
	libtest_aligned_alloc_is_custom = 1;
	assert(libtest_have_custom_free());
	assert(libtest_have_custom_free_aligned_sized());

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
	assert(libtest_have_custom_free_aligned_sized());

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


PURE size_t
(malloc_usable_size)(void *ptr)
{
	libtest_malloc_usable_size_is_custom = 1;
	assert(libtest_have_custom_malloc());

	return ptr ? GET_MEMINFO(ptr)->usable_alloc_size : 0u;
}


void
(free)(void *ptr)
{
	if (libtest_free_is_custom < 0) {
		libtest_free_is_custom = 1;

		assert(libtest_have_custom_malloc());
		assert(libtest_have_custom_calloc());
		assert(libtest_have_custom_realloc());
		assert(libtest_have_custom_reallocarray());
		assert(libtest_have_custom_valloc());
		assert(libtest_have_custom_pvalloc());
		assert(libtest_have_custom_memalign());
		assert(libtest_have_custom_aligned_alloc());
		assert(libtest_have_custom_posix_memalign());
		assert(libtest_have_custom_strdup());
		assert(libtest_have_custom_strndup());
		assert(libtest_have_custom_wcsdup());
		assert(libtest_have_custom_wcsndup());
		assert(libtest_have_custom_memdup());
	}

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
	if (libtest_free_sized_is_custom < 0) {
		libtest_free_sized_is_custom = 1;

		assert(libtest_have_custom_malloc());
		assert(libtest_have_custom_calloc());
		assert(libtest_have_custom_realloc());
		assert(libtest_have_custom_reallocarray());
		assert(libtest_have_custom_memdup());
	}

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
	if (libtest_free_aligned_sized_is_custom < 0) {
		libtest_free_aligned_sized_is_custom = 1;

		assert(libtest_have_custom_memalign());
		assert(libtest_have_custom_aligned_alloc());
		assert(libtest_have_custom_posix_memalign());
	}

	libtest_free_aligned_sized_is_custom = 1;

	if (ptr) {
		struct meminfo *meminfo;
		meminfo = GET_MEMINFO(ptr);
		assert(meminfo->alignment_type == CUSTOM_ALIGNMENT);
		assert(meminfo->requested_alloc_size == size);
		assert(meminfo->requested_alignment == alignment);
		assert(meminfo->origin != FROM_STRDUP);
		assert(meminfo->origin != FROM_STRNDUP);
		assert(meminfo->origin != FROM_WCSDUP);
		assert(meminfo->origin != FROM_WCSDUP);
	}

	libtest_free(ptr, REQUIRE_ZEROED);
}


char *
(strdup)(const char *s)
{
	size_t n;
	char *p;

	libtest_strdup_is_custom = 1;
	assert(libtest_have_custom_free());

	n = strlen(s) + 1u;
	p = common_memalign(_Alignof(char), n * sizeof(*s), FROM_STRDUP);
	if (p)
		memcpy(p, s, n * sizeof(*s));
	return p;
}


char *
(strndup)(const char *s, size_t n)
{
	char *p;

	libtest_strndup_is_custom = 1;
	assert(libtest_have_custom_free());

	n = strnlen(s, n);
	p = common_memalign(_Alignof(char), (n + 1u) * sizeof(*s), FROM_STRNDUP);
	if (p) {
		memcpy(p, s, n * sizeof(*s));
		p[n] = '\0';
	}
	return p;
}


wchar_t *
(wcsdup)(const wchar_t *s)
{
	size_t n;
	wchar_t *p;

	libtest_wcsdup_is_custom = 1;
	assert(libtest_have_custom_free());

	n = wcslen(s) + 1u;
	p = common_memalign(_Alignof(wchar_t), n * sizeof(*s), FROM_WCSDUP);
	if (p)
		memcpy(p, s, n * sizeof(*s));
	return p;
}


wchar_t *
(wcsndup)(const wchar_t *s, size_t n)
{
	wchar_t *p;

	libtest_wcsndup_is_custom = 1;
	assert(libtest_have_custom_free());

	n = wcsnlen(s, n);
	p = common_memalign(_Alignof(wchar_t), (n + 1u) * sizeof(*s), FROM_WCSNDUP);
	if (p) {
		memcpy(p, s, n * sizeof(*s));
		p[n] = 0;
	}
	return p;
}


void *
(memdup)(const void *s, size_t n)
{
	char *p;

	libtest_memdup_is_custom = 1;
	assert(libtest_have_custom_free());
	assert(libtest_have_custom_free_sized());

	p = common_malloc(n, FROM_MEMDUP);
	if (p)
		memcpy(p, s, n);
	return p;
}


int
libtest_check_custom_mmap(void)
{
	static _Thread_local int in_check_custom_mmap = 0;
	char *volatile test_dummy = NULL;

	if (in_check_custom_mmap)
		return libtest_mmap_is_custom;
	in_check_custom_mmap = 1;

	if (libtest_mmap_is_custom >= 0 &&
	    libtest_mremap_is_custom >= 0 &&
	    libtest_munmap_is_custom >= 0) {
		if (libtest_mmap_is_custom & libtest_mremap_is_custom & libtest_munmap_is_custom)
			goto custom;
		goto real_deallocated;
	}

	test_dummy = mmap(NULL, 1u, PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(test_dummy != MAP_FAILED);
	assert(test_dummy != NULL);
	*test_dummy = 0;

	if (libtest_mmap_is_custom == 0)
		goto real;

	if (libtest_mremap_is_custom < 0) {
		test_dummy = mremap(test_dummy, 1u, 1u, MREMAP_MAYMOVE);
		assert(test_dummy != MAP_FAILED);
		assert(test_dummy != NULL);
	}
	if (libtest_mremap_is_custom == 0)
		goto real;

	if (libtest_munmap_is_custom < 0)
		assert(!munmap(test_dummy, 1u));
	if (libtest_munmap_is_custom == 0)
		goto real_deallocated;

custom:
	in_check_custom_mmap = 0;
	return 1;

real:
	assert(!munmap(test_dummy, 1u));
real_deallocated:
	in_check_custom_mmap = 0;
	libtest_mmap_is_custom = 0;
	libtest_mremap_is_custom = 0;
	libtest_munmap_is_custom = 0;
	return 0;
}


void *
(mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	/* TODO implement tracking */

	libtest_mmap_is_custom = 1;
	if (!libtest_check_custom_mmap())
		goto real;

	if (!libtest_malloc_internal_usage) {
		if (libtest_malloc_fail_in && !--libtest_malloc_fail_in) {
			errno = ENOMEM;
			return MAP_FAILED;
		}
	}

real:
	return libtest_real_mmap(addr, len, prot, flags, fd, off);
}


int
(munmap)(void *addr, size_t len)
{
	libtest_munmap_is_custom = 1;
	if (!libtest_check_custom_mmap())
		goto real;

real:
	return libtest_real_munmap(addr, len);
}


void *
(mremap)(void *old_addr, size_t old_len, size_t new_len, int flags, ...)
{
	va_list args;
	void *new_addr = NULL;

	if (flags & MREMAP_FIXED) {
		va_start(args, flags);
		new_addr = va_arg(args, void *);
		va_end(args);
	}

	libtest_mremap_is_custom = 1;
	if (!libtest_check_custom_mmap())
		goto real;

	if (!libtest_malloc_internal_usage) {
		if (libtest_malloc_fail_in && !--libtest_malloc_fail_in) {
			errno = ENOMEM;
			return MAP_FAILED;
		}
	}

real:
	return libtest_real_mremap(old_addr, old_len, new_len, flags, new_addr);
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
char *(strdup)(const char *s);
char *(strndup)(const char *s, size_t n);
wchar_t *(wcsdup)(const wchar_t *s);
wchar_t *(wcsndup)(const wchar_t *s, size_t n);
void *(memdup)(const void *s, size_t n);
void *(mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int (munmap)(void *addr, size_t len);
void *(mremap)(void *old_addr, size_t old_len, size_t new_len, int flags, ...);


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


static void
check_successfuls(void)
{
	size_t pagesize;
	char *s;
	wchar_t *w;
	void *q;

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

	libtest_start_tracking();

	s = strdup("test string");
	assert(s);
	assert(malloc_usable_size(s) >= sizeof("test string"));
	assert(GET_MEMINFO(s)->requested_alignment == _Alignof(char));
	assert((uintptr_t)s % (uintptr_t)_Alignof(char) == 0u);
	assert(GET_MEMINFO(s)->requested_alloc_size == sizeof("test string"));
	EXPECT(!strcmp(s, "test string"));
	free(s);

	s = strndup("test string", 100u);
	assert(s);
	assert(malloc_usable_size(s) >= sizeof("test string"));
	assert(GET_MEMINFO(s)->requested_alignment == _Alignof(char));
	assert((uintptr_t)s % (uintptr_t)_Alignof(char) == 0u);
	assert(GET_MEMINFO(s)->requested_alloc_size == sizeof("test string"));
	EXPECT(!strcmp(s, "test string"));
	free(s);

	s = strndup("test string", 4u);
	assert(s);
	assert(malloc_usable_size(s) >= sizeof("test"));
	assert(GET_MEMINFO(s)->requested_alignment == _Alignof(char));
	assert((uintptr_t)s % (uintptr_t)_Alignof(char) == 0u);
	assert(GET_MEMINFO(s)->requested_alloc_size == sizeof("test"));
	EXPECT(!strcmp(s, "test"));
	free(s);

	s = memdup("test", 4u);
	assert(s);
	assert(malloc_usable_size(s) >= 4u);
	assert(GET_MEMINFO(s)->requested_alignment == _Alignof(max_align_t));
	assert((uintptr_t)s % (uintptr_t)_Alignof(max_align_t) == 0u);
	assert(GET_MEMINFO(s)->requested_alloc_size == 4u);
	EXPECT(!memcmp(s, "test", 4u));
	free(s);

	w = wcsdup((wchar_t[]){11, 22, 33, 0});
	assert(w);
	assert(malloc_usable_size(w) >= 4u * sizeof(wchar_t));
	assert(GET_MEMINFO(w)->requested_alignment == _Alignof(wchar_t));
	assert((uintptr_t)w % (uintptr_t)_Alignof(wchar_t) == 0u);
	assert(GET_MEMINFO(w)->requested_alloc_size == 4u * sizeof(wchar_t));
	EXPECT(!memcmp(w, (wchar_t[]){11, 22, 33, 0}, 4u * sizeof(wchar_t)));
	free(w);

	w = wcsndup((wchar_t[]){11, 22, 33, 0}, 100u);
	assert(w);
	assert(malloc_usable_size(w) >= 4u * sizeof(wchar_t));
	assert(GET_MEMINFO(w)->requested_alignment == _Alignof(wchar_t));
	assert((uintptr_t)w % (uintptr_t)_Alignof(wchar_t) == 0u);
	assert(GET_MEMINFO(w)->requested_alloc_size == 4u * sizeof(wchar_t));
	EXPECT(!memcmp(w, (wchar_t[]){11, 22, 33, 0}, 4u * sizeof(wchar_t)));
	free(w);

	w = wcsndup((wchar_t[]){11, 22, 33, 0}, 2u);
	assert(w);
	assert(malloc_usable_size(w) >= 3u * sizeof(wchar_t));
	assert(GET_MEMINFO(w)->requested_alignment == _Alignof(wchar_t));
	assert((uintptr_t)w % (uintptr_t)_Alignof(wchar_t) == 0u);
	assert(GET_MEMINFO(w)->requested_alloc_size == 3u * sizeof(wchar_t));
	EXPECT(!memcmp(w, (wchar_t[]){11, 22, 0}, 3u * sizeof(wchar_t)));
	free(w);

	p = mmap(NULL, 1u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(p != MAP_FAILED);
	p = mremap(p, 1u, 2u, 0);
	assert(p != MAP_FAILED);
	assert(malloc_usable_size(p) >= 6u);
	asser(!munmap(p, 2u));
}


static void
check_failures(void)
{
	void *q;

	libtest_set_alloc_failure_in(2u);
	p = malloc(1u);
	EXPECT(p);
	free(p);
	assert(libtest_get_alloc_failure_in() == 1u);
	errno = 0;
	p = malloc(1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = calloc(1u, 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = realloc(NULL, 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());
	p = realloc(NULL, 1u);
	assert(p);
	libtest_set_alloc_failure_in(1u);
	errno = 0;
	EXPECT(!realloc(p, 1u));
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());
	free(p);

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	EXPECT(!reallocarray(NULL, 1u, 1u));
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());
	p = reallocarray(NULL, 1u, 1u);
	assert(p);
	libtest_set_alloc_failure_in(1u);
	errno = 0;
	EXPECT(!reallocarray(p, 1u, 1u));
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());
	free(p);

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = memalign(1u, 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = aligned_alloc(1u, 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	EXPECT(posix_memalign(&q, sizeof(void *), 1u) == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = valloc(1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = pvalloc(1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = strdup("x");
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = strndup("x", 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = wcsdup((wchar_t[]){1, 0});
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = wcsndup((wchar_t[]){1, 0}, 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = memdup("x", 1u);
	EXPECT(!p);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = mmap(NULL, 1u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT(p == MAP_FAILED);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());

	p = mmap(NULL, 1u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(p != MAP_FAILED);
	q = p;
	libtest_set_alloc_failure_in(1u);
	errno = 0;
	p = mremap(p, 1u, 2u, 0);
	EXPECT(errno == ENOMEM);
	EXPECT(!libtest_get_alloc_failure_in());
	munmap(q, 1u);
}


int
main(void)
{
	SET_UP_ALARM();

	libtest_start_tracking();

	check_successfuls();
	libtest_set_alloc_failure_in(1000u);
	check_successfuls();
	EXPECT(libtest_get_alloc_failure_in() == 1000u - 31u);
	check_failures();

	p = NULL;
	free(p);

	libtest_stop_tracking();
	EXPECT(libtest_check_no_leaks());
	return 0;
}


#endif
