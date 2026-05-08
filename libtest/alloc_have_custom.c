/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic push
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
PURE size_t (malloc_usable_size)(void *ptr);
void (free)(void *ptr);
void (free_sized)(void *ptr, size_t size);
void (free_aligned_sized)(void *ptr, size_t alignment, size_t size);

#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif


#define CHECK_CUSTOM_ALLOC(WHAT, ...)\
	do {\
		int r = libtest_##WHAT##_is_custom;\
		if (r < 0) {\
			void *p = (WHAT)(__VA_ARGS__);\
			free(p);\
			r = libtest_##WHAT##_is_custom;\
			if (r < 0)\
				libtest_##WHAT##_is_custom = r = 0;\
		}\
		assert(r == 0 || r == 1);\
		return r;\
	} while (0)


static void *
malloc_with_realloc(size_t n)
{
	void *volatile ptr = malloc(1u);
	assert(ptr);
	ptr = realloc(ptr, n);
	assert(ptr);
	return ptr;
}


static void *
malloc_with_reallocarray(size_t n, size_t m)
{
	void *volatile ptr = malloc(1u);
	assert(ptr);
	ptr = reallocarray(ptr, n, m);
	assert(ptr);
	return ptr;
}


static void *
freeable_valloc(size_t n)
{
	void *ptr = valloc(n);
	if (ptr) {
		GET_MEMINFO(ptr)->origin = FROM_ALIGNED_ALLOC;
		GET_MEMINFO(ptr)->alignment_type = CUSTOM_ALIGNMENT;
	}
	return ptr;
}


static void *
freeable_pvalloc(size_t n)
{
	void *ptr = pvalloc(n);
	if (ptr) {
		GET_MEMINFO(ptr)->origin = FROM_ALIGNED_ALLOC;
		GET_MEMINFO(ptr)->alignment_type = CUSTOM_ALIGNMENT;
	}
	return ptr;
}


#define libtest_malloc_with_realloc_is_custom libtest_realloc_is_custom
#define libtest_malloc_with_reallocarray_is_custom libtest_reallocarray_is_custom
#define libtest_freeable_valloc_is_custom libtest_valloc_is_custom
#define libtest_freeable_pvalloc_is_custom libtest_pvalloc_is_custom
int libtest_have_custom_malloc(void) { CHECK_CUSTOM_ALLOC(malloc, 1u); }
int libtest_have_custom_calloc(void) { CHECK_CUSTOM_ALLOC(calloc, 1u, 1u); }
int libtest_have_custom_realloc(void) { CHECK_CUSTOM_ALLOC(malloc_with_realloc, 1u); }
int libtest_have_custom_reallocarray(void) { CHECK_CUSTOM_ALLOC(malloc_with_reallocarray, 1u, 1u); }
int libtest_have_custom_valloc(void) { CHECK_CUSTOM_ALLOC(freeable_valloc, 1u); }
int libtest_have_custom_pvalloc(void) { CHECK_CUSTOM_ALLOC(freeable_pvalloc, 1u); }
int libtest_have_custom_memalign(void) { CHECK_CUSTOM_ALLOC(memalign, 1u, 1u); }
int libtest_have_custom_aligned_alloc(void) { CHECK_CUSTOM_ALLOC(aligned_alloc, 1u, 1u); }


int
libtest_have_custom_posix_memalign(void)
{
	int r = libtest_posix_memalign_is_custom;
	if (r < 0) {
		void *p = NULL;
		r = (posix_memalign)(&p, sizeof(p), 1u);
		if (r)
			free(p);
		r = libtest_posix_memalign_is_custom;
		if (r < 0)
			libtest_posix_memalign_is_custom = r = 0;
	}
	assert(r == 0 || r == 1);
	return r;
}


static volatile size_t libtest_have_custom_malloc_usable_size_discard;

int
libtest_have_custom_malloc_usable_size(void)
{
	int r = libtest_malloc_usable_size_is_custom;
	if (r < 0) {
		void *p = (malloc)(1u);
		assert(p);
		libtest_have_custom_malloc_usable_size_discard = malloc_usable_size(p);
		(free)(p);
		r = libtest_malloc_usable_size_is_custom;
		if (r < 0)
			libtest_malloc_usable_size_is_custom = r = 0;
	}
	assert(r == 0 || r == 1);
	return r;
}


int
libtest_have_custom_free(void)
{
	int r = libtest_free_is_custom;
	void *p;
	if (r < 0) {
		libtest_free_is_custom = 1;
		p = (malloc)(1u);
		assert(p);
		assert(libtest_malloc_is_custom == 1);
		(free)(p);
		r = libtest_free_is_custom;
		if (r < 0)
			libtest_free_is_custom = r = 0;
	}
	assert(r == 0 || r == 1);
	return r;
}


int
libtest_have_custom_free_sized(void)
{
	int r = libtest_free_sized_is_custom;
	void *p;
	if (r < 0) {
		libtest_free_sized_is_custom = 1;
		p = (malloc)(1u);
		assert(p);
		assert(libtest_malloc_is_custom == 1);
		(free_sized)(p, 1u);
		r = libtest_free_sized_is_custom;
		if (r < 0)
			libtest_free_sized_is_custom = r = 0;
	}
	assert(r == 0 || r == 1);
	return r;
}


int
libtest_have_custom_free_aligned_sized(void)
{
	int r = libtest_free_aligned_sized_is_custom;
	void *p;
	if (r < 0) {
		libtest_free_aligned_sized_is_custom = 1;
		p = (aligned_alloc)(1u, 1u);
		assert(p);
		assert(libtest_aligned_alloc_is_custom == 1);
		(free_aligned_sized)(p, 1u, 1u);
		r = libtest_free_aligned_sized_is_custom;
		if (r < 0)
			libtest_free_aligned_sized_is_custom = r = 0;
	}
	assert(r == 0 || r == 1);
	return r;
}


#else


#define CHECK(WHAT)\
	do {\
		fprintf(stderr, "testing %s\n", #WHAT);\
		EXPECT(WHAT() == 1);\
	} while (0)


int
main(void)
{
	SET_UP_ALARM();

	CHECK(libtest_have_custom_malloc);
	CHECK(libtest_have_custom_calloc);
	CHECK(libtest_have_custom_realloc);
	CHECK(libtest_have_custom_reallocarray);
	CHECK(libtest_have_custom_valloc);
	CHECK(libtest_have_custom_pvalloc);
	CHECK(libtest_have_custom_memalign);
	CHECK(libtest_have_custom_aligned_alloc);
	CHECK(libtest_have_custom_posix_memalign);
	CHECK(libtest_have_custom_malloc_usable_size);
	CHECK(libtest_have_custom_free);
	CHECK(libtest_have_custom_free_sized);
	CHECK(libtest_have_custom_free_aligned_sized);

	return 0;
}


#endif
