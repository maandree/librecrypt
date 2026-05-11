/* See LICENSE file for copyright and license details. */
#ifdef WITH_BACKTRACE
# define UNW_LOCAL_ONLY
# include <libunwind.h>
# include <elfutils/libdwfl.h>
#endif
#if defined(__linux__)
# include <sys/random.h>
# include <sys/syscall.h>
#endif
#include <sys/mman.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>


#if defined(__clang__)
# pragma clang diagnostic ignored "-Wpre-c11-compat" /* clang is being silly: it complains about _Thread_local */
# pragma clang diagnostic ignored "-Wc++-keyword" /* clang is being silly: it complains about using wchar_t */
# pragma clang diagnostic ignored "-Wimplicit-void-ptr-cast" /* clang is being silly: this is C, not C++ */
# pragma clang diagnostic ignored "-Wunsafe-buffer-usage" /* completely broken warning */
# pragma clang diagnostic ignored "-Wdisabled-macro-expansion" /* clang is being silly: it is common practice, and it complains about libc code */
#endif


#include "libtest.h"


#if __STDC_VERSION__ >= 202311L
# define _Alignof alignof
# define _Alignas alignas
# define _Thread_local thread_local
#endif


#if defined(__GNUC__)
# define HIDDEN __attribute__((__visibility__("hidden")))
# define CONST __attribute__((__const__))
# define PURE __attribute__((__pure__))
#else
# define HIDDEN
# define CONST
# define PURE
#endif


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wpadded"
#endif


#ifndef MAP_UNINITIALIZED
# define MAP_UNINITIALIZED 0
#endif


#define ELEMSOF(A) (sizeof(A) / sizeof(*(A)))


#define BASE_POINTER(PTR) (*libtest_base_pointer((PTR)))
#define GET_MEMINFO(PTR) ((struct meminfo *)BASE_POINTER(PTR))
#define SPINLOCK(LOCK) do {} while (atomic_flag_test_and_set_explicit(&(LOCK), memory_order_acquire))
#define SPINUNLOCK(LOCK) atomic_flag_clear_explicit(&(LOCK), memory_order_release)


enum libtest_zero_check {
	DO_NOT_REQUIRE_ZEROED,
	REQUIRE_ZEROED
};

enum align_type {
	DEFAULT_ALIGNMENT,
	PAGE_ALIGNMENT,
	CUSTOM_ALIGNMENT
};

enum memory_origin {
	FROM_MALLOC,
	FROM_CALLOC,
	FROM_REALLOC,
	FROM_REALLOCARRAY,
	FROM_VALLOC,
	FROM_PVALLOC,
	FROM_MEMALIGN,
	FROM_ALIGNED_ALLOC,
	FROM_POSIX_MEMALIGN,
	FROM_STRDUP,
	FROM_STRNDUP,
	FROM_WCSDUP,
	FROM_WCSNDUP,
	FROM_MEMDUP,
	FROM_MMAP_FILE,
	FROM_MMAP_ANON
};

#ifdef WITH_BACKTRACE
struct backtrace {
	size_t n;
	Dwarf_Addr trace[];
};
#endif

struct meminfo {
#ifdef WITH_BACKTRACE
	struct backtrace *backtrace;
#endif
	struct meminfo *next, *prev;
	void *usable_area;
	size_t real_alloc_size;
	size_t usable_alloc_size;
	size_t requested_alloc_size;
	size_t requested_alignment;
	size_t actual_alignment;
	enum align_type alignment_type;
	int initialised_on_alloc;
	enum memory_origin origin;
	int accept_leakage; /* implies DO_NOT_REQUIRE_ZEROED */
};


extern volatile int libtest_malloc_is_custom;
extern volatile int libtest_calloc_is_custom;
extern volatile int libtest_realloc_is_custom;
extern volatile int libtest_reallocarray_is_custom;
extern volatile int libtest_valloc_is_custom;
extern volatile int libtest_pvalloc_is_custom;
extern volatile int libtest_memalign_is_custom;
extern volatile int libtest_aligned_alloc_is_custom;
extern volatile int libtest_posix_memalign_is_custom;
extern volatile int libtest_malloc_usable_size_is_custom;
extern volatile int libtest_free_is_custom;
extern volatile int libtest_free_sized_is_custom;
extern volatile int libtest_free_aligned_sized_is_custom;
extern volatile int libtest_strdup_is_custom;
extern volatile int libtest_strndup_is_custom;
extern volatile int libtest_wcsdup_is_custom;
extern volatile int libtest_wcsndup_is_custom;
extern volatile int libtest_memdup_is_custom;

extern struct meminfo libtest_allocs_head;
extern struct meminfo libtest_allocs_tail;
extern int libtest_allocs_list_inited;
extern atomic_flag libtest_allocs_list_spinlock;

extern int libtest_zero_on_alloc;
extern int libtest_expect_zeroed;
extern int libtest_malloc_accept_leakage;

extern _Thread_local size_t libtest_malloc_internal_usage;
extern _Thread_local size_t libtest_kill_malloc_tracking;
extern _Thread_local size_t libtest_malloc_fail_in;


HIDDEN inline void **
libtest_base_pointer(void *ptr)
{
	uintptr_t addr = (uintptr_t)ptr - (uintptr_t)sizeof(void *);
	addr -= addr % _Alignof(void *);
	return (void **)addr;
}


HIDDEN size_t libtest_get_pagesize(void);
HIDDEN void *libtest_alloc(struct meminfo *);
HIDDEN void libtest_free(void *, enum libtest_zero_check);

#ifdef WITH_BACKTRACE
HIDDEN void libtest_print_backtrace(FILE *, const char *prefix, const char *indent,
                                    size_t first, const struct backtrace *, ucontext_t *);
#else
# define libtest_print_backtrace(FP, PREFIX, INDENT, FIRST, BACKTRACE, CONTEXT)\
	do {\
		(void) (FP);\
		(void) (PREFIX);\
		(void) (INDENT);\
		(void) (FIRST);\
		(void) (BACKTRACE);\
		(void) (CONTEXT);\
	} while (0)
#endif



#ifdef IMPLEMENT_MMAP
void *libtest_real_mmap(void *, size_t, int, int, int, off_t);
int libtest_real_munmap(void *, size_t);
void *libtest_real_mremap(void *, size_t, size_t, int, ...);
#else
# if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-identifier"
# endif
void *__mmap(void *, size_t, int, int, int, off_t);
int __munmap(void *, size_t);
void *__mremap(void *, size_t, size_t, int, ...);
# define libtest_real_mmap __mmap
# define libtest_real_munmap __munmap
# define libtest_real_mremap __mremap
# if defined(__clang__)
#  pragma clang diagnostic pop
# endif
#endif


#define assert(EXPR)\
	do {\
		if (!(EXPR)) {\
			libtest_malloc_internal_usage++;\
			fprintf(stderr, "Assetion failure at %s:%i: %s\n", __FILE__, __LINE__, #EXPR);\
			libtest_print_backtrace(stderr, NULL, "\t", 0u, NULL, NULL);\
			exit(2);\
		}\
	} while (0)


#ifdef TEST
# ifdef __linux__
#  include <sys/prctl.h>
# endif
# include <sys/resource.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <signal.h>
# include <string.h>
# include <unistd.h>

# define SET_UP_ALARM()\
	do {\
		unsigned int alarm_time__ = alarm(10u);\
		if (alarm_time__ > 10u)\
			alarm(alarm_time__);\
	} while (0)

# if defined(PR_SET_DUMPABLE)
#  define INIT_TEST_ABORT()\
	do {\
		struct rlimit rl__;\
		rl__.rlim_cur = 0;\
		rl__.rlim_max = 0;\
		(void) setrlimit(RLIMIT_CORE, &rl__);\
		(void) prctl(PR_SET_DUMPABLE, 0);\
		EXPECT_ABORT(abort());\
	} while (0)
# else
#  define INIT_TEST_ABORT()\
	do {\
		struct rlimit rl__;\
		rl__.rlim_cur = 0;\
		rl__.rlim_max = 0;\
		(void) setrlimit(RLIMIT_CORE, &rl__);\
		EXPECT_ABORT(abort());\
	} while (0)
# endif

# define EXPECT__(EXPR, HOW, RETEXTRACT, RETEXPECT)\
	do {\
		pid_t pid__;\
		int status__;\
		pid__ = fork();\
		EXPECT(pid__ != -1);\
		if (pid__ == 0) {\
			(EXPR);\
			_exit(0);\
		}\
		EXPECT(waitpid(pid__, &status__, 0) == pid__);\
		EXPECT(HOW(status__));\
		EXPECT(RETEXTRACT(status__) == RETEXPECT);\
	} while (0)

# define EXPECT_ABORT(EXPR)\
	do {\
		EXPECT__(EXPR, WIFSIGNALED, WTERMSIG, SIGABRT);\
	} while (0)

# define EXPECT(EXPR)\
	do {\
		if (!(EXPR)) {\
			libtest_malloc_internal_usage++;\
			fprintf(stderr, "Failure at %s:%i: %s\n", __FILE__, __LINE__, #EXPR);\
			libtest_print_backtrace(stderr, NULL, "\t", 0u, NULL, NULL);\
			exit(1);\
		}\
	} while (0)
#endif
