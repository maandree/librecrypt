/* See LICENSE file for copyright and license details. */
#include <setjmp.h>
#include <stddef.h>
#include <signal.h>


/**
 * Start tracking resources which `libtest_check_no_leaks`
 * will detect if they are not released
 * 
 * Memory resource tracking will only be started for the
 * calling thread
 */
void libtest_start_tracking(void);

/**
 * Stop tracking resources, so that `libtest_check_no_leaks`
 * will not detect if they are not released
 * 
 * Memory resource tracking will only be stop for the
 * calling thread
 */
void libtest_stop_tracking(void);

/**
 * Check for resource leaks
 * 
 * Memory leaks are detected for all threads with
 * tracking enabled, not just the calling thread
 * 
 * Any leak will be printed to standard error
 * 
 * @return  1 if there was no leaks, 0 otherwise
 */
int libtest_check_no_leaks(void);


/**
 * Make all overriden memory allocation functions
 * full the usable memory area with null bytes,
 * or disable this feature
 *
 * The setting applies only to the calling thread
 * 
 * @param  enabled  1 to enable, 0 to disable
 */
void libtest_force_zero_on_alloc(int enabled);

/**
 * Make all overriden memory deallocation functions
 * check that the entire usable memory area is filled
 * with null bytes, or disable this feature
 * 
 * The setting applies only to the calling thread
 * 
 * @param  enabled  1 to enable, 0 to disable
 */
void libtest_expect_zeroed_on_free(int enabled);


/**
 * Test whether malloc(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_malloc(void);

/**
 * Test whether calloc(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_calloc(void);

/**
 * Test whether realloc(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_realloc(void);

/**
 * Test whether reallocarray(3) has been overridden,
 * allowing allocations to be tracked, and memory
 * allocation failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_reallocarray(void);

/**
 * Test whether valloc(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_valloc(void);

/**
 * Test whether pvalloc(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_pvalloc(void);

/**
 * Test whether memalign(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_memalign(void);

/**
 * Test whether aligned_alloc(3) has been overridden,
 * allowing allocations to be tracked, and memory
 * allocation failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_aligned_alloc(void);

/**
 * Test whether posix_memalign(3) has been overridden,
 * allowing allocations to be tracked, and memory
 * allocation failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_posix_memalign(void);

/**
 * Test whether strdup(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_strdup(void);

/**
 * Test whether strndup(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_strndup(void);

/**
 * Test whether wcsdup(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_wcsdup(void);

/**
 * Test whether wcsndup(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_wcsndup(void);

/**
 * Test whether memdup(3) has been overridden, allowing
 * allocations to be tracked, and memory allocation
 * failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_memdup(void);

/**
 * Test whether malloc_usable_size(3) has been overridden,
 * allowing it to be used for override implementations of
 * memory allocation functions
 * 
 * Tools like valgrind(1) prevent resource allocation
 * inspection functions from being overridden as they
 * may override such functions themselves as they may
 * override memory allocation functions to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_malloc_usable_size(void);

/**
 * Test whether free(3) has been overridden, allowing it
 * to be used for override implementations of memory
 * allocation functions
 * 
 * Tools like valgrind(1) prevent resource deallocation
 * functions from being overridden as they may override
 * such functions themselves as they may override memory
 * allocation functions to detect leaks and invalid
 * memory access patterns
 * 
 * You don't have to call this function yourself,
 * overriden memory allocation function will call it
 * and abort the process if this function return 0,
 * likewise free(3) will abort the process if one of
 * the memory allocation functions have not been
 * overriden
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_free(void);

/**
 * Test whether free_sized(3) has been overridden,
 * allowing it to be used for override implementations
 * of memory allocation functions
 * 
 * Tools like valgrind(1) prevent resource deallocation
 * functions from being overridden as they may override
 * such functions themselves as they may override memory
 * allocation functions to detect leaks and invalid
 * memory access patterns
 * 
 * You don't have to call this function yourself,
 * overriden memory allocation function will call it
 * and abort the process if this function return 0,
 * likewise free_sized(3) will abort the process if
 * one of the memory allocation functions, whose
 * alloactions it can deallocate, have not been
 * overriden
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_free_sized(void);

/**
 * Test whether free_aligned_sized(3) has been overridden,
 * allowing it to be used for override implementations
 * of memory allocation functions
 * 
 * Tools like valgrind(1) prevent resource deallocation
 * functions from being overridden as they may override
 * such functions themselves as they may override memory
 * allocation functions to detect leaks and invalid
 * memory access patterns
 * 
 * You don't have to call this function yourself,
 * overriden memory allocation function will call it
 * and abort the process if this function return 0,
 * likewise free_aligned_sized(3) will abort the process
 * if one of the memory allocation functions, whose
 * alloactions it can deallocate, have not been
 * overriden
 * 
 * @return  1 if overridden, 0 otherwise
 */
int libtest_have_custom_free_aligned_sized(void);

/**
 * Test whether mmap(3), munmap(3), and mremap(3) has
 * been overridden, allowing allocations to be tracked,
 * and memory allocation failures to be injected
 * 
 * Tools like valgrind(1) prevent resource allocation
 * functions from being overridden as they may override
 * such functions themselves in order to detect leaks
 * and invalid memory access patterns
 * 
 * @return  1 if all three overridden,
 *          0 if none have been overridden
 * 
 * The case that only some of the three functions have
 * been overriden, those will redirect to the real
 * implementation and identify as non-overridden
 */
int libtest_have_custom_mmap(void);


/**
 * Print a stack trace, to standard error, provided
 * that backtrace support was enabled at compile-time
 * 
 * @param  prefix  The text to print at the beginning of the first line
 * @param  indent  The text to print at the beginning of the other lines
 * 
 * If one if `prefix` or `indent` is `NULL`, the other
 * will be used as both. Both may not be `NULL` at the
 * same time.
 */
void libtest_dump_stack(const char *prefix, const char *indent);

/**
 * Set up a signal handler to print a stack trace when
 * a signal is received
 * 
 * This function has no affect if backtrace support
 * was disbled at compile-time, and therefore `*old_out`
 * is only set if backtrace support was enabled
 * 
 * @param  signo    The signal to catch
 * @param  old_out  Output parameter for the older signal handler
 */
void libtest_stack_on_signal(int signo, struct sigaction *old_out);

/**
 * Undo `libtest_stack_on_signal`
 * 
 * This function has no affect if backtrace support
 * was disbled at compile-time, making it safe,
 * unlike sigaction(3), to use to to restore the
 * old signal handler returned by `libtest_stack_on_signal`
 * when backtrace support is disabled. Additionally,
 * this function will deallocate the alternative stack
 * set up by `libtest_stack_on_signal` once it has been
 * called as many times as `libtest_stack_on_signal`.
 * 
 * @param  signo  The signal handler to stop catching
 * @param  old    The old signal handler to restore
 */
void libtest_stop_stack_on_signal(int signo, const struct sigaction *old);


/**
 * Get the number of allocation attempts
 * before the next allocation will fail
 * (ENOMEM), including that attempt in
 * the count
 *
 * @return  0 if no memory allocation failure is scheduled,
 *          1 if the next memory allocation will fail,
 *          2 if the attempt after that will fail,
 *          and so on
 */
#if defined(__GNUC__)
__attribute__((__pure__))
#endif
size_t libtest_get_alloc_failure_in(void);

/**
 * Get the number of allocation attempts
 * before the next allocation will fail
 * (ENOMEM), including that attempt in
 * the count
 *
 * @param  n  0 if no memory allocation should fail,
 *            1 if the next memory allocation shall fail,
 *            2 if the attempt after that shall fail,
 *            and so on
 * 
 * Once the scheduled memory allocation
 * failure as occurred, the schedule is
 * cleared and the next attempt will be
 * successful (provided that there isn't
 * a real failure)
 */
void libtest_set_alloc_failure_in(size_t n);


extern const unsigned char *volatile libtest_random_pattern;
extern volatile size_t libtest_random_pattern_length;
extern volatile size_t libtest_random_pattern_offset;

#if defined(__linux__)
extern volatile int libtest_getrandom_real;
extern volatile int libtest_getrandom_error;
extern volatile size_t libtest_getrandom_max_return;
#endif

extern volatile int libtest_getentropy_real;
extern volatile int libtest_getentropy_error;
extern volatile size_t libtest_getentropy_calls;
extern volatile int libtest_getentropy_jmp_val;
extern jmp_buf libtest_getentropy_jmp;
