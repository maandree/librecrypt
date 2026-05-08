/* See LICENSE file for copyright and license details. */

void libtest_start_tracking(void);
void libtest_stop_tracking(void);
int libtest_check_no_leaks(void);
void libtest_force_zero_on_alloc(int);
void libtest_expect_zeroed_on_free(int);

int libtest_have_custom_malloc(void);
int libtest_have_custom_calloc(void);
int libtest_have_custom_realloc(void);
int libtest_have_custom_reallocarray(void);
int libtest_have_custom_valloc(void);
int libtest_have_custom_pvalloc(void);
int libtest_have_custom_memalign(void);
int libtest_have_custom_aligned_alloc(void);
int libtest_have_custom_posix_memalign(void);
int libtest_have_custom_malloc_usable_size(void);
int libtest_have_custom_free(void);
int libtest_have_custom_free_sized(void);
int libtest_have_custom_free_aligned_sized(void);

void libtest_dump_stack(const char *indent);
