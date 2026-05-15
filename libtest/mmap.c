/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST

#if !defined(__linux__)
# errno "Don't know how to implement mmap(3), mumap(3), and mremap(3)"
#endif


#ifdef SYS_mmap2
# define IF_MMAP2(A) do { A; } while (0)
#else
# define IF_MMAP2(A) ((void)0)
#endif

#if defined(__x86_64__) && defined(__ILP32__) /* x32 */
# define SYSCALL_ARG_MAX LLONG_MAX
#else
# define SYSCALL_ARG_MAX LONG_MAX
#endif


void *
libtest_real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	size_t pagesize = libtest_get_pagesize();
	uintptr_t ret;

	IF_MMAP2(assert(pagesize == 4096u));
	if (off < 0 || off % (off_t)pagesize)
		goto einval;
	IF_MMAP2(off /= (off_t)pagesize);

	if (off > SYSCALL_ARG_MAX)
		goto einval;

#ifdef SYS_mmap2
	ret = (uintptr_t)syscall(SYS_mmap2, addr, len, prot, flags, fd, off);
#else
	ret = (uintptr_t)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
#endif
	return (void *)ret;

einval:
	errno = EINVAL;
	return MAP_FAILED;
}


int
libtest_real_munmap(void *addr, size_t len)
{
	return (int)syscall(SYS_munmap, addr, len);
}


void *
libtest_real_mremap(void *old_addr, size_t old_len, size_t new_len, int flags, ...)
{
	va_list args;
	void *new_addr = NULL;
	uintptr_t ret;

	if (flags & MREMAP_FIXED) {
		va_start(args, flags);
		new_addr = va_arg(args, void *);
		va_end(args);
	}

	ret = (uintptr_t)syscall(SYS_mremap, old_addr, old_len, new_len, flags, new_addr);
	return (void *)ret;
}


#else


CONST int
main(void)
{
	/* TODO maybe test */
	return 0;
}


#endif
