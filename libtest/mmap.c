/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST

#include <sys/syscall.h>


void *
libtest_real_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	size_t pagesize = libtest_get_pagesize();

	if (off < 0 || off % (off_t)pagesize)
		goto einval;
	off /= (off_t)pagesize;

#if defined(__x86_64__) && defined(__ILP32__) /* x32 */
	if (off > LLONG_MAX)
		goto einval;
#else
	if (off > LONG_MAX)
		goto einval;
#endif

#ifdef SYS_mmap2
	assert(pagesize == 4096u);
	return (void *)syscall(SYS_mmap2, addr, len, prot, flags, fd, off);
#else
	return (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
#endif

einval:
	errno = EINVAL;
	return MAP_FAILED;
}


int
libtest_real_munmap(void *addr, size_t len)
{
	return syscall(SYS_munmap, addr, len);
}


void *
libtest_real_mremap(void *old_addr, size_t old_len, size_t new_len, int flags, ...)
{
	va_list args;
	void *new_addr = NULL;

	if (flags & MREMAP_FIXED) {
		va_start(args, flags);
		new_addr = va_arg(args, void *);
		va_end(args);
	}

	return (void *)syscall(SYS_mremap, old_addr, old_len, new_len, flags, new_addr);
}


#else


CONST int
main(void)
{
	/* TODO maybe test */
	return 0;
}


#endif
