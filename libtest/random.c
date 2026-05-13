/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


unsigned char *libtest_random_pattern = NULL;
size_t libtest_random_pattern_length = 0u;
size_t libtest_random_pattern_offset = 0u;

static ssize_t
genpattern(void *buf, size_t size)
{
	unsigned char *out = buf;
	size_t n;
	ssize_t ret;

	if (size > (size_t)SSIZE_MAX)
		size = (size_t)SSIZE_MAX;

	ret = (ssize_t)size;

	if (libtest_random_pattern_length) {
		while (size) {
			if (libtest_random_pattern_offset == libtest_random_pattern_length)
				libtest_random_pattern_offset = 0u;
			n = libtest_random_pattern_length - libtest_random_pattern_offset;
			if (n > size)
				n = size;
			memcpy(out, &libtest_random_pattern[libtest_random_pattern_offset], n);
			out = &out[n];
			size -= n;
			libtest_random_pattern_offset += n;
		}
	} else {
		for (; size; size--, out++)
			out[0] = (unsigned char)rand();
	}

	return ret;
}


#if defined(__linux__)
int libtest_getrandom_real = 1;
int libtest_getrandom_error = 0;
size_t libtest_getrandom_max_return = SIZE_MAX;

ssize_t
(getrandom)(void *buf, size_t size, unsigned int flags)
{
	if (size > libtest_getrandom_max_return)
		size = libtest_getrandom_max_return;

	if (libtest_getrandom_error) {
		errno = libtest_getrandom_error;
		if (libtest_getrandom_error == EINTR)
			libtest_getrandom_error = 0;
		return -1;
	}

	if (!libtest_getrandom_real)
		return genpattern(buf, size);

# if defined(SYS_getrandom)
	return syscall(SYS_getrandom, buf, size, flags);
# else
	errno = ENOSYS;
	return -1;
# endif
}
#endif


int libtest_getentropy_real = 1;
int libtest_getentropy_error = 0;
size_t libtest_getentropy_calls = 0u;
int libtest_getentropy_jmp_val = 0;
jmp_buf libtest_getentropy_jmp;

int
(getentropy)(void *buf, size_t size)
{
	unsigned char *out = buf;
	ssize_t r;

	libtest_getentropy_calls += 1u;

	if (libtest_getentropy_jmp_val)
		longjmp(libtest_getentropy_jmp, libtest_getentropy_jmp_val);

	if (libtest_getentropy_error) {
		errno = libtest_getentropy_error;
		if (libtest_getentropy_error == EINTR)
			libtest_getentropy_error = 0;
		return -1;
	}

	if (size > 256u) {
		errno = EIO;
		return -1;
	}

	if (!libtest_getentropy_real) {
		r = genpattern(out, size);
		if (r == (ssize_t)size)
			return 0;
		errno = EIO;
		return -1;
	}

#if defined(__linux__) && defined(SYS_getrandom)
	while (size) {
		r = (ssize_t)syscall(SYS_getrandom, out, size, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno != ENOSYS)
				errno = EIO;
			return -1;
		}
		out = &out[r];
		size -= (size_t)r;
	}
	return 0;
#else
	errno = ENOSYS;
	return -1;
#endif
}


#else


CONST int
main(void)
{
	/* TODO maybe test */
	return 0;
}


#endif
