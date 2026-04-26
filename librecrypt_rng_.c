/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_rng_(void *out, size_t n, void *user)
{
	static unsigned int seed = 0u;
	unsigned char *buf = out;
	int v, fd, saved_errno = errno;
	unsigned int state;
	size_t i, min, ret = 0u;
	ssize_t r;
	struct timespec ts;
#if defined(__linux__) && defined(AT_RANDOM)
	const unsigned char *at_random;
	uintptr_t at_random_addr;
#endif

	(void) user;

	if (!n)
		return 0;

	if (n > (size_t)SSIZE_MAX)
		n = (size_t)SSIZE_MAX;

#if defined(__linux__)
	for (;;) {
		r = getrandom(buf, n, 0u);
		if (r < 0) {
			if (errno != EINTR)
				break;
			saved_errno = EINTR;
		} else if (r > 0) {
			ret += (size_t)r;
			buf = &buf[(size_t)r];
			n -= (size_t)r;
			if (!n)
				goto out;
		} else {
			break;
		}
	}
#endif

	for (;;) {
		min = n < 256u ? n : 256u;
		if (getentropy(buf, min)) {
			if (errno != EINTR)
				break;
			saved_errno = EINTR;
		} else {
			ret += min;
			buf = &buf[min];
			n -= min;
			if (!n)
				goto out;
		}
	}

#ifndef O_CLOEXEC
# define O_CLOEXEC 0
#endif
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		for (;;) {
			r = read(fd, buf, n);
			if (r < 0) {
				if (errno != EINTR) {
					close(fd);
					break;
				}
				saved_errno = EINTR;
			} else if (r > 0) {
				ret += (size_t)r;
				buf = &buf[(size_t)r];
				n -= (size_t)r;
				if (!n) {
					close(fd);
					goto out;
				}
			} else {
				close(fd);
				break;
			}
		}
	}

	state = seed;
	if (!state) {
		state = (unsigned int)rand();
		state ^= (unsigned int)time(NULL);
		if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
			state ^= (unsigned int)ts.tv_sec;
			state ^= (unsigned int)ts.tv_nsec;
		}
#if defined(__linux__) && defined(AT_RANDOM)
		at_random_addr = (uintptr_t)getauxval(AT_RANDOM);
		if (at_random_addr) {
			at_random = (const void *)at_random_addr;
			for (i = 0u; i < 16u; i++)
				state ^= (unsigned int)at_random[i] << (i % sizeof(unsigned int) * 8u);
		}
	}
#endif
	for (i = 0u; i < n; i++) {
		v = rand_r(&state);
		v = (int)((uintmax_t)v * 255u / (uintmax_t)RAND_MAX);
		buf[i] = (unsigned char)v;
	}
	ret += n;
	seed = state;

out:
	errno = saved_errno;
	return (ssize_t)ret;
}


#else


int
main(void)
{
	/* TODO test failure cases */

	unsigned char buf1[1024u];
	unsigned char buf2[sizeof(buf1)];
	ssize_t n1, n2;

	SET_UP_ALARM();

	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	n2 = librecrypt_rng_(buf2, sizeof(buf2), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));

	return 0;
}


#endif
