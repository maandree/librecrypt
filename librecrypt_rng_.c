/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_rng_(void *out, size_t n, void *user)
{
	static volatile unsigned int seed = 0u;
	unsigned char *buf = out;
	int v, fd, saved_errno = errno;
	unsigned int state;
	size_t i, min, ret = 0u;
	ssize_t r;
	struct timespec ts;
#if defined(__linux__) && defined(AT_RANDOM)
	const unsigned char *at_random;
#endif
	void *random_ptr;
	uintptr_t random_addr;

	(void) user;

	/* Done if nothing was requested */
	if (!n)
		return 0;

	/* Make sure we don't return more than in range for the return value */
	if (n > (size_t)SSIZE_MAX)
		n = (size_t)SSIZE_MAX;

	/* Use Linux's system call version of /dev/urandom */
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

	/* Use getentropy(3posix) */
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

	/* Use /dev/urandom if available */
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

	/* Last restort, use non-entropy based RNG */
	/* but try to use a good seed */
	state = seed;
	if (!state) {
		/* Hopefully the application has already called srand(3) */
		state = (unsigned int)rand();
#if defined(__linux__) && defined(AT_RANDOM)
		/* Otherwise can we use random data the kernel gave to the process */
		random_addr = (uintptr_t)getauxval(AT_RANDOM);
		if (random_addr) {
			at_random = (const void *)random_addr;
			for (i = 0u; i < 16u; i++)
				state ^= (unsigned int)at_random[i] << (i % sizeof(unsigned int) * 8u);
			goto have_initial_seed;
		}
#endif
#ifndef MAP_UNINITIALIZED
# define MAP_UNINITIALIZED 0
#endif
		/* But where that is not supported, we can hopefully
		 * get a random address: here mmap(2) is much better than
		 * malloc(3), as malloc(3) may be less random when the
		 * allocation is small, and we don't want to make a big
		 * allocation. A few bit's are always 0, but that's not
		 * a big deal. */
		random_ptr = mmap(NULL, 1u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
		if (random_ptr != MAP_FAILED) {
			random_addr = (uintptr_t)random_ptr;
			state ^= (unsigned int)random_addr;
			munmap(random_ptr, 1u);
			goto have_initial_seed; /* just using goto to simplify the #if'ing */
		}
		random_ptr = malloc(1u); /* NULL is OK (MAP_FAILED was actually also OK) */
		random_addr = (uintptr_t)random_ptr;
		state ^= (unsigned int)random_addr;
		free(random_ptr);
	}
have_initial_seed:
	/* and always do a time-based reseed in case of multithreading,
	 * so multiple passwords don't end up using the same salt */
	if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
		state ^= (unsigned int)ts.tv_sec;
		state ^= (unsigned int)ts.tv_nsec;
	} else {
		state ^= (unsigned int)time(NULL);
	}
	/* rand(3) is good enough on modern systems: all bits are equality random */
	for (i = 0u; i < n; i++) {
		v = rand_r(&state);
		v = (int)((uintmax_t)v * 255u / (uintmax_t)RAND_MAX);
		buf[i] = (unsigned char)v;
	}
	ret += n;
	/* Of course we have to save the RNG state so next run
	 * depends both of the this run and the time */
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
	void *user = NULL;

	SET_UP_ALARM();

	/* Check that output is random */
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	n2 = librecrypt_rng_(buf2, sizeof(buf2), &user);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));

	/* Check zero-request */
	EXPECT(librecrypt_rng_(NULL, 0u, NULL) == 0u);

	return 0;
}


#endif
