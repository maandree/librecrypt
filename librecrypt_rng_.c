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
#ifndef O_CLOFORK
# define O_CLOFORK 0
#endif
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_CLOFORK);
	if (fd < 0)
		goto no_urandom; /* this is a goto to make coverage test more comprehensive */
	/* TODO we should make sure this is a character special device */
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
			/* /dev/urandom cannot be exhausted, your system
			 * has been compromised if this happens */
			/* TODO we should probably warn the user */
			abort();
		}
	}

no_urandom:
	/* Last resort, use non-entropy based RNG */
	/* but try to use a good seed */
	state = seed;
	if (state)
		goto have_initial_seed;
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


static size_t open_calls = 0u;
static int open_error = 0;

int
(open)(const char *path, int flags, ...)
{
	mode_t mode = 0;

	open_calls += 1u;

	if (open_error) {
		errno = open_error;
		if (open_error == EINTR)
			open_error = 0;
		return -1;
	}

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list args;
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	return openat(AT_FDCWD, path, flags, mode);
}


static volatile size_t beyond_ssize_max = (size_t)SSIZE_MAX + 1u;

static void
test_oversized(void)
{
	volatile int jumped = 0;
	char *buf;

	buf = mmap(NULL, 1u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(buf != MAP_FAILED);
	assert(buf != NULL);
	buf[0] = 99;

	libtest_getentropy_jmp_val = 1;
	if (!setjmp(libtest_getentropy_jmp)) {
		EXPECT(librecrypt_rng_(buf, beyond_ssize_max, NULL) == 9999);
	} else {
		jumped = 1;
	}
	EXPECT(jumped);

	EXPECT(buf[0] == 99);
	assert(!munmap(buf, 1u));
}


int
main(void)
{
	/* TODO test failure cases */

	unsigned char buf1[1024u];
	unsigned char buf2[sizeof(buf1)];
	ssize_t n1, n2;
	void *user = NULL;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	open_calls = 0u;

	/* TODO Test with output pattern (useful for other tests) */

	/* Check that output is random */
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	n2 = librecrypt_rng_(buf2, sizeof(buf2), &user);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));

#if defined(__linux__)
	libtest_getentropy_calls = 0u;

	/* Check with short getrandom(3) */
	errno = 0;
	libtest_getrandom_max_return = 1u;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	libtest_getrandom_max_return = SIZE_MAX;
	EXPECT(libtest_getentropy_calls == 0u);
	EXPECT(errno == 0);

	/* Check with getrandom(3) with EINTR */
	errno = 0;
	libtest_getrandom_error = EINTR;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(!libtest_getrandom_error);
	EXPECT(libtest_getentropy_calls == 0u);
	EXPECT(errno == EINTR);

	/* Check with getrandom(3) with ENOSYS */
	errno = 0;
	libtest_getrandom_error = ENOSYS;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(libtest_getrandom_error == ENOSYS);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);

	/* Check with getrandom(3) other error */
	errno = 0;
	libtest_getrandom_error = EDOM;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(libtest_getrandom_error == EDOM);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	libtest_getrandom_error = 0;
	EXPECT(errno == 0);

	/* Check with getrandom(3) zero return */
	errno = 0;
	libtest_getrandom_max_return = 0u;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	libtest_getrandom_max_return = SIZE_MAX;
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);

	/* Don't use getrandom(3) for reminder of the test */
	libtest_getrandom_error = ENOSYS;
#endif

	/* Check with getentropy(3) with EINTR */
	errno = 0;
	libtest_getentropy_error = EINTR;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(!libtest_getentropy_error);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == EINTR);

	/* Check with getentropy(3) with ENOSYS */
	errno = 0;
	libtest_getentropy_error = ENOSYS;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(libtest_getentropy_error == ENOSYS);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);

	/* Check with getentropy(3) other error */
	errno = 0;
	libtest_getentropy_error = EDOM;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(libtest_getentropy_error == EDOM);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	libtest_getentropy_error = 0;
	EXPECT(errno == 0);

	/* Check with getentropy(3) */
	assert(open_calls > 0u);
	open_calls = 0u;
	errno = 0;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	n2 = librecrypt_rng_(buf2, sizeof(buf2), &user);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);
	libtest_getentropy_real = 1;
	EXPECT(open_calls == 0u);

	/* TODO Check with getentropy(3) with small buffer */

	/* Don't use getentropy(3) for reminder of the test */
	libtest_getentropy_error = ENOSYS;

	/* Check with urandom(4) */
	errno = 0;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	n2 = librecrypt_rng_(buf2, sizeof(buf2), &user);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	EXPECT(errno == 0);
	/* TODO check that rand(3) was not called */

	/* Check with urandom(4) not available */
	open_calls = 0;
	open_error = ENOENT;
	n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);
	n2 = librecrypt_rng_(buf2, sizeof(buf2), &user);
	EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));
	EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));
	assert(open_error == ENOENT);
	open_error = 0;
	EXPECT(open_calls > 0u);

	/* TODO Check with urandom(4) read(3) EINTR */
	/* TODO Check with urandom(4) read(3) EIO */
	/* TODO Check with urandom(4) read(3) exhaustion */

	/* Don't use urandom(4) for reminder of the test */
	open_error = ENOENT;

	/* TODO Check with rand(3) */
	/* TODO Check with mmap(3) failure */
	/* TODO Check with clock_gettime(3) failure */

	/* Check zero-request */
	errno = 0;
	EXPECT(librecrypt_rng_(NULL, 0u, NULL) == 0u);
	EXPECT(errno == 0);

	test_oversized();

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
