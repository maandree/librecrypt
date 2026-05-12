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
			abort(); /* $covered$ */
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
	if (random_ptr == MAP_FAILED) {
		random_ptr = malloc(1u); /* NULL is OK (MAP_FAILED was actually also OK) */
		random_addr = (uintptr_t)random_ptr;
		state ^= (unsigned int)random_addr;
		free(random_ptr);
	} else {
		random_addr = (uintptr_t)random_ptr;
		state ^= (unsigned int)random_addr;
		munmap(random_ptr, 1u);
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


static size_t open_calls = 0u;
static int open_error = 0;

int
(open)(const char *path, int flags, ...)
{
	mode_t mode = 0;
	va_list args;

	open_calls += 1u;

	if (open_error) {
		errno = open_error;
		if (open_error == EINTR)
			open_error = 0;
		return -1;
	}

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	return openat(AT_FDCWD, path, flags, mode);
}


static int read_error = 0;
static size_t read_max_return = SIZE_MAX;

ssize_t
(read)(int fd, void *buf, size_t n)
{
	struct iovec iov;

	if (n > read_max_return)
		n = read_max_return;

	if (read_error) {
		errno = read_error;
		if (read_error == EINTR)
			read_error = 0;
		return -1;
	}

	iov.iov_base = buf;
	iov.iov_len = n;
	return readv(fd, &iov, 1);
}


static int clock_gettime_error = 0;

int
(clock_gettime)(clockid_t clockid, struct timespec *tp)
{
	(void) clockid;

	if (clock_gettime_error) {
		errno = clock_gettime_error;
		return -1;
	}

	memset(tp, 0, sizeof(*tp));
	return 0;
}


#if defined(__linux__) && defined(AT_RANDOM)
static int getauxval_error = 0;

unsigned long
(getauxval)(unsigned long type)
{
	/* We don't want to read from after the first NULL
	 * in the environment variable list provided by the
	 * kernel, because (1) this function may be executed
	 * before `main` so we cannot copy the auxiliary
	 * vector in `main` and use that, (2) if this function
	 * is executed before `main`, we don't know if
	 * environ(3) has been set up by libc, and (3) we
	 * cannot know if environ(3) is it's original pointer
	 * without addition elements when this function is
	 * executed. Therefore we use /proc/self/auxv instead. */

	size_t saved_open_calls = open_calls;
	int saved_open_error = open_error;
	int saved_read_error = read_error;
	size_t saved_read_max_return = read_max_return;
	size_t *aux;
	unsigned char buf[2u * sizeof(*aux)];
	size_t off;
	ssize_t r;
	int fd;
	unsigned long ret = 0u;

	if (getauxval_error) {
		errno = getauxval_error;
		return 0;
	}

	open_error = 0;
	read_error = 0;
	read_max_return = SIZE_MAX;

	fd = open("/proc/self/auxv", O_RDONLY);

	if (fd < 0) {
		errno = ENOENT;
		goto out;
	}

	aux = (unsigned long *)buf;
	for (off = 0u;;) {
		r = read(fd, &buf[off], sizeof(buf) - off);
		if (r <= 0) {
			if (r && errno == EINTR)
				continue;
			errno = ENOENT;
			goto out_close;
		}
		off += (size_t)r;
		if (off < sizeof(buf))
			continue;
		off = 0u;
		if (aux[0] == type)
			break;
	}

	ret = aux[1];
out_close:
	close(fd);
out:
	open_calls = saved_open_calls;
	open_error = saved_open_error;	
	read_error = saved_read_error;
	read_max_return = saved_read_max_return;
	return ret;
}
#endif


static size_t rand_r_calls = 0u;
static int rand_r_clean_seed = 0;

int
(rand_r)(unsigned int *seedp)
{
	int ret;

	rand_r_calls += 1u;

	if (*seedp)
		srand(*seedp);
	ret = rand();

	*seedp = (unsigned int)ret;
	if (rand_r_clean_seed)
		*seedp = 0u;

	return ret;
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
	unsigned char buf1[1024u];
	unsigned char buf2[sizeof(buf1)];
	ssize_t n1, n2;
	void *user = NULL;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	open_calls = 0u;

#define CHECK1()\
	do {\
		n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);\
		EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));\
		EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));\
	} while (0)

#define CHECK2()\
	do {\
		n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL);\
		n2 = librecrypt_rng_(buf2, sizeof(buf2), &user);\
		EXPECT(n1 >= 128 && (size_t)n1 <= sizeof(buf1));\
		EXPECT(n2 >= 128 && (size_t)n2 <= sizeof(buf2));\
		EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));\
	} while (0)

	/* TODO Test with output pattern (useful for other tests) */

	/* Check that output is random */
	CHECK2();

#if defined(__linux__)
	libtest_getentropy_calls = 0u;

	/* Check with short getrandom(3) */
	errno = 0;
	libtest_getrandom_max_return = 1u;
	CHECK1();
	libtest_getrandom_max_return = SIZE_MAX;
	EXPECT(libtest_getentropy_calls == 0u);
	EXPECT(errno == 0);

	/* Check with getrandom(3) with EINTR */
	errno = 0;
	libtest_getrandom_error = EINTR;
	CHECK1();
	assert(!libtest_getrandom_error);
	EXPECT(libtest_getentropy_calls == 0u);
	EXPECT(errno == EINTR);

	/* Check with getrandom(3) with ENOSYS */
	errno = 0;
	libtest_getrandom_error = ENOSYS;
	CHECK1();
	assert(libtest_getrandom_error == ENOSYS);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);

	/* Check with getrandom(3) other error */
	errno = 0;
	libtest_getrandom_error = EDOM;
	CHECK1();
	assert(libtest_getrandom_error == EDOM);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	libtest_getrandom_error = 0;
	EXPECT(errno == 0);

	/* Check with getrandom(3) zero return */
	errno = 0;
	libtest_getrandom_max_return = 0u;
	CHECK1();
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
	CHECK1();
	assert(!libtest_getentropy_error);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == EINTR);

	/* Check with getentropy(3) with ENOSYS */
	errno = 0;
	libtest_getentropy_error = ENOSYS;
	CHECK1();
	assert(libtest_getentropy_error == ENOSYS);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);

	/* Check with getentropy(3) other error */
	errno = 0;
	libtest_getentropy_error = EDOM;
	CHECK1();
	assert(libtest_getentropy_error == EDOM);
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	libtest_getentropy_error = 0;
	EXPECT(errno == 0);

	/* Check with getentropy(3) */
	assert(open_calls > 0u);
	open_calls = 0u;
	errno = 0;
	CHECK2();
	EXPECT(libtest_getentropy_calls > 0u);
	libtest_getentropy_calls = 0u;
	EXPECT(errno == 0);
	libtest_getentropy_real = 1;
	EXPECT(open_calls == 0u);

	/* Check with getentropy(3) with small buffer */
	n1 = librecrypt_rng_(buf1, 64u, NULL);
	EXPECT(n1 == 64u);
	EXPECT(memcmp(buf1, buf2, (size_t)(n1 < n2 ? n1 : n2)));

	/* Don't use getentropy(3) for reminder of the test */
	libtest_getentropy_error = ENOSYS;

	/* Check with urandom(4) */
	rand_r_calls = 0;
	errno = 0;
	CHECK2();
	EXPECT(errno == 0);
	EXPECT(rand_r_calls == 0u);

	/* Check with urandom(4) not available */
	open_calls = 0;
	open_error = ENOENT;
	CHECK2();
	assert(open_error == ENOENT);
	open_error = 0;
	EXPECT(open_calls > 0u);

	/* Check with urandom(4) read(3) failure */
	read_error = EBADF;
	errno = 0;
	CHECK1();
	EXPECT(errno == 0);
	assert(read_error == EBADF);
	read_error = 0;

	/* Check with urandom(4) read(3) EINTR */
	read_error = EINTR;
	errno = 0;
	CHECK1();
	EXPECT(errno == EINTR);
	assert(read_error == 0);

	/* Check with urandom(4) short read(3) */
	read_max_return = 1u;
	CHECK1();
	assert(read_max_return == 1u);
	read_max_return = SIZE_MAX;

	/* Check with urandom(4) read(3) exhaustion */
	read_max_return = 0u;
	EXPECT_ABORT(n1 = librecrypt_rng_(buf1, sizeof(buf1), NULL));
	read_max_return = SIZE_MAX;

	/* Don't use urandom(4) for reminder of the test */
	open_error = ENOENT;

	rand_r_clean_seed = 1;

	/* Check with rand(3) */
	rand_r_calls = 0u;
	errno = 0;
	CHECK2();
	EXPECT(errno == 0);
	assert(rand_r_calls > 0u);

#if defined(__linux__) && defined(AT_RANDOM)
	getauxval_error = ENOENT;

	/* Check with getauxval(3) failure */
	assert(getauxval(AT_RANDOM) == 0u);
	assert(getauxval_error == ENOENT);
	errno = 0;
	CHECK1();
	EXPECT(errno == 0);
#endif

	/* Check with mmap(3) failure */
	if (libtest_have_custom_mmap()) {
		libtest_set_alloc_failure_in(1u);
		errno = 0;
		CHECK1();
		EXPECT(errno == 0);
		assert(libtest_get_alloc_failure_in() == 0u);
	}

#if defined(__linux__) && defined(AT_RANDOM)
	getauxval_error = 0;
#endif

	/* Check with clock_gettime(3) failure */
	clock_gettime_error = EDOM;
	errno = 0;
	CHECK1();
	EXPECT(errno == 0);
	EXPECT(clock_gettime_error == EDOM);
	clock_gettime_error = 0;

	assert(rand_r_clean_seed == 1);
	rand_r_clean_seed = 0;

	/* Check zero-request */
	errno = 0;
	EXPECT(librecrypt_rng_(NULL, 0u, NULL) == 0u);
	EXPECT(errno == 0);

	test_oversized();

	/* So that gcov can report coverage */
	open_error = 0;

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
