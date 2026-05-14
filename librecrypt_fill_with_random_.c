/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_fill_with_random_(void *out, size_t n, ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	char *buf = out;
	ssize_t r;

	if (!rng)
		rng = &librecrypt_rng_;

	while (n) {
		r = (*rng)(buf, n, user);
		if (r <= 0) {
			if (!r)
				abort(); /* $covered$ */
			return -1;
		}
		buf = &buf[(size_t)r];
		n -= (size_t)r;
	}

	return 0;
}


#else


static ssize_t
zero(void *out, size_t n, void *user)
{
	(void) user;
	memset(out, 0, n);
	return (ssize_t)n;
}


static ssize_t
seq(void *out, size_t n, void *user)
{
	unsigned char *restrict buf = out;
	unsigned char *restrict num = user;
	size_t i;
	if (n > 64u)
		n = 64u;
	for (i = 0u; i < n; i++)
		buf[i] = (*num)++;
	return (ssize_t)n;
}


static ssize_t
next(void *out, size_t n, void *user)
{
	unsigned char *restrict buf = out;
	unsigned char *restrict num = user;
	assert(n);
	*buf = (*num)++;
	return 1;
}


static ssize_t
failer(void *out, size_t n, void *user)
{
	(void) out;
	(void) n;
	(void) user;
	errno = EDOM;
	return -1;
}


static ssize_t
zero_ret(void *out, size_t n, void *user)
{
	(void) out;
	(void) n;
	(void) user;
	return 0;
}


int
main(void)
{
	unsigned char buf1[1024u];
	unsigned char buf2[sizeof(buf1)];
	unsigned char s;
	size_t i;
	int rv = 0;

	INIT_TEST_ABORT();
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* Check zero-request */
	EXPECT(librecrypt_fill_with_random_(NULL, 0u, NULL, NULL) == 0);

	/* Check default RNG */
	EXPECT(librecrypt_fill_with_random_(buf1, sizeof(buf1), NULL, NULL) == 0);
	EXPECT(librecrypt_fill_with_random_(buf2, sizeof(buf1), NULL, NULL) == 0);
	EXPECT(memcmp(buf1, buf2, sizeof(buf1)));

	/* Check that it is not writing too much */
	CANARY_FILL(buf1);
	CANARY_FILL(buf2);
	EXPECT(librecrypt_fill_with_random_(buf1, sizeof(buf1) / 2u, NULL, NULL) == 0);
	EXPECT(librecrypt_fill_with_random_(buf2, sizeof(buf2) / 2u, NULL, NULL) == 0);
	EXPECT(memcmp(buf1, buf2, sizeof(buf1) / 2u));
	CANARY_CHECK(buf1, sizeof(buf1) / 2u);
	CANARY_CHECK(buf2, sizeof(buf2) / 2u);

	/* Check stateless all-at-once RNG */
	CANARY_FILL(buf1);
	errno = 0;
	EXPECT(librecrypt_fill_with_random_(buf1, sizeof(buf1), &zero, NULL) == 0);
	EXPECT(errno == 0);
	for (s = 0u, i = 0u; i < sizeof(buf1); i++, s++)
		EXPECT(!buf1[i]);

	/* Check stateful chunked RNG (importantly, chunks are smaller than pattern) */
	CANARY_FILL(buf1);
	s = 0u;
	errno = 0;
	EXPECT(librecrypt_fill_with_random_(buf1, sizeof(buf1), &seq, &s) == 0);
	EXPECT(errno == 0);
	for (s = 0u, i = 0u; i < sizeof(buf1); i++, s++)
		EXPECT(buf1[i] == s);

	/* Check stateful one-byte-per-call RNG */
	CANARY_FILL(buf1);
	s = 0u;
	errno = 0;
	EXPECT(librecrypt_fill_with_random_(buf1, sizeof(buf1), &next, &s) == 0);
	EXPECT(errno == 0);
	for (s = 0u, i = 0u; i < sizeof(buf1); i++, s++)
		EXPECT(buf1[i] == s);

	/* Check failure in RNG */
	CANARY_FILL(buf1);
	s = 0u;
	errno = 0;
	EXPECT(librecrypt_fill_with_random_(buf1, sizeof(buf1), &failer, NULL) == -1);
	EXPECT(errno == EDOM);
	CANARY_CHECK(buf1, 0u);

	/* Check function abort(3)s if RNG returns 0 */
	EXPECT_ABORT(rv = librecrypt_fill_with_random_(buf1, sizeof(buf1), &zero_ret, NULL));

	STOP_RESOURCE_TEST();
	return rv;
}


#endif
