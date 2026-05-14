/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_make_settings(char *out_buffer, size_t size, const char *algorithm, size_t memcost, uintmax_t timecost,
                         int gensalt, ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	const struct algorithm *algo;

	/* Get algorithm */
	if (!algorithm) {
		/* Select best algorithm if `NULL` is specified */
		algo = &librecrypt_algorithms_[0];
		if (IS_END_OF_ALGORITHMS(algo))
			goto enosys; /* $covered$ (covered iff reachable: when algorithms are disabled) */
	} else {
		/* Verify single, unchained algorithm is specified if not `NULL`*/
		if (strchr(algorithm, LIBRECRYPT_ALGORITHM_LINK_DELIMITER)) {
			errno = EINVAL;
			return -1;
		}
		/* Identify the algorithm */
		algo = librecrypt_find_first_algorithm_(algorithm, strlen(algorithm));
		if (!algo)
			goto enosys;
	}

	/* Use default random number generator if none was specified */
	if (!rng)
		rng = &librecrypt_rng_;

	/* Configure */
	return (*algo->make_settings)(out_buffer, size, algorithm, memcost, timecost, gensalt, rng, user);

enosys:
	errno = ENOSYS;
	return -1;
}


#else


static unsigned char saltbyte = 0u;


static ssize_t
saltgen(void *out, size_t n, void *user)
{
	if (!n)
		return 0;
	*(unsigned char *)out = *(unsigned char *)user;
	return 1;
}


static ssize_t
saltfail(void *out, size_t n, void *user)
{
	(void) out;
	(void) n;
	(void) user;
	errno = EDOM;
	return -1;
}


int
main(void)
{
	char buf[1024];
	char buf2[sizeof(buf)];
	int any_supported = 0;
	int any_salted = 0;
	ssize_t r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, ">", 0u, 0u, 0, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, "$argon2id$>", 0u, 0u, 0, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, ">$argon2id$", 0u, 0u, 0, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, "$argon2id$>$argon2id$", 0u, 0u, 0, NULL, NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_make_settings(NULL, 0u, "$~no~such~algorithm~$", 0u, 0u, 0, NULL, NULL) == -1);
	EXPECT(errno == ENOSYS);

#if defined(SUPPORT_ARGON2I)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2i$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2i$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

#if defined(SUPPORT_ARGON2D)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2d$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2d$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

#if defined(SUPPORT_ARGON2ID)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2id$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2id$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

#if defined(SUPPORT_ARGON2DS)
	saltbyte = 0u;
	CANARY_FILL(buf);
	r = librecrypt_make_settings(buf, sizeof(buf), "$argon2ds$", 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strcmp(buf, "$argon2ds$v=19$m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	CANARY_CHECK(buf, (size_t)r + 1u);
	any_supported = 1;
	any_salted = 1;
#endif

	if (any_supported) {
		EXPECT(librecrypt_make_settings(NULL, 0u, NULL, 0u, 0u, 0, NULL, NULL) > 0);
		EXPECT(librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 0, NULL, NULL) > 0);

		if (any_salted) {
			errno = 0;
			EXPECT(librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 1, &saltfail, NULL) == -1);
			EXPECT(errno == EDOM);
		} else {
			EXPECT(librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 1, &saltfail, NULL) > 0);
		}

		CANARY_FILL(buf);
		CANARY_FILL(buf2);
		r = librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 0, &saltfail, NULL);
		EXPECT(r > 0 && (size_t)r < sizeof(buf));
		EXPECT(!buf[r] && (size_t)r == strlen(buf));
		EXPECT(librecrypt_make_settings(buf2, sizeof(buf2), NULL, 0u, 0u, 0, &saltfail, NULL) == r);
		EXPECT(!buf2[r] && (size_t)r == strlen(buf2));
		EXPECT(!strcmp(buf, buf2));
		CANARY_CHECK(buf, (size_t)r + 1u);
		CANARY_CHECK(buf2, (size_t)r + 1u);

		CANARY_FILL(buf);
		CANARY_FILL(buf2);
		r = librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 0, NULL, NULL);
		EXPECT(r > 0 && (size_t)r < sizeof(buf));
		EXPECT(!buf[r] && (size_t)r == strlen(buf));
		EXPECT(librecrypt_make_settings(buf2, sizeof(buf2), NULL, 0u, 0u, 0, NULL, NULL) == r);
		EXPECT(!buf2[r] && (size_t)r == strlen(buf2));
		EXPECT(!strcmp(buf, buf2));
		CANARY_CHECK(buf, (size_t)r + 1u);
		CANARY_CHECK(buf2, (size_t)r + 1u);

		CANARY_FILL(buf);
		CANARY_FILL(buf2);
		r = librecrypt_make_settings(buf, sizeof(buf), NULL, 0u, 0u, 1, NULL, NULL);
		EXPECT(r > 0 && (size_t)r < sizeof(buf));
		EXPECT(!buf[r] && (size_t)r == strlen(buf));
		EXPECT(librecrypt_make_settings(buf2, sizeof(buf2), NULL, 0u, 0u, 1, NULL, NULL) == r);
		EXPECT(!buf2[r] && (size_t)r == strlen(buf2));
		EXPECT(strcmp(buf, buf2));
		CANARY_CHECK(buf, (size_t)r + 1u);
		CANARY_CHECK(buf2, (size_t)r + 1u);
	} else {
		errno = 0;
		EXPECT(librecrypt_make_settings(NULL, 0u, NULL, 0u, 0u, 0, NULL, NULL) == -1);
		EXPECT(errno == ENOSYS);
	}

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
