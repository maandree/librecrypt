/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


int
librecrypt_verify(const char *phrase, size_t len, const char *settings, void *reserved)
{
	char *hash = NULL;
	size_t size = 0u;
	size_t off;
	ssize_t n;
	int ret, err;

	/* Measure base64 hash size */
	n = librecrypt_hash_(NULL, 0u, phrase, len, settings, reserved, ASCII_HASH);
	if (n < 0) {
		if (errno == EOVERFLOW)
			errno = ENOMEM; /* $covered$ (on 32-bit) */
		return -1;
	}

	/* Get position of hash in `settings` */
	off = librecrypt_settings_prefix(settings, NULL, reserved);
	if (settings[off] == '*') {
		if ('0' <= settings[off + 1u] && settings[off + 1u] <= '9') {
			errno = EINVAL;
			return -1;
		}
	} else if (!settings[off]) {
		errno = EINVAL;
		return -1;
	}

	/* Allocate hash output buffer for comparsion */
	size = (size_t)n + 128u; /* a little extra so the hasher don't need to allocate output scratch */
	hash = malloc(size);
	if (!hash)
		return -1;

	/* Calculate password hash and encode to base64 */
	n = librecrypt_hash_(hash, size, phrase, len, settings, reserved, ASCII_HASH);
	if (n < 0) {
		err = errno;
		librecrypt_wipe(hash, size);
		free(hash);
		if (err == EOVERFLOW)
			err = ENOMEM; /* $covered$ (impossible) */
		errno = err;
		return -1;
	}
	if ((size_t)n > size)
		abort(); /* $covered$ (impossible) */

	/* Compare hash */
	ret = librecrypt_equal(hash, &settings[off]);

	librecrypt_wipe(hash, size);
	free(hash);
	return ret;
}


#else


int
main(void)
{
	char conf[256];
	int r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_verify(NULL, 0u, "$~no~such~algorithm~$", NULL) == -1);
	EXPECT(errno == ENOSYS);

#if defined(SUPPORT_ARGON2ID)
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL) == 1);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/", NULL) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4x", NULL) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/a", NULL) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$a29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/a", NULL) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$af65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL) == 0);
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMRauIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL) == 0);

	errno = 0;
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$", NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$*64", NULL) == -1);
	EXPECT(errno == EINVAL);
	errno = 0;
	EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$*16$nf65EOgLrQMRauIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL) == -1);
	EXPECT(errno == EINVAL);

	if (libtest_have_custom_malloc()) {
		libtest_set_alloc_failure_in(1u);
		errno = 0;
		EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL) == -1);
		assert(errno == ENOMEM);
		assert(libtest_get_alloc_failure_in() == 0u);

		libtest_set_alloc_failure_in(2u);
		errno = 0;
		EXPECT(librecrypt_verify("password", 8u, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", NULL) == -1);
		assert(errno == ENOMEM);
		assert(libtest_get_alloc_failure_in() == 0u);
	}

        r = snprintf(conf, sizeof(conf), "$argon2id$m=256,t=8,p=1$AAAABBBBCCCC$*%zu", SIZE_MAX / 4u * 3u + 3u);
        assert(r > 0 && (size_t)r < sizeof(conf));
        errno = 0;
	EXPECT(librecrypt_verify(NULL, 0u, conf, NULL) == -1);
# if SIZE_MAX > UINT32_MAX
        EXPECT(errno == EINVAL);
# else
        EXPECT(errno == EOVERFLOW);
# endif
#endif

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
