/* See LICENSE file for copyright and license details. */
#include "../common.h"
#include <libar2.h>
#ifndef TEST


static ssize_t
make_settings(char *out_buffer, size_t size, const char *algorithm, size_t memcost, uintmax_t timecost,
              int gensalt, ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	const char *p, *version = "19";
	size_t algolen, ret, min, len, i;
	int r;

	/* Use default RNG if NULL is specified */
	if (!rng)
		rng = &librecrypt_rng_;

	/* Adjust `memcost` for algorithm */
	if (!memcost) {
		/* Use default memcost if 0 was specified */
		memcost = (size_t)4096u; /* 4 MiB */
	} else {
		/* Function takes bytes as memcost, algorithm takes kilobytes */
		size_t memcost_round_up = (memcost >> 9) & 1u;
		memcost >>= 10;
		memcost += memcost_round_up;
	}
	memcost = memcost < LIBAR2_MIN_M_COST ? LIBAR2_MIN_M_COST : memcost;
	memcost = memcost > LIBAR2_MAX_M_COST ? LIBAR2_MAX_M_COST : memcost;

	/* Adjust `timecost` for algorithm */
	if (!timecost) {
		/* Use default timecost if 0 was specified:
		 * default m_cost (4096) multiple by default t_cost (10) */
		timecost = 40960u;
	}
	timecost /= memcost;
	timecost = timecost < LIBAR2_MIN_T_COST ? LIBAR2_MIN_T_COST : timecost;
	timecost = timecost > LIBAR2_MAX_T_COST ? LIBAR2_MAX_T_COST : timecost;

	/* Get version */
	p = algorithm;
	if (*p++ != '$')
		abort(); /* $covered$ */
	p = strchr(p, '$');
	algolen = p ? (size_t)(p - algorithm) : strlen(algorithm);
	if (algolen > 32u) /* just some small value absolute will fit all variants */
		abort(); /* $covered$ */
	if (p++ && *p++ == 'v') {
		if (!strncmp(p, "=16", 3u) && (!p[3u] || p[3u] == '$'))
			version = "16";
		else if (!strncmp(p, "=19", 3u) && (!p[3u] || p[3u] == '$'))
			version = "19";
		else
			goto enosys;
	}

	/* Write algorithm and parameters */
	r = snprintf(out_buffer, size, "%.*s$v=%s$m=%zu,t=%llu,p=1$",
	             (int)algolen, algorithm, version,
	             memcost, (unsigned long long int)timecost);
	if (r < (int)sizeof("$argon2_$v=__$m=_,t=_,p=1$") - 1)
		abort(); /* $covered$ (impossible) */
	ret = (size_t)r;
	min = size ? ret < size - 1u ? ret : size - 1u : 0u;
	out_buffer = &out_buffer[min];
	size -= min;

	/* Add 16 bytes of salt */
	if (gensalt) {
		/* 16 bytes is 128 bits, and 128 = 21*6+2, so that is
		 * 21 full base-64 characeters and 1 that only use 2 bits */
		ret += len = 22u;
		min = size ? len < size - 1u ? len : size - 1u : 0u;
		if (librecrypt_fill_with_random_(out_buffer, min, rng, user))
			return -1;
		if (min == len)
			out_buffer[len - 1u] = (char)((unsigned char)out_buffer[len - 1u] & ~15u);
		for (i = 0u; i < min; i++)
			out_buffer[i] = librecrypt_common_rfc4848s4_encoding_lut_[((unsigned char *)out_buffer)[i]];
	} else {
		ret += len = sizeof("*16") - 1u;
		min = size ? len < size - 1u ? len : size - 1u : 0u;
		memcpy(out_buffer, "*16", min);
	}
	out_buffer = &out_buffer[min];
	size -= min;

	/* Add tag size (size of hash result) */
	ret += len = sizeof("$*32") - 1u;
	min = size ? len < size - 1u ? len : size - 1u : 0u;
	memcpy(out_buffer, "$*32", min);
	out_buffer = &out_buffer[min];
	size -= min;

	/* NUL terminate */
	if (size) {
		/* We were careful to make sure size is positive at
		 * the end if it was when the function was called */
		*out_buffer = '\0';
	}

	return (ssize_t)ret;

enosys:
	errno = ENOSYS;
	return -1;
}


#define DECLARE_MAKE_SETTINGS(ALGO)\
	ssize_t\
	librecrypt__##ALGO##__make_settings(char *out_buffer, size_t size, const char *algorithm,\
	                                    size_t memcost, uintmax_t timecost, int gensalt,\
	                                    ssize_t (*rng)(void *out, size_t n, void *user), void *user)\
	{\
		algorithm = algorithm ? algorithm : "$"#ALGO"$";\
		return make_settings(out_buffer, size, algorithm, memcost, timecost, gensalt, rng, user);\
	}

IF__argon2i__SUPPORTED(DECLARE_MAKE_SETTINGS(argon2i))
IF__argon2d__SUPPORTED(DECLARE_MAKE_SETTINGS(argon2d))
IF__argon2id__SUPPORTED(DECLARE_MAKE_SETTINGS(argon2id))
IF__argon2ds__SUPPORTED(DECLARE_MAKE_SETTINGS(argon2ds))


#else


static unsigned char saltbyte = 0u;
static ssize_t discarded_ssize;


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


static void
check(ssize_t (*gen)(char *, size_t, const char *, size_t, uintmax_t,
                     int , ssize_t (*)(void *, size_t, void *), void *),
      const char *algo_out, const char *algo_in)
{
	uintmax_t v, d;
	char buf[1024];
	char buf2[sizeof(buf)];
	size_t off, i;
	ssize_t r;

	if (!algo_out) {
		errno = 0;
		EXPECT((*gen)(buf, sizeof(buf), algo_in, 0u, 0u, 0, &saltgen, &saltbyte) == -1);
		EXPECT(errno == ENOSYS);
		return;
	}

	off = strlen(algo_out);

	r = (*gen)(buf, sizeof(buf), algo_in, 0u, 0u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=4096,t=10,p=1$*16$*32"));
	assert(LIBAR2_MIN_SALTLEN <= 16u && 16u <= LIBAR2_MAX_SALTLEN);
	assert(LIBAR2_MIN_HASHLEN <= 32u && 32u <= LIBAR2_MAX_HASHLEN);

	EXPECT((*gen)(NULL, 0u, algo_in, 0u, 0u, 0, &saltgen, &saltbyte) == r);
	for (i = 1u; i <= (size_t)r; i++) {
		EXPECT((*gen)(buf2, i, algo_in, 0u, 0u, 0, &saltgen, &saltbyte) == r);
		EXPECT(!buf2[i - 1u]);
		EXPECT(!memcmp(buf2, buf, i - 1u));
	}

	r = (*gen)(buf, sizeof(buf), algo_in, 8192u << 10, 0u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=8192,t=5,p=1$*16$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, 8192u << 10, (uintmax_t)81920u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=8192,t=10,p=1$*16$*32"));

	saltbyte = 0u;
	r = (*gen)(buf, sizeof(buf), algo_in, 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));

	EXPECT((*gen)(buf, sizeof(buf), algo_in, 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte) == r);
	for (i = 1u; i <= (size_t)r; i++) {
		EXPECT((*gen)(buf2, i, algo_in, 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte) == r);
		EXPECT(!buf2[i - 1u]);
		EXPECT(!memcmp(buf2, buf, i - 1u));
	}

	r = (*gen)(buf, sizeof(buf), algo_in, 8192u << 10, (uintmax_t)81920u, 1, NULL, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(strcmp(&buf[off], "m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));
	memcpy(buf2, buf, (size_t)r);
	memset(&buf[off + sizeof("m=8192,t=10,p=1$") - 1u], 'A', 22u);
	EXPECT(!strcmp(&buf[off], "m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));

	EXPECT((*gen)(buf, sizeof(buf), algo_in, 8192u << 10, (uintmax_t)81920u, 1, NULL, &saltbyte) == r);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(memcmp(buf, buf2, (size_t)r));
	memset(&buf[off + sizeof("m=8192,t=10,p=1$") - 1u], 'A', 22u);
	EXPECT(!strcmp(&buf[off], "m=8192,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$*32"));

	saltbyte = 255u;
	r = (*gen)(buf, sizeof(buf), algo_in, 8192u << 10, (uintmax_t)81920u, 1, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=8192,t=10,p=1$/////////////////////w$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, 0u, (uintmax_t)81920u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=4096,t=20,p=1$*16$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, 1u, 1u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=8,t=1,p=1$*16$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, 1u, 1u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=8,t=1,p=1$*16$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, (10u << 10) + 512u, 1u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=11,t=1,p=1$*16$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, (10u << 10) + 511u, 1u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strcmp(&buf[off], "m=10,t=1,p=1$*16$*32"));

	r = (*gen)(buf, sizeof(buf), algo_in, SIZE_MAX, 1u, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strncmp(&buf[off], "m=", sizeof("m=") - 1u));
	i = off + sizeof("m=") - 1u;
	EXPECT('0' <= buf[i] && buf[i] <= '9');
	for (v = 0; buf[i] != ','; i++) {
		EXPECT('0' <= buf[i] && buf[i] <= '9');
		d = (uintmax_t)(buf[i] - '0');
		EXPECT(v <= (UINTMAX_MAX - d) / 10u);
		v = v * 10u + d;
	}
	EXPECT(v <= (uintmax_t)LIBAR2_MAX_M_COST);

	r = (*gen)(buf, sizeof(buf), algo_in, 1u, UINTMAX_MAX, 0, &saltgen, &saltbyte);
	EXPECT(r > 0 && (size_t)r < sizeof(buf));
	EXPECT(!buf[r] && (size_t)r == strlen(buf));
	EXPECT(!strncmp(buf, algo_out, off));
	EXPECT(!strncmp(&buf[off], "m=8,t=", sizeof("m=8,t=") - 1u));
	i = off + sizeof("m=8,t=") - 1u;
	EXPECT('0' <= buf[i] && buf[i] <= '9');
	for (v = 0; buf[i] != ','; i++) {
		EXPECT('0' <= buf[i] && buf[i] <= '9');
		d = (uintmax_t)(buf[i] - '0');
		EXPECT(v <= (UINTMAX_MAX - d) / 10u);
		v = v * 10u + d;
	}
	EXPECT(v <= (uintmax_t)LIBAR2_MAX_T_COST);

	errno = 0;
	EXPECT((*gen)(buf, sizeof(buf), algo_in, 0u, 0u, 1, &saltfail, NULL) == -1);
	EXPECT(errno == EDOM);
}


static void
check_aborts(ssize_t (*gen)(char *, size_t, const char *, size_t, uintmax_t,
                            int , ssize_t (*)(void *, size_t, void *), void *))
{
#define SHORTTEXT "------------------------------------------------------------------------"
#define LONGTEXT SHORTTEXT SHORTTEXT SHORTTEXT SHORTTEXT SHORTTEXT SHORTTEXT SHORTTEXT
	EXPECT_ABORT(discarded_ssize = (*gen)(NULL, 0u, "argon2i$", 0u, 0u, 0, NULL, NULL));
	EXPECT_ABORT(discarded_ssize = (*gen)(NULL, 0u, "$argon2"LONGTEXT"$", 0u, 0u, 0, NULL, NULL));
}


#define CHECK(FUNC, ALGO)\
	do {\
		check(&(FUNC), "$"ALGO"$v=19$", NULL);\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$");\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO);\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$m=100,t=10,p=2$xxxx$*32");\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$m=100,t=10,p=2$*40$");\
		check(&(FUNC), "$"ALGO"$v=16$", "$"ALGO"$v=16");\
		check(&(FUNC), "$"ALGO"$v=16$", "$"ALGO"$v=16$");\
		check(&(FUNC), "$"ALGO"$v=16$", "$"ALGO"$v=16$m=100,t=10,p=2$xxxx$*32");\
		check(&(FUNC), "$"ALGO"$v=16$", "$"ALGO"$v=16$m=100,t=10,p=2$*40$");\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$v=19");\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$v=19$");\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$v=19$m=100,t=10,p=2$xxxx$*32");\
		check(&(FUNC), "$"ALGO"$v=19$", "$"ALGO"$v=19$m=100,t=10,p=2$*40$");\
		check(&(FUNC), NULL, "$"ALGO"$v=1");\
		check(&(FUNC), NULL, "$"ALGO"$v=");\
		check(&(FUNC), NULL, "$"ALGO"$v=160");\
		check(&(FUNC), NULL, "$"ALGO"$v=160$");\
		check(&(FUNC), NULL, "$"ALGO"$v=10$");\
		check_aborts(&(FUNC));\
	} while (0)


int
main(void)
{
	SET_UP_ALARM();
	INIT_TEST_ABORT();
	INIT_RESOURCE_TEST();

	IF__argon2i__SUPPORTED(CHECK(librecrypt__argon2i__make_settings, "argon2i");)
	IF__argon2d__SUPPORTED(CHECK(librecrypt__argon2d__make_settings, "argon2d");)
	IF__argon2id__SUPPORTED(CHECK(librecrypt__argon2id__make_settings, "argon2id");)
	IF__argon2ds__SUPPORTED(CHECK(librecrypt__argon2ds__make_settings, "argon2ds");)

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
