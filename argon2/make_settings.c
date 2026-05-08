/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST

#include <libar2.h>


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
		abort();
	p = strchr(p, '$');
	algolen = p ? (size_t)(p - algorithm) : strlen(algorithm);
	if (algolen > 64) /* just some small value absolute will fit all variants */
		abort();
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
		abort();
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


CONST int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
/* TODO test */
