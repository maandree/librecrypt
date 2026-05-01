/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST


static ssize_t
make_settings(char *out_buffer, size_t size, const char *algorithm, size_t memcost, uintmax_t timecost,
              int gensalt, ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	/* Use default RNG if NULL is specified */
	if (!rng)
		rng = &librecrypt_rng_;

	/* Adjust `memcost` for algorithm */
	if (!memcost) {
		/* Use default memcost if 0 was specified */
		memcost = (size_t)4096u; /* 4 MiB */
	} else {
		/* Function takes bytes as memcost, algorithm takes kilobytes */
		int memcost_round_up = memcost % 1024u >= 512u;
		memcost >>= 10;
		memcost += memcost_round_up ? 1u : 0u;
		memcost = memcost ? memcost : 1u;
	}

	/* TODO implement */
	(void) out_buffer;
	(void) size;
	(void) algorithm;
	(void) memcost;
	(void) timecost;
	(void) gensalt;
	(void) rng;
	(void) user;
	return 0;
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

	return 0;
}


#endif
/* TODO test */
