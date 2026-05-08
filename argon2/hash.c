/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST

#include <libar2.h>
#include <libar2simplified.h>


#define RANGE(MIN, MAX) (uintmax_t)(MIN), (uintmax_t)(MAX)
#define BASE64 librecrypt_common_rfc4848s4_decoding_lut_, argon2__PAD, argon2__STRICT_PAD
#define REMOVE_CONST(X) (*(void **)(void *)&(X))


int
librecrypt__argon2__hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                         const char *settings, size_t prefix, void *reserved)
{
	struct libar2_argon2_parameters params;
	struct libar2_context ctx;
	const char *type, *version, *salt_encoded;
	uintmax_t mcost, tcost, lanes, saltlen, hashlen;
	void *salt = NULL, *scratch = NULL;
	size_t scratch_size;
	ssize_t r;
	int saved_errno;

	/* Not yet used */
	(void) reserved;

	/* Gives us memory allocation and threading support;
	 * so we don't have to implement any of that ourselves */
	libar2simplified_init_context(&ctx);
	/* Configure automatic erasure of input memory */
	ctx.autoerase_message = 0; /* allows `phrase` to be read-only */
	ctx.autoerase_secret = 0; /* alloes to params.key, which we are not using, but maybe in the future */
	ctx.autoerase_associated_data = 0; /* alloes to params.ad, which we are not using, but maybe in the future */
	ctx.autoerase_salt = 1; /* since we are decoding the salt, we do a memory allocation,
	                         * and our testing always checks that allocated memory is earse;
	                         * it doesn't really matter, but it's paranoid, and that's good */

	/* Parse `settings` */
	r = librecrypt_check_settings_(settings, prefix,
		"$argon2%^s$%^sm=%^p,t=%^p,p=%^p$%&b$%^h",
		&type, "id", "i", "ds", "d", NULL, /* order partially matters */
		&version, "v=19$", "v=16$", "", NULL,
		&mcost, RANGE(LIBAR2_MIN_M_COST, LIBAR2_MAX_M_COST),
		&tcost, RANGE(LIBAR2_MIN_T_COST, LIBAR2_MAX_T_COST),
		&lanes, RANGE(LIBAR2_MIN_LANES, LIBAR2_MAX_LANES),
		&salt_encoded, &saltlen, RANGE(LIBAR2_MIN_SALTLEN, LIBAR2_MAX_SALTLEN), BASE64,
		&hashlen, RANGE(LIBAR2_MIN_HASHLEN, LIBAR2_MAX_HASHLEN), BASE64);
	if (!r) {
		errno = EINVAL;
		return -1;
	}

	/* Decode salt */
	if (!salt_encoded) /* this would be if asterisk-notation is used, but it is not */
		abort();
	r = librecrypt_decode(NULL, 0u, salt_encoded, saltlen, BASE64);
	if (r < 0)
		return -1;
	if (r > 0) {
		/* We allow `r` to be 0, although that means saltlen is 0,
		 * which it cannot actaully be since LIBAR2_MIN_SALTLEN is 8,
		 * but who knows the future. Of course, we cannot run this
		 * part if `r` is 0, because we don't want to run malloc(3)
		 * with 0 because our test's implementation of malloc(3)
		 * doesn't allow that because it's implementation-defined,
		 * and we still would have to have a special case handling
		 * for implementations where it returns NULL, so instead
		 * we just let `salt` remain NULL, and `saltlen` remain 0. */
		salt = malloc((size_t)r);
		if (!salt)
			return -1;
		if (librecrypt_decode(salt, (size_t)r, salt_encoded, saltlen, BASE64) != r)
			abort();
		saltlen = (uintmax_t)r;
	}

	/* Apply `settings` */
	params.type = type[1u] == 'd' ? LIBAR2_ARGON2ID :
	              type[1u] == 's' ? LIBAR2_ARGON2DS :
	              type[0u] == 'i' ? LIBAR2_ARGON2I :
	                                LIBAR2_ARGON2ID;
	params.version = version[3u] == '9' ? LIBAR2_ARGON2_VERSION_13 : /* 19 = 0x13 = 1.3 */
	                                      LIBAR2_ARGON2_VERSION_10;  /* 16 = 0x10 = 1.0 */
	params.t_cost = (uint_least32_t)tcost;
	params.m_cost = (uint_least32_t)mcost;
	params.lanes = (uint_least32_t)lanes;
	params.salt = salt;
	params.saltlen = (size_t)saltlen;
	params.key = NULL;
	params.keylen = 0u;
	params.ad = NULL;
	params.adlen = 0u;
	params.hashlen = hashlen ? (size_t)hashlen : argon2__HASH_SIZE;

	/* Argon2 may require a larger buffer to work with for the hash than it outputs */
	scratch_size = libar2_hash_buf_size(&params);
	if (scratch_size > size) {
		scratch = malloc(scratch_size);
		if (!scratch)
			goto fail;
	}

	/* Calculate hash */
	if (libar2_hash(scratch ? scratch : out_buffer, REMOVE_CONST(phrase), len, &params, &ctx))
		goto fail;

	/* same rationale as for `ctx.autoerase_salt = 1;` */
	if (scratch) {
		librecrypt_wipe(scratch, scratch_size);
		free(scratch);
	} else if (scratch_size > params.hashlen) {
		librecrypt_wipe(&out_buffer[params.hashlen], scratch_size - params.hashlen);
	}

	free(salt);
	return 0;

fail:
	saved_errno = errno;
	if (salt) {
		librecrypt_wipe(salt, saltlen);
		free(salt);
	}
	errno = saved_errno;
	return -1;
}


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
