/* See LICENSE file for copyright and license details. */
#include "../common.h"
#ifndef TEST

#include <libar2.h>


#define RANGE(MIN, MAX) (uintmax_t)(MIN), (uintmax_t)(MAX)
#define BASE64 librecrypt_common_rfc4848s4_decoding_lut_, argon2__PAD, argon2__STRICT_PAD


int
librecrypt__argon2__test_supported(const char *phrase, size_t len, int text, const char *settings, size_t prefix, size_t *len_out)
{
	uintmax_t hashlen;
	int r;

	/* We don't care about password content, arbitrary binary is supported */
	(void) phrase;
	(void) text;

	/* Validate string format and parameters */
	r = librecrypt_check_settings_(settings, prefix,
		"$%*$%sm=%p,t=%p,p=%p$%b$%^h",
		"v=16$", "v=19$", "", NULL,
		RANGE(LIBAR2_MIN_M_COST, LIBAR2_MAX_M_COST),
		RANGE(LIBAR2_MIN_T_COST, LIBAR2_MAX_T_COST),
		RANGE(LIBAR2_MIN_LANES, LIBAR2_MAX_LANES),
		RANGE(LIBAR2_MIN_SALTLEN, LIBAR2_MAX_SALTLEN), BASE64,
		&hashlen, RANGE(LIBAR2_MIN_HASHLEN, LIBAR2_MAX_HASHLEN), BASE64);
	if (!r)
		return 0;

	/* Return hash size */
	if (!hashlen)
		hashlen = argon2__HASH_SIZE;
	*len_out = (size_t)hashlen;

	/* Check password size */
#if SIZE_MAX > UINT32_MAX
	return len <= UINT32_MAX;
#else
	(void) len;
	return 1;
#endif
}


#else


int
main(void)
{
	size_t n = 99u;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#define S(STR) (STR), (sizeof(STR) - 1u)

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$"), &n) == 1);
	EXPECT(n == 32u);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*40"), &n) == 1);
	EXPECT(n == 40u);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$////////////"), &n) == 1);
	EXPECT(n == 9u);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$////////////AA"), &n) == 1);
	EXPECT(n == 10u);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$////////////AAA"), &n) == 1);
	EXPECT(n == 11u);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$////////////AA#"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$////"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*40$"), &n) == 0);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$CCCCBBBBAAA$*40"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$CCCCBBBBAA#$*40"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$CCCCBBBB$*40"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$AAAABBBBCCCC$*40"), &n) == 1);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$v=16$m=8,t=1,p=1$*16$*40"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$v=19$m=8,t=1,p=1$*16$*40"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$v=1$m=8,t=1,p=1$*16$*40"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$v=10$m=8,t=1,p=1$*16$*40"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$v=160$m=8,t=1,p=1$*16$*40"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$v=190$m=8,t=1,p=1$*16$*40"), &n) == 0);

	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=0$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=0,p=1$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=0,t=1,p=1$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=7,t=1,p=1$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=4294967296,t=1,p=1$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=4294967296,p=1$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=4294967295,p=1$*16$"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=16777216$*16$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=16777215$*16$"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*4294967296$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*4294967295$"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*8$"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*7$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*0$"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*4294967296"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*4294967295"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*4"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*3"), &n) == 0);
	EXPECT(librecrypt__argon2__test_supported(NULL, UINT32_MAX, 0, S("$...$m=8,t=1,p=1$*16$*0"), &n) == 0);

	EXPECT(librecrypt__argon2__test_supported(NULL, 1u, 0, S("$...$m=8,t=1,p=1$*16$"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, 0u, 0, S("$...$m=8,t=1,p=1$*16$"), &n) == 1);

	EXPECT(librecrypt__argon2__test_supported(NULL, 1u, 1, S("$...$m=8,t=1,p=1$*16$"), &n) == 1);
	EXPECT(librecrypt__argon2__test_supported(NULL, 0u, 1, S("$...$m=8,t=1,p=1$*16$"), &n) == 1);

#if SIZE_MAX > UINT32_MAX
	EXPECT(librecrypt__argon2__test_supported(NULL, (size_t)UINT32_MAX + 1u, 0, S("$...$m=8,t=1,p=1$*16$"), &n) == 0);
#endif

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
