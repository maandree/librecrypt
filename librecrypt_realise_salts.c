/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


ssize_t
librecrypt_realise_salts(char *restrict out_buffer, size_t size, const char *settings,
                         ssize_t (*rng)(void *out, size_t n, void *user), void *user)
{
	const char *lut;
	char pad;
	int strict_pad, nul_term = 0;
	size_t i, min, nasterisks, prefix, ret = 0u;
	size_t count, digit, q, r, left, mid, right;

	/* If we are doing output, it should be NUL-terminated */
	if (size) {
		nul_term = 1;
		size -= 1u;
	}

	/* For each chained algorithm */
	while (*settings) {
		/* Get the number of '*' that are not in the result
		 * (hash size specification), and also length of
		 * the algorithm configuration, so we can identify
		 * the algorithm next and get its binary data encoding
		 * format (just calling librecrypt_get_encoding on the
		 * entire string would get it for the last algorithm
		 * in the chain) */
		nasterisks = 0u;
		count = 0u;
		for (prefix = 0u; settings[prefix]; prefix++) {
			if (settings[prefix] == LIBRECRYPT_HASH_COMPOSITION_DELIMITER)
				nasterisks = count;
			else if (settings[prefix] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;
			else if (settings[prefix] == '*')
				count += 1u;
		}

		/* Get binary data encoding format */
		lut = librecrypt_get_encoding(settings, prefix, &pad, &strict_pad, 0);
		if (!lut)
			return -1;
		pad = strict_pad ? pad : '\0';

		/* Process each asterisk-encoded salt */
		while (nasterisks--) {
			/* Copy text before next '*' */
			for (i = 0u; settings[i] != '*'; i++);
			min = MIN(i, size);
			memcpy(out_buffer, settings, min);
			out_buffer = &out_buffer[min];
			size -= min;
			settings = &settings[i];
			ret += i;

			/* Skip past the '*' */
			settings++;

			/* If the '*' is not followed by an unsigned,
			 * decimal integer include it literally */
			if ('0' > settings[0u] || settings[0u] > '9') {
				if (size) {
					*out_buffer++ = '*';
					size -= 1u;
				}
				ret += 1u;
				continue;
			}

			/* Parse encoded integer */
			count = 0u;
			while ('0' <= *settings && *settings <= '9') {
				digit = (size_t)(*settings++ - '0');
				if (count > ((size_t)SSIZE_MAX - digit) / 10u)
					goto erange;
				count *= 10u;
				count += digit;
			}

			/* Get number of random base-64 characters to generated,
			 * and the number of padding characters to append */
			/* 1 byte (8 bits) requires 2 base-64 characters (12 bits, 4 bits extra),
			 * 2 bytes (16 bits) requires 3 base-64 characters (18 bits, 2 bits extra), and
			 * 3 bytes (25 bits) requires 4 base-64 characters (24 bits) exactly */
			q = count / 3u;
			r = count % 3u;
			/* Full alphabet */
			left = q * 4u + r;
			/* Partial alphabet (extra bits are encoded as 0) */
			mid = r ? 1u : 0u;
			/* Padding: r==0: no padding,
			 *          r==1: 2 base-64 characters, so 2 padding characters,
			 *          r==2: 3 base-64 characters, so 1 padding characters */
			right = (r && pad) ? 3u - r : 0u;
			/* Get total length */
			if (q > ((size_t)SSIZE_MAX - (r + mid + right)) / 4u)
				goto erange;
			if (ret > (size_t)SSIZE_MAX - (left + mid + right))
				goto erange;
			ret += left + mid + right;

			/* Make sure we don't write more random characters than
			 * we have room for; we add `mid` into `left` so we have
			 * one variable for all random characters */
			left += mid;
			if (left > size) {
				left = size;
				mid = 0u;
			}

			/* Write random characters */
			if (librecrypt_fill_with_random_(out_buffer, left, rng, user))
				return -1;
			for (i = 0u; i < left; i++)
				out_buffer[i] = lut[((unsigned char *)out_buffer)[i]];
			if (mid) {
				i = left - 1u;
				out_buffer[i] = lut[((unsigned char *)out_buffer)[i] & (r == 1u ? ~15u : ~3u)];
			}
			out_buffer = &out_buffer[left];
			size -= left;

			/* Write padding charaters */
			right = MIN(right, size);
			for (i = 0u; i < right; i++)
				out_buffer[right] = pad; /* $covered$ (TODO we currently don't have an algorithm to trigger this) */
			out_buffer = &out_buffer[right];
			size -= right;
		}

		/* Copy remainder of the algorithm configuration, and the '>' if intermediate */
		for (i = 0u; settings[i];)
			if (settings[i++] == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
				break;
		min = MIN(i, size);
		memcpy(out_buffer, settings, min);
		out_buffer = &out_buffer[min];
		size -= min;
		settings = &settings[i];
		ret += i;
	}

	/* NUL-terminate the output if we were doing output */
	if (nul_term)
		*out_buffer = '\0';

	/* Return the number of written bytes (excluding NUL byte):
	 * the length of the new password hash string, but ensure
	 * the new salts where not so large that our return value
	 * is out of range */
	if (ret > (size_t)SSIZE_MAX)
		goto erange;
	return (ssize_t)ret;

erange:
	errno = ERANGE;
	return -1;
}


#else


# define LARGE "99999999999999999999999999999999999999999999999999999999999999"
# define A10 "AAAAAAAAAA"
# define A40 A10 A10 A10 A10


static unsigned char saltbyte = 0u;


static ssize_t
saltgen(void *out, size_t n, void *user)
{
	(void) user;
	if (n > (size_t)SSIZE_MAX)
		n = (size_t)SSIZE_MAX;
	memset(out, *(unsigned char *)user, n);
	return (ssize_t)n;
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
	char buf[1024], buf2[1024], conf[128];
	size_t i;
	int r;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, "$~no~such~algorithm~$", NULL, NULL) == -1);
	EXPECT(errno == ENOSYS);

	EXPECT(librecrypt_realise_salts(NULL, 0u, "", NULL, NULL) == 0);

#if defined(SUPPORT_ARGON2ID)
# define ALGO "$argon2id$"
#elif defined(SUPPORT_ARGON2I)
# define ALGO "$argon2i$"
#elif defined(SUPPORT_ARGON2D)
# define ALGO "$argon2d$"
#elif defined(SUPPORT_ARGON2DS)
# define ALGO "$argon2ds$"
#endif

#if defined(ALGO)
# define CHECK(IN, OUT)\
	do {\
		EXPECT(librecrypt_realise_salts(NULL, 0u, (IN), NULL, NULL) == (ssize_t)sizeof(OUT) - 1);\
		EXPECT(librecrypt_realise_salts(buf, 0u, (IN), NULL, NULL) == (ssize_t)sizeof(OUT) - 1);\
		memset(buf, 99, sizeof(buf));\
		EXPECT(librecrypt_realise_salts(buf, sizeof(buf), (IN), &saltgen, &saltbyte) == (ssize_t)sizeof(OUT) - 1);\
		EXPECT(!strcmp(buf, (OUT)));\
		for (i = 0u; i < sizeof(OUT); i++) {\
			memset(buf, 99, sizeof(buf));\
			EXPECT(librecrypt_realise_salts(buf, i + 1u, (IN), &saltgen, &saltbyte) == (ssize_t)sizeof(OUT) - 1);\
			EXPECT(!memcmp(buf, (OUT), i));\
			EXPECT(!buf[i]);\
		}\
	} while (0)

	CHECK(ALGO, ALGO);
	CHECK(ALGO"*100", ALGO "*100");
	CHECK(ALGO"*30$", ALGO A40 "$");
	CHECK(ALGO"*30$*100", ALGO A40 "$*100");
	CHECK(ALGO"*31$*100", ALGO A40 "AA$*100");
	CHECK(ALGO"*32$*100", ALGO A40 "AAA$*100");
	CHECK(ALGO"*33$*100", ALGO A40 "AAAA$*100");
	CHECK(ALGO"*1$*100", ALGO "AA$*100");
	CHECK(ALGO"*2$*100", ALGO "AAA$*100");
	CHECK(ALGO"*3$*100", ALGO "AAAA$*100");
	CHECK(ALGO"*033$*100", ALGO A40 "AAAA$*100");
	CHECK(ALGO"*0$*100", ALGO "$*100");
	CHECK(ALGO"*30*30$*100", ALGO A40 A40"$*100");
	CHECK(ALGO"*30*3$*100", ALGO A40 "AAAA$*100");
	CHECK(ALGO"*30$*30$*100", ALGO A40 "$" A40"$*100");
	CHECK(ALGO"*30$*3$*100", ALGO A40 "$AAAA$*100");
	CHECK(ALGO"*$*100", ALGO "*$*100");
	CHECK(ALGO"*x$*100", ALGO "*x$*100");
	CHECK(ALGO">"ALGO, ALGO">"ALGO);
	CHECK(ALGO"*30$*100>"ALGO"*30$*10", ALGO A40 "$*100>" ALGO A40 "$*10");
	CHECK(ALGO"*30$>"ALGO"*30$", ALGO A40 "$>" ALGO A40 "$");

# undef CHECK

	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, ALGO">$~no~such~algorithm~$", &saltgen, &saltbyte) == -1);
	EXPECT(errno == ENOSYS);
	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, "$~no~such~algorithm~$>"ALGO, &saltgen, &saltbyte) == -1);
	EXPECT(errno == ENOSYS);
	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, ALGO"*"LARGE"$", &saltgen, &saltbyte) == -1);
	EXPECT(errno == ERANGE);

	EXPECT(librecrypt_realise_salts(buf, sizeof(ALGO) - 1u, ALGO"*3$", &saltfail, NULL) == (ssize_t)sizeof(ALGO"$") - 1 + 4);
	errno = 0;
	EXPECT(librecrypt_realise_salts(buf, sizeof(buf), ALGO"*3$", &saltfail, NULL) == -1);
	EXPECT(errno == EDOM);

	r = snprintf(conf, sizeof(conf), "%s*%zu$", ALGO, (size_t)SSIZE_MAX / 4u * 3u + 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, conf, &saltgen, &saltbyte) == -1);
	EXPECT(errno == ERANGE);

	r = snprintf(conf, sizeof(conf), "%s*%zu$", ALGO, (size_t)SSIZE_MAX / 4u * 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, conf, &saltgen, &saltbyte) == -1);
	EXPECT(errno == ERANGE);

	r = snprintf(conf, sizeof(conf), "%s*%zu$abcdef", ALGO, ((size_t)SSIZE_MAX - (sizeof(ALGO) - 1u)) / 4u * 3u);
	assert(r > 0 && (size_t)r < sizeof(conf));
	errno = 0;
	EXPECT(librecrypt_realise_salts(NULL, 0u, conf, &saltgen, &saltbyte) == -1);
	EXPECT(errno == ERANGE);

	memset(buf, 99, sizeof(buf));
	memset(buf2, 99, sizeof(buf2));
	EXPECT(librecrypt_realise_salts(buf, sizeof(buf), ALGO"*30$", NULL, NULL) == (ssize_t)sizeof(ALGO"$") - 1 + 40);
	EXPECT(librecrypt_realise_salts(buf2, sizeof(buf2), ALGO"*30$", NULL, NULL) == (ssize_t)sizeof(ALGO"$") - 1 + 40);
	EXPECT(!buf[sizeof(ALGO"$") - 1u + 40u]);
	EXPECT(!buf2[sizeof(ALGO"$") - 1u + 40u]);
	EXPECT(memcmp(buf, buf2, sizeof(ALGO"$") - 1u + 40u));
#endif

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
