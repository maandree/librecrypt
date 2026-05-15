/* See LICENSE file for copyright and license details. */
#if defined(__clang__)
# pragma clang diagnostic ignored "-Wunsafe-buffer-usage" /* completely broken */
# pragma clang diagnostic ignored "-Wpadded" /* don't care */
# pragma clang diagnostic ignored "-Wdisabled-macro-expansion" /* glibc issue */
# pragma clang diagnostic ignored "-Wc11-extensions" /* glibc issue */
# pragma clang diagnostic ignored "-Wpre-c11-compat" /* glibc issue */
# pragma clang diagnostic ignored "-Wunknown-warning-option" /* ignoring -Wsuggest-attribute=const|pure */
# pragma clang diagnostic ignored "-Wimplicit-void-ptr-cast" /* C++ warning, and we are in internal files */
# pragma clang diagnostic ignored "-Wc++-keyword" /* C++ warning, and we are in internal files */
# pragma clang diagnostic ignored "-Wc++-unterminated-string-initialization" /* Stupid C++ warning, and we are in internal files */
#endif
#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Winline"
#endif

#include "librecrypt.h"
#if defined(__linux__)
# include <sys/auxv.h>
# include <sys/random.h>
#endif
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


#if defined(__GNUC__)
# define HIDDEN __attribute__((__visibility__("hidden")))
# define CONST __attribute__((__const__))
# define PURE __attribute__((__pure__))
#else
# define HIDDEN
# define CONST
# define PURE
#endif

#define NONSTRING
#if defined(__GNUC__)
# if __GNUC__ >= 8 || defined(__clang__)
#   undef NONSTRING
#   define NONSTRING __attribute__((__nonstring__))
# endif
#endif


#if defined(POSIX_CLOSE_RESTART) && !defined(__linux__)
# define close(fd) posix_close(fd, 0)
#endif


/**
 * Used for literal commas in macro calls
 */
#define COMMA ,

/**
 * Get the number of elements in an array
 * 
 * @param   ARRAY:nondecayed-array  The array
 * @return  :size_t                 The number of elements in `ARRAY`
 */
#define ELEMSOF(ARRAY) (sizeof(ARRAY) / sizeof(*(ARRAY)))

/**
 * Select the minimum of two values
 */
#define MIN(A, B) ((A) < (B) ? (A) : (B))

/**
 * Select the maximum of two values
 */
#define MAX(A, B) ((A) > (B) ? (A) : (B))


#include "algorithms.h"


/**
 * Which function `librecrypt_hash_` shall behave as
 */
enum action {
	/**
	 * Used for `librecrypt_hash_binary`
	 * 
	 * Output is binary and hash result-only
	 */
	BINARY_HASH,

	/**
	 * Used for `librecrypt_hash`
	 * 
	 * Output is ASCII and hash result-only
	 */
	ASCII_HASH,

	/**
	 * Used for `librecrypt_hash`
	 * 
	 * Output is ASCII and contains algorithm configurations
	 */
	ASCII_CRYPT
};


/**
 * Hash algorithm information and implementation
 */
struct algorithm {
	/**
	 * Determine if a password hash string
	 * selects the algorithm
	 * 
	 * @param   settings  The password hash string, containing a single algorithm
	 * @param   len       The number of bytes in `settings`
	 * @return            A positive value if the string matches the algorithm,
	 *                    0 otherwise
	 * 
	 * If non-zero is returned for multiple algorithm,
	 * the first with the highest value wins
	 * 
	 * This function shall be MT-Safe and AS-Safe
	 */
	unsigned (*is_algorithm)(const char *settings, size_t len);

	/**
	 * Implements `librecrypt_hash_binary` for a single hash algorithm;
	 * see `librecrypt_hash_binary` for more information
	 * 
	 * @param   out_buffer  See `librecrypt_hash_binary`
	 * @param   size        See `librecrypt_hash_binary`
	 * @param   phrase      See `librecrypt_hash_binary`; may be `NULL`
	 *                      even if `len` is positive, this happens when
	 *                      `size` is too small and the hash result will
	 *                      not be included, so there is no need to actually
	 *                      calculate the hash, however `len` and `settings`
	 *                      should still be checked
	 * @param   len         See `librecrypt_hash_binary`
	 * @param   settings    See `librecrypt_hash_binary`,
	 *                      will not contains asterisk-encoding
	 * @param   prefix      The length of `settings`, in bytes
	 * @param   reserved    See `librecrypt_hash_binary`
	 * @return              0 on success, -1 on failure
	 * @throws              See `librecrypt_hash_binary`
	 * 
	 * This function shall be MT-Safe but may be AS-Unsafe
	 */
	int (*hash)(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
	            const char *settings, size_t prefix, void *reserved);

	/**
	 * Check whether the hash algorithm is supported for given
	 * configuration and input
	 * 
	 * @param   phrase    The password to hash, may contain NUL bytes;
	 *                    may be `NULL` even if `len` is non-zero
	 * @param   len       The number of bytes in `phrase`, if `phrase` is `NULL`,
	 *                    the function will check that the specified number of
	 *                    bytes is supported as well as any byte sequence unless
	 *                    `text` is non-zero
	 * @param   text      Assume the password is valid UTF-8 text (without NUL bytes)
	 *                    iff non-zero; ignored if `phrase` is non-`NULL`
	 * @param   settings  The password hash string; it is allowed for algorithm
	 *                    tuning parameters, and the hash result, to be omitted
	 * @param   prefix    The number of bytes in `settings`
	 * @param   len_out   Output parameter for the binary hash size, in bytes
	 * @return            1 if the configuration is supported and correctly
	 *                    configured, 0 otherwise
	 * 
	 * This function shall be MT-Safe and AS-Safe
	 */
	int (*test_supported)(const char *phrase, size_t len, int text, const char *settings, size_t prefix, size_t *len_out);

	/**
	 * See `librecrypt_make_settings`
	 * 
	 * @param   out_buffer  See `librecrypt_make_settings`
	 * @param   size        See `librecrypt_make_settings`
	 * @param   algorithm   See `librecrypt_make_settings`,
	 *                      will match the algorithm or be `NULL`
	 * @param   memcost     See `librecrypt_make_settings`
	 * @param   timecost    See `librecrypt_make_settings`
	 * @param   gensalt     See `librecrypt_make_settings`
	 * @param   rng         See `librecrypt_make_settings`
	 * @param   user        See `librecrypt_make_settings`
	 * @return              See `librecrypt_make_settings`
	 * @throws              See `librecrypt_make_settings`
	 * 
	 * This function shall be MT-Safe but may be AS-Safe
	 */
	ssize_t (*make_settings)(char *out_buffer, size_t size, const char *algorithm, size_t memcost, uintmax_t timecost,
	                         int gensalt, ssize_t (*rng)(void *out, size_t n, void *user), void *user);

	/**
	 * Expected argument for the `lut` parameter
	 * of the `librecrypt_encode` function
	 */
	const char *encoding_lut;

	/**
	 * Expected argument for the `lut` parameter
	 * of the `librecrypt_decode` function
	 */
	const unsigned char *decoding_lut;

	/**
	 * The algoritm's hash result size, in number
	 * of bytes when using binary encoding
	 */
	size_t hash_size;

	/**
	 * 1 if `.hash_size` is just a default,
	 * 0 if `.hash_size` is always used
	 */
	signed char flexible_hash_size;

	/**
	 * Expected argument for the `strict_pad` parameter
	 * of the `librecrypt_decode` function
	 */
	signed char strict_pad;

	/**
	 * Expected argument for the `pad` parameter
	 * of the `librecrypt_decode` function
	 */
	char pad;
};

/**
 * Check if an `struct algorithm *` is the `END_OF_ALGORITHMS`
 * at the end of `librecrypt_algorithms_`
 */
#define IS_END_OF_ALGORITHMS(A) (!(A)->is_algorithm)

/**
 * Used at the end of `librecrypt_algorithms_`
 */
#define END_OF_ALGORITHMS\
	{\
		.is_algorithm = NULL,\
		.hash = NULL,\
		.test_supported = NULL,\
		.make_settings = NULL,\
		.encoding_lut = NULL,\
		.decoding_lut = NULL,\
		.hash_size = 0u,\
		.flexible_hash_size = 0,\
		.strict_pad = 0,\
		.pad = '\0'\
	}

/**
 * Create a concatenation of `ALPHABET` repeated
 * for times; used to convert a base-64 alphabet
 * to an encoding lookup table
 * 
 * @param   ALPHABET:string-literal  A 64-character string
 * @return  :string-literal          A 256-character string
 * 
 * @seealso  NONSTRING
 */
#define MAKE_ENCODING_LUT(ALPHABET) ALPHABET ALPHABET ALPHABET ALPHABET

/**
 * Use in algorithms's base-64 decoding lookup tables
 * in entries matching the pad character and invalid
 * characters
 */
#define XX 0xFFu


/**
 * The list of all supported algorithms (those not disabled
 * at compile-time)
 * 
 * They are ordered by how preferable they are as the
 * default algorithm, with the most preferable first
 * 
 * The list is terminated by `END_OF_ALGORITHMS`,
 * which can be checked using `IS_END_OF_ALGORITHMS`
 */
extern struct algorithm librecrypt_algorithms_[];

/**
 * This just points to memset(3), but the pointer is volalite
 * so that the compiler cannot assume that, and therefore the
 * call cannot be optimised away
 */
extern void *(*volatile librecrypt_explicit_memset_____)(void *, int, size_t); /* librecrypt_wipe.c */

/**
 * The is a pointer to a function that doesn't do anything,
 * however the pointer is volatile so that the function
 * cannot assume that and cannot optimise away the calculating
 * of the input value
 */
extern void (*volatile librecrypt_explicit_____)(unsigned char); /* librecrypt_equal_binary.c */


/**
 * This function implements `librecrypt_hash_binary`, `librecrypt_hash`,
 * and `librecrypt_test_supported`, depending on the value of `action`,
 * see documentation of those functions for more default information
 * 
 * @param   out_buffer  Output buffer for the hash result
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   phrase      The password to hash, may contain NUL bytes
 * @param   len         The number of bytes in `phrase`
 * @param   settings    The password hash configuration string,
 *                      may contain resulting hash, which will be ignored
 * @param   reserved    Reserved for future use, should be `NULL`
 * @param   action      The function this function shall implement
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte (not present if `action == BINARY_HASH`);
 *                      -1 on failure
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4)
LIBRECRYPT_READ_STR__(6) LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__ HIDDEN
ssize_t librecrypt_hash_(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                         const char *settings, void *reserved, enum action action);


/**
 * Default random number generator, used if no other
 * is specified
 * 
 * Generates up to `n`, or {SSIZE_MAX} if `n` is
 * greater than {SSIZE_MAX}, random bytes
 * 
 * @param   out   Output buffer for the random bytes
 * @param   n     The maximum number of bytes to generate
 * @param   user  Not used
 * @return        The number of generated bytes;
 *                will always be positive
 * 
 * This function cannot fail, however it will ignore
 * any `EINTR`; if `EINTR` is encountered `errno` will
 * be set to `EINTR` upon return, otherwise `errno`
 * will remain unmodifed
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_WUR__ HIDDEN
ssize_t librecrypt_rng_(void *out, size_t n, void *user);


/**
 * Generate a specific number of random bytes
 * 
 * @param   out   Output buffer for the random bytes
 * @param   n     The number of bytes to generate
 * @param   rng   The random number generator to use,
 *                `librecrypt_rng_` will be used if `NULL`,
 *                see `librecrypt_rng_` details, but not
 *                that it may return -1 on failure and has
 *                no restrictions on modifying `errno`
 * @param   user  Passed as is to `*rng` as its third argument,
 *                so that it can be used for user-defined
 *                purposes
 * @return        0 on success, -1 on failure
 * 
 * When `rng` is non-`NULL`, this function inherits any
 * MT-Unsafe and AS-Unsafe properties from `*rng`, being
 * is MT-Safe and AS-Safe as a baseline; however when
 * `rng` is `NULL`, this function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_WUR__ HIDDEN
int librecrypt_fill_with_random_(void *out, size_t n, ssize_t (*rng)(void *out, size_t n, void *user), void *user);


/**
 * Find the first algorithm specified by a password has string
 * 
 * @param   settings   The password has string
 * @param   len        The number of bytes in `settings`
 * @return             Pointer to the algorithm information,
 *                     `NULL` if not found
 * 
 * This function does not modify `errno`, but the
 * caller should usually set `errno` to `ENOSYS`
 * if this function returns `NULL`
 * 
 * This function is MT-Safe And AS-Safe
 */
LIBRECRYPT_READ_MEM__(1, 2) LIBRECRYPT_NONNULL__ LIBRECRYPT_WUR__ HIDDEN
const struct algorithm *librecrypt_find_first_algorithm_(const char *settings, size_t len);


/**
 * Function used to validate a password hash string
 * 
 * @param   settings  The string to validate
 * @param   len       The number of bytes in `settings`
 * @param   fmt       The expected format of the string, it may contain
 *                    the metacharacter '%' (`fmt` is parsed left to right)
 *                    to perform special string content checks:
 *                      "%%"  - Literal '%'
 *                      "%*"  - Any sequence of non-'$' bytes (greedly matched)
 *                      "%s"  - String
 *                      "%u"  - Unsigned integer that may start with a leading zeroes
 *                      "%p"  - Unsigned integer that most not start with a leading zeroes
 *                      "%b"  - Binary data, either encoded to ASCII or ungenerated content
 *                              that is length specified using asterisk-notation
 *                      "%h"  - Same as "%b", except empty content as always allowed unless
 *                              asterisk-notation is used
 *                      "%^s" - Same as "%s" except with output argument
 *                      "%^u" - Same as "%u" except with output argument
 *                      "%^p" - Same as "%p" except with output argument
 *                      "%^b" - Same as "%b" except with one output argument: length
 *                      "%&b" - Same as "%b" except with two output argument:
 *                              pointer to text, text length, or NULL and binary length
 *                      "%^h" - Same as "%h" except with one output argument: length
 *                      "%&h" - Same as "%h" except with two output argument:
 *                              pointer to text, text length, or NULL and binary length
 * @param   ...       Arguments for each use of '%' in `fmt`:
 *                      "%%"  - None
 *                      "%*"  - None
 *                      "%s"  - At least one `const char *`: allowed matches (in order of preference),
 *                              followed by a `NULL`
 *                      "%u"  - Two `uintmax_t`: the minimum value and the maximum value
 *                      "%p"  - Same as "%u"
 *                      "%b"  - Two `uintmax_t`: the minimum value and the maximum value,
 *                              one `const unsigned char dlut[static 256]`: the ASCII-encoding decoding table,
 *                              one `char`: the padding character or `'\0'` if none may be used, and
 *                              one `int`: whether padding must always be used unless the previous argument is `'\0'`
 *                      "%h"  - Same as "%b"
 *                      "%^s" - Same as "%s" but with an additional argument, as the first one:
 *                              a `const char **` used to store the matched string
 *                      "%^u" - Same as "%u" but with an additional argument, as the first one:
 *                              a `uintmax_t *` used to store the encoded integer
 *                      "%^p" - Same as "%p" but with an additional argument, as the first one:
 *                              a `uintmax_t *` used to store the encoded integer
 *                      "%^b" - Same as "%b" but with an additional argument, as the first one:
 *                              a `uintmax_t *` used to store the number of encoded bytes or
 *                              the encoded integer after the asterisk if asterisk-encoding is used
 *                      "%&b" - Same as "%b" but with two additional arguments, as the first two:
 *                              a `const char **` and a `uintmax_t *`: if asterisk-notation is used
 *                              the `const char *` will be set to `NULL` and the `uintmax_t` will be
 *                              set to the encoded number, othererwise the `const char *` will be
 *                              set to point to the position in `settings` where the base-64 encoded
 *                              text begins and the `uintmax_t` will be set to length of the text
 *                              (as encoded in base-64, _not_ as decoded to binary)
 *                      "%^h" - Same as "%^b"
 *                      "%&h" - Same as "%&b"
 * @return            1 if `string` matches `fmt`, 0 otherwise
 */
LIBRECRYPT_READ_MEM__(1, 2) LIBRECRYPT_NONNULL_I__(3) LIBRECRYPT_WUR__ HIDDEN
int librecrypt_check_settings_(const char *settings, size_t len, const char *fmt, ...);



#ifdef TEST
# include "libtest/libtest.h"
# ifdef __linux__
#  include <sys/prctl.h>
# endif
# include <sys/resource.h>
# include <sys/types.h>
# include <sys/uio.h>
# include <sys/wait.h>
# include <setjmp.h>
# include <signal.h>
# include <string.h>
# include <unistd.h>

# define SET_UP_ALARM()\
	do {\
		unsigned int alarm_time__ = alarm(10u);\
		if (alarm_time__ > 10u)\
			alarm(alarm_time__);\
	} while (0)

# if defined(PR_SET_DUMPABLE)
#  define INIT_TEST_ABORT()\
	do {\
		struct rlimit rl__;\
		rl__.rlim_cur = 0;\
		rl__.rlim_max = 0;\
		(void) setrlimit(RLIMIT_CORE, &rl__);\
		(void) prctl(PR_SET_DUMPABLE, 0);\
		EXPECT_ABORT(abort());\
	} while (0)
# else
#  define INIT_TEST_ABORT()\
	do {\
		struct rlimit rl__;\
		rl__.rlim_cur = 0;\
		rl__.rlim_max = 0;\
		(void) setrlimit(RLIMIT_CORE, &rl__);\
		EXPECT_ABORT(abort());\
	} while (0)
# endif

# define INIT_RESOURCE_TEST()\
	do {\
		libtest_start_tracking();\
		libtest_force_zero_on_alloc(1);\
		libtest_expect_zeroed_on_free(1);\
	} while (0)

# define STOP_RESOURCE_TEST()\
	do {\
		libtest_stop_tracking();\
		libtest_force_zero_on_alloc(0);\
		libtest_expect_zeroed_on_free(0);\
		EXPECT(libtest_check_no_leaks());\
	} while (0)

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
# include <stdatomic.h>
# define MEMFENCE() atomic_thread_fence(memory_order_seq_cst)
#elif defined(_MSC_VER)
# include <intrin.h>
# define MEMFENCE() _ReadWriteBarrier()
#else
# define MEMFENCE() __asm__ volatile("" ::: "memory")
#endif

# define EXPECT__(EXPR, HOW, RETEXTRACT, RETEXPECT)\
	do {\
		pid_t pid__;\
		int status__;\
		pid__ = fork();\
		EXPECT(pid__ != -1);\
		if (pid__ == 0) {\
			(EXPR);\
			_exit(0);\
		}\
		EXPECT(waitpid(pid__, &status__, 0) == pid__);\
		EXPECT(HOW(status__));\
		EXPECT(RETEXTRACT(status__) == RETEXPECT);\
	} while (0)

# define EXPECT_ABORT(EXPR)\
	do {\
		EXPECT__(EXPR, WIFSIGNALED, WTERMSIG, SIGABRT);\
	} while (0)

# define EXPECT(EXPR)\
	do {\
		MEMFENCE();\
		if (!(EXPR)) {\
			int test_expect_saved_errno__ = errno;\
			libtest_expect_zeroed_on_free(0);\
			libtest_stop_tracking();\
			fprintf(stderr, "Failure at %s:%i: %s (errno = %i)\n",\
			       __FILE__, __LINE__, #EXPR, test_expect_saved_errno__);\
			libtest_dump_stack(NULL, "\t");\
			exit(1);\
		}\
	} while (0)

# define assert(EXPR)\
	do {\
		MEMFENCE();\
		if (!(EXPR)) {\
			libtest_expect_zeroed_on_free(0);\
			libtest_stop_tracking();\
			fprintf(stderr, "Assertion failure at %s:%i: %s\n",\
			       __FILE__, __LINE__, #EXPR);\
			libtest_dump_stack(NULL, "\t");\
			exit(2);\
		}\
	} while (0)

# define CANARY_FILL(BUF) CANARY_C_FILL(99, BUF)
# define CANARY_CHECK(BUF, OFF) CANARY_C_CHECK(99, BUF, OFF)
# define CANARY_X_CHECK(BUF, OFF1, OFF2) CANARY_XC_CHECK(99, BUF, OFF1, OFF2)

# define CANARY_C_FILL(C, BUF)\
	memset((BUF), (C), sizeof(BUF))

# define CANARY_C_CHECK(C, BUF, OFF)\
	do {\
		size_t canary_i__;\
		for (canary_i__ = (OFF); canary_i__ < sizeof(BUF); canary_i__++)\
			EXPECT(((unsigned char *)(BUF))[canary_i__] == (unsigned char)(C));\
	} while (0)

# define CANARY_XC_CHECK(C, BUF, OFF1, OFF2)\
	CANARY_XCC_CHECK(0, C, BUF, OFF1, OFF2)

# define CANARY_XCC_CHECK(C1, C2, BUF, OFF1, OFF2)\
	do {\
		if ((OFF2) > (OFF1))\
			CANARY_C_CHECK((C2), (BUF), (OFF2));\
		memset(&(BUF)[(OFF1)], (C1), sizeof(BUF) - (OFF1));\
		CANARY_C_CHECK((C1), (BUF), (OFF1));\
	} while (0)

#endif
