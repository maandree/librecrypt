/* See LICENSE file for copyright and license details. */
#include "librecrypt.h"
#if defined(__linux__)
# include <sys/auxv.h>
# include <sys/random.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "algorithms.h"


#if defined(__GNUC__)
# define HIDDEN __attribute__((__visibility__("hidden")))
# define CONST __attribute__((__const__))
#else
# define HIDDEN
# define CONST
#endif

#define NONSTRING
#if defined(__GNUC__) && !defined(__clang__)
# if __GNUC__ >= 8
#   undef NONSTRING
#   define NONSTRING __attribute__((__nonstring__))
# endif
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
	 * Get the number of bytes that constitute
	 * the algorithm specification and configuration
	 * 
	 * @param   settings  The password hash string, containing a single algorithm
	 * @param   len       The number of bytes in `settings`
	 * @return            `len` if the string does not contain any hash result,
	 *                    otherwise the offset of `settings` where the hash
	 *                    result begins
	 * 
	 * This function shall be MT-Safe and AS-Safe
	 */
	size_t (*get_prefix)(const char *settings, size_t len);

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
	 * @return            1 if the configuration is supported and correctly
	 *                    configured, 0 otherwise
	 * 
	 * This function shall be MT-Safe and AS-Safe
	 */
	int (*test_supported)(const char *phrase, size_t len, int text, const char *settings, size_t prefix);

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
	 * Expected argument for the `strict_pad` parameter
	 * of the `librecrypt_decode` function
	 */
	int strict_pad;

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
#define IS_END_OF_ALGORITHMS(A) (!(A)->get_prefix)

/**
 * Used at the end of `librecrypt_algorithms_`
 */
#define END_OF_ALGORITHMS {NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, '\0'}

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



#ifdef TEST
# ifdef __linux__
#  include <sys/prctl.h>
# endif
# include <sys/resource.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <assert.h>
# include <signal.h>
# include <stdio.h>
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
		if (!(EXPR)) {\
			fprintf(stderr, "Failure at %s:%i: %s\n", __FILE__, __LINE__, #EXPR);\
			exit(1);\
		}\
	} while (0)
#endif
