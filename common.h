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
# pragma clang diagnostic ignored "-Wcovered-switch-default" /* harmful warning */
#endif
#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Winline"
#endif

#include "librecrypt.h"
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>


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
#  undef NONSTRING
#  define NONSTRING __attribute__((__nonstring__))
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
 * Pepper for a hash algorithm
 */
struct pepper {
	/**
	 * The binary pepper
	 */
	const void *data;

	/**
	 * The number of bytes in `.data`
	 */
	size_t len;
};


/**
 * Structure used for doing truncated text concatenation
 *
 * This structure is laid out so that `{buf, size, 0u}` will
 * properly initialise the state to use a buffer and have
 * it's size properly set, and have the resulting length
 * initialised to zero. This will not change.
 */
struct concat_state {
	/**
	 * Where the function shall write to
	 *
	 * Update to an offset of it by the called function.
	 * Shall be set to the beginning of the output buffer
	 * before the first function call.
	 */
	char *buf;

	/**
	 * The (remaining) size of the output buffer
	 *
	 * This is decremented by the called function
	 * Shall be set to the size of the output buffer
	 * before the first function call.
	 */
	size_t size;

	/**
	 * The length the constructed text would
	 * have had if it wasn't truncated
	 *
	 * This length does not include NUL termination
	 * which is added by every function
	 *
	 * This is increased by the called function.
	 * Should be set to 0 before the first function call.
	 *
	 * After the last concatenation call, this field
	 * is read to get the final size before truncation
	 */
	size_t len;
};


/**
 * The real type of `LIBRECRYPT_CONTEXT`
 */
struct librecrypt_context {
	/**
	 * Application-defined data
	 */
	void *user_data;

	/**
	 * Application-provided hash function implementations
	 */
	const struct librecrypt_algorithm *algos;

	/**
	 * The number of elements in `.algos`
	 */
	size_t nalgos;

	/**
	 * Per hash algorithm peppers
	 */
	struct pepper peppers[LIBRECRYPT_HASH_ALGORITHM_END];
	/* TODO we probably don't want slots allocated for
	 *      algorithms that have been disabled */
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
extern struct librecrypt_algorithm librecrypt_algorithms_[];

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
 * @param   ctx         Library configuration
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
                         const char *settings, LIBRECRYPT_CONTEXT *ctx, enum action action);


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
 * @param   ctx        Library configuration
 * @return             Pointer to the algorithm information,
 *                     `NULL` if not found
 * 
 * This function does not modify `errno`, but the
 * caller should usually set `errno` to `ENOSYS`
 * if this function returns `NULL`
 * 
 * This function is MT-Safe And AS-Safe
 */
LIBRECRYPT_READ_MEM__(1, 2) LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__ HIDDEN
const struct librecrypt_algorithm *librecrypt_find_first_algorithm_(const char *settings, size_t len,
                                                                    LIBRECRYPT_CONTEXT *ctx);


/**
 * Sets the pepper for a hash algorithm
 * 
 * @param   ctx   The library configuration object
 * @param   algo  The hash algorithm to apply the pepper to
 * @param   len   Pepper size to test support for, or 0 to not
 *                test (0 is always supported for algorithms that
 *                support pepper as it means no pepper)
 * @return        Pointer to the pepper configuration for
 *                `algo` in `ctx`; `NULL` on failure
 * 
 * @throws  ENOSYS  The hash algorithm `algo` is either not
 *                  recognised or was disabled at compile-time
 * @throws  ENOSUP  The hash algorithm `algo` does not support
 *                  peppers; the application is instead adviced
 *                  to, itself, append or prepend the pepper
 *                  to the password
 * @throws  EINVAL  The size of the pepper is unsupported
 *                  for the hash algorithm `algo`
 */
LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__ HIDDEN
struct pepper *librecrypt_get_pepper_(LIBRECRYPT_CONTEXT *ctx, enum librecrypt_hash_algorithm algo, size_t len);


/**
 * Create a gap in a buffer to write data to
 *
 * @param   state  The buffer to modify, see `struct concat_state` for more information
 * @param   len    The desired gap size
 * @return         The number of bytes available to write to; will be at most `len`
 *
 * The function will compare `len` against the remaining
 * buffer size and return how much of that is available
 * for writing to. At the same time, buffer position and
 * remainging size is update as if that much data was
 * written, `state->len` in increased by `len`, and the
 * buffer is NUL terminated. The caller must retrieve
 * the current buffer position, `state->buf` _before_ calling
 * this function, so that it knows where the write data to.
 *
 * Example:
 *     void copy(struct concat_state *state, const char *text, size_t len)
 *     {
 *         char *buf = state->buf;
 *         size_t n = librecrypt_concat_void_(state, len);
 *         if (n) memcpy(buf, text, n);
 *     }
 */
LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__ HIDDEN
inline size_t
librecrypt_concat_void_(struct concat_state *state, size_t len)
{
	size_t n = state->size ? MIN(state->size - 1u, len) : 0u;
	if (len > SIZE_MAX - state->len)
		abort(); /* TODO not covered */
	state->len += len;
	if (n) {
		state->buf = &state->buf[n];
		state->size -= n;
	}
	if (state->size)
		state->buf[0u] = '\0';
	return n;
}


/**
 * Concatenate two strings
 *
 * Truncation is done to ensure the resulting string
 * does not overrun it's buffer but is still NUL
 * terminated (assuming the buffer is not zero-sized)
 *
 * @param  state  The buffer to write to, see `struct concat_state` for more information
 * @param  text   The text to copy to the buffer
 * @param  len    The length of `text`, in bytes
 */
LIBRECRYPT_NONNULL_1__ LIBRECRYPT_READ_MEM__(2, 3) HIDDEN
inline void
librecrypt_concat_mem_(struct concat_state *state, const char *text, size_t len)
{
	char *buf = state->buf;
	size_t n = librecrypt_concat_void_(state, len);
	if (n)
		memcpy(buf, text, n);
}


/**
 * Concatenate two strings
 *
 * Truncation is done to ensure the resulting string
 * does not overrun it's buffer but is still NUL
 * terminated (assuming the buffer is not zero-sized)
 *
 * @param  state  The buffer to write to, see `struct concat_state` for more information
 * @param  text   The text to copy to the buffer
 */
LIBRECRYPT_NONNULL__ LIBRECRYPT_READ_STR__(2) HIDDEN
inline void
librecrypt_concat_str_(struct concat_state *state, const char *text)
{
	librecrypt_concat_mem_(state, text, strlen(text));
}


/**
 * Concatenate an unsigned integer onto a string
 *
 * The integer will be formated in decimal without
 * redundant noughts
 *
 * Truncation is done to ensure the resulting string
 * does not overrun it's buffer but is still NUL
 * terminated (assuming the buffer is not zero-sized)
 *
 * @param  state  The buffer to write to, see `struct concat_state` for more information
 * @param  value  The integer to write to the buffer
 */
LIBRECRYPT_NONNULL_1__ HIDDEN
void librecrypt_concat_uint_(struct concat_state *state, uintmax_t value);


/**
 * Concatenate a single chracter onto a string
 *
 * NB! NUL termination will not be added
 *
 * Truncation is done to ensure the resulting string
 * does not overrun it's buffer but is still has room
 * for NUL terminnation (assuming the buffer is not
 * zero-sized)
 *
 * @param  state  The buffer to write to, see `struct concat_state` for more information
 * @param  c      The character to append
 */
LIBRECRYPT_NONNULL_1__ HIDDEN
inline void
librecrypt_concat_char_no_nul_(struct concat_state *state, char c)
{
	if (state->len == SIZE_MAX)
		abort(); /* TODO not covered */
	state->len += 1u;
	if (state->size > 1u) {
		*state->buf++ = c;
		state->size -= 1u;
	}
}


/**
 * Adjust a `struct concat_state` has been modified by
 * another function
 *
 * This function will not by it self modify the buffer
 * in any way. It will not add NUL-termination. This
 * function will only update `*state` to reflect that
 * some function wanted to write `len` bytes (but may
 * have written less due to the buffer being to small).
 *
 * @param   state  The buffer to write to, see `struct concat_state` for more information
 * @param   len    the length of the concatenated data sans NUL-termination
 * @return         Normally 0, -1 if `state->len` would overflow
 *
 * The proper error code when this function returns -1 is
 * usually EOVERFLOW, however this function does not modify errno
 *
 * It is unspecified whether `state->buf` and `state->size` will
 * be updated when -1 is returned. It is also unspecified whether
 * `state->len` will be updated when -1 is returned.
 *
 * Precondition: `state->buf != NULL`
 */
LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__ HIDDEN
inline int
librecrypt_post_concat_adjust_(struct concat_state *state, size_t len)
{
	size_t n = state->size ? MIN(state->size - 1u, len) : 0u;
	state->buf = &state->buf[n];
	state->size -= n;
	if (state->len > SIZE_MAX - len)
		return -1;
	state->len += len;
	return 0;
}


/**
 * Get the base64-encoding length for some size of data
 *
 * @param   raw_len        The size of the data
 * @param   padded         Whether the base64-encoding shall be padded to a multiple of 4 bytes
 * @param   ascii_len_out  Output parameter for the length of the base64-encoding
 * @return                 Normally 1, 0 if the value for `*ascii_len_out` could not be represented
 *
 * The proper error code when this function returns 0 is
 * usually EOVERFLOW, however this function does not modify errno
 */
LIBRECRYPT_WUR__ LIBRECRYPT_NONNULL__ HIDDEN
inline int
librecrypt_raw_len_to_base64_len_(size_t raw_len, int padded, size_t *ascii_len_out)
{
	size_t q = raw_len / 3u;
	size_t r = raw_len % 3u;
	if (r) {
		if (padded)
			r = 4u; /* padding to for bytes */
		else
			r += 1u; /* 3n+m bytes: 4n+m+1 chars, unless m=0 */
	}
	if (q > (SIZE_MAX - r) / 4u)
		return 0;
	*ascii_len_out = q * 4u + r;
	return 1;
}


/**
 * Get the size of some data based on the length of its base64-encoding
 *
 * @param   ascii_len    The length of the data's unpadded base64-encoding
 * @param   raw_len_out  Output parameter for the size of the data
 * @return               Normally 1, 0 if `ascii_len` doesn't have proper
 *                       for a base64-encoding
 *
 * The proper error code when this function returns 0 is
 * usually EINVAL, however this function does not modify errno
 */
LIBRECRYPT_WUR__ LIBRECRYPT_NONNULL__ HIDDEN
inline int
librecrypt_base64_len_to_raw_len_(size_t ascii_len, size_t *raw_len_out)
{
	size_t q = ascii_len / 4u;
	size_t r = ascii_len % 4u;
	if (r == 1u)
		return 0;
	*raw_len_out = q * 3u;
	if (r)
		*raw_len_out += r - 1u;
	return 1;
}


/**
 * Check whether a base64-encoding is padded to a multiple
 * of 4 characters, without being excessively padded
 *
 * @param   unpadded_len  The length of the base64-encoding sans it's padding
 * @param   padded_len    The length of the base64-encoding including any present padding
 * @return                Whether the base64-encoding is appropriately padded
 *
 * Precondition: `padded_len >= unpadded_len`
 * Precondition: librecrypt_base64_len_to_raw_len_(unpadded_len, _) != 0 (i.e. `unpadded_len % 4u != 1u`)
 */
LIBRECRYPT_WUR__ CONST HIDDEN
inline int
librecrypt_is_base64_properly_padded_(size_t unpadded_len, size_t padded_len)
{
	if (padded_len % 4u)
		return 0;
	if (padded_len - unpadded_len >= 4u)
		return 0;
	return 1;
}


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
# include <stdio.h>
# include <stdlib.h>
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
