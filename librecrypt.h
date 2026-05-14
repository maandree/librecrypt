/* See LICENSE file for copyright and license details. */
#ifndef LIBRECRYPT_H
#define LIBRECRYPT_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


#if defined(__GNUC__)
# define LIBRECRYPT_PURE__ __attribute__((__pure__))
# define LIBRECRYPT_NONNULL__ __attribute__((__nonnull__))
# define LIBRECRYPT_NONNULL_I__(I) __attribute__((__nonnull__(I)))
# define LIBRECRYPT_WUR__ __attribute__((__warn_unused_result__))
#else
# define LIBRECRYPT_PURE__
# define LIBRECRYPT_NONNULL__
# define LIBRECRYPT_NONNULL_I__(I)
# define LIBRECRYPT_WUR__
#endif
#if defined(__GNUC__) && !defined(__clang__)
# define LIBRECRYPT_READ_STR__(S) __attribute__((__access__(read_only, S)))
# define LIBRECRYPT_READ_MEM__(B, N) __attribute__((__access__(read_only, B, N)))
# define LIBRECRYPT_WRITE_MEM__(B, N) __attribute__((__access__(write_only, B, N)))
# define LIBRECRYPT_READ_WRITE_STR__(S) __attribute__((__access__(read_write, S)))
#else
# define LIBRECRYPT_READ_STR__(S)
# define LIBRECRYPT_READ_MEM__(B, N)
# define LIBRECRYPT_WRITE_MEM__(B, N)
# define LIBRECRYPT_READ_WRITE_STR__(S)
#endif
#define LIBRECRYPT_NONNULL_1__ LIBRECRYPT_NONNULL_I__(1)

/* Silence clang's warnings for glibc */
#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
# pragma clang diagnostic ignored "-Wc11-extensions"
# pragma clang diagnostic ignored "-Wunsafe-buffer-usage" /* as well as this one, which is completely broken */
#endif


/**
 * Symbol used as a general delimiter
 */
#define LIBRECRYPT_HASH_COMPOSITION_DELIMITER '$'

/**
 * Symbol used to delimit algorithms in a chain
 */
#define LIBRECRYPT_ALGORITHM_LINK_DELIMITER '>'



/**
 * Get number of bytes in a password hash string
 * that make up the algorithm configuration
 * 
 * Some algorithms have flexible hash size which
 * is encoded either with an actual hash (its
 * length after decoding to binary is checked)
 * or using asterisk-notation in place of the
 * result (that is, as '*' followed by an unsigned,
 * decimal integer, which may have leading zeroes).
 * This part is always excluded (from the last
 * algorithm in the algorithm chain in `hash`) in
 * the return value.
 * 
 * @param   hash          The password hash string; must not be `NULL`
 * @param   hashsize_out  Unless `NULL`; if the hash size is fixed,
 *                        the value 0 is stored in the provided memory,
 *                        otherwise a non-zero value will be stored,
 *                        which is the number bytes in the output hash,
 *                        however if the a hash or hash size is not
 *                        available (in which case the function shall
 *                        return `strlen(hash)` if `hash` is properly
 *                        formatted) the value 0 is stored, indicating
 *                        that a default hash size shall be used
 * @return                The number of bytes, from the front of `hash`,
 *                        that make up the algorithm configuration; may be 0
 * 
 * For the return value `r`, `&hash[r]` points to the
 * hash result proper
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_STR__(1) LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__ LIBRECRYPT_PURE__
size_t librecrypt_settings_prefix(const char *hash, size_t *hashsize_out);


/**
 * Get the number of chained hash algorithms specified in
 * a password hash string
 * 
 * @param   hash  The password hash string; must not be `NULL`
 * @return        The number of chained hash algorithms; always non-zero
 * 
 * @seealso  librecrypt_decompose_chain
 * @seealso  librecrypt_decompose_chain1
 * @seealso  librecrypt_next_algorithm
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_STR__(1) LIBRECRYPT_NONNULL__ LIBRECRYPT_WUR__ LIBRECRYPT_PURE__
inline size_t
librecrypt_chain_length(const char *hash)
{
	size_t n = 1u;

	for (; *hash; hash++)
		if (*hash == LIBRECRYPT_ALGORITHM_LINK_DELIMITER)
			n += 1u;

	return n;
}


/**
 * Decompose the chain of hash algorithms specified in
 * a password hash string
 * 
 * @param    hash             The password hash string to decompose; may be modified; must not be `NULL`
 * @param    chain_out_array  Output array for the hash algorithms; each element will be an offset of `hash`
 * @param    size             The number of elements `chain_out_buffer` fit
 * @return                    The number of chained hashes (same as `librecrypt_chain_length(hash)`)
 * 
 * Algorithms are delimited using `LIBRECRYPT_ALGORITHM_LINK_DELIMITER`
 * (which is `'>'`). The first `size - 1u` occurences will be set to `NULL`.
 * `hash` can be restored by setting the terminating NUL byte in each but
 * the last string, that is stored to `chain_out_array`, to
 * `LIBRECRYPT_ALGORITHM_LINK_DELIMITER`
 * 
 * If positive `size` is smaller than the returned value,
 * `chain_out_array[size - 1u]` will contain all algorithms
 * (still delimited by `LIBRECRYPT_ALGORITHM_LINK_DELIMITER`)
 * that where not placed in earlier slots
 * 
 * Unless already stripped out before input,
 * `chain_out_array[size - 1u]` (provided that `size` is
 * positive) will end with the resulting hash
 * 
 * @seealso  librecrypt_chain_length
 * @seealso  librecrypt_decompose_chain1
 * @seealso  librecrypt_next_algorithm
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_WRITE_STR__(1) LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__
inline size_t
librecrypt_decompose_chain(char *hash, char **chain_out_array, size_t size)
{
	size_t n = 1u;

	if (size)
		chain_out_array[0u] = hash;

	for (; *hash; hash++) {
		if (*hash == LIBRECRYPT_ALGORITHM_LINK_DELIMITER) {
			if (n < size) {
				*hash = '\0';
				chain_out_array[n] = &hash[1u];
			}
			n += 1u;
		}
	}

	return n;
}


/**
 * Replace each `LIBRECRYPT_ALGORITHM_LINK_DELIMITER`
 * (which is `'>'`) in a password hash string with NUL
 * bytes, effectively decomposing it to one string per
 * hash algorithm, with the hashing result still attached
 * to the last one if it as in the string
 * 
 * @param   hash  The password hash string to decompose; may be modified; must not be `NULL`
 * @return        The number of chained hashes (same as `librecrypt_chain_length(hash)`)
 * 
 * @seealso  librecrypt_decompose_chain
 * @seealso  librecrypt_next_algorithm
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_WRITE_STR__(1) LIBRECRYPT_NONNULL__ LIBRECRYPT_WUR__
inline size_t
librecrypt_decompose_chain1(char *hash)
{
	size_t n = 1u;

	for (; *hash; hash++) {
		if (*hash == LIBRECRYPT_ALGORITHM_LINK_DELIMITER) {
			*hash = '\0';
			n += 1u;
		}
	}

	return n;
}


/**
 * This function is called repeatedly to get each
 * hash algorithm (with parameters) that shall
 * be chained together according to a provided
 * hash string
 * 
 * @param   hash  On the initial call, this argument shall point
 *                to the password hash string; on each call the
 *                function will update it to the current parsing
 *                state, meaning it will set `*hash` to point to
 *                an offset of `*hash` or point to `NULL`;
 *                additionally at each call, except on the final
 *                call, the string will be modified
 * @return        On the first call, this will be the first hash
 *                algorithm to use, and the second call it will
 *                be the second algorithm to use (if there is a
 *                second one), and so on. Once all algorithms have
 *                been extracted and returned, `NULL` is returned.
 * 
 * Except once the function has returned `NULL`, overwriting
 * the terminating NUL byte in the previous returned string
 * with `LIBRECRYPT_ALGORITHM_LINK_DELIMITER` (which is `'>'`)
 * will restore the password hash string to its original content
 * 
 * Unless already stripped out before input, the last returned
 * string will end with the resulting hash
 * 
 * @seealso  librecrypt_decompose_chain
 * @seealso  librecrypt_decompose_chain1
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_NONNULL__ LIBRECRYPT_WUR__
inline char *
librecrypt_next_algorithm(char **hash)
{
	char *ret;

	if (!*hash)
		return NULL;

	ret = *hash;
	*hash = strchr(*hash, LIBRECRYPT_ALGORITHM_LINK_DELIMITER);
	if (*hash)
		*(*hash)++ = '\0';
	return ret;
}


/**
 * Encode a hash result or salt in ASCII, from binary
 * 
 * This is the inverse of `librecrypt_decode`
 * 
 * @param   out_buffer  Output buffer for the ASCII representation
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   binary      The raw binary data to encode
 * @param   len         The number of bytes in `binary`
 * @param   lut         The encoding alphabet, consisting of 64 characters,
 *                      repeated 4 times
 * @param   pad         The padding character to use at the end; the NUL byte if none
 * @return              The number of bytes that would have been written to `out_buffer`,
 *                      excluding the terminating NUL byte, if `size` was sufficiently large
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and 1 in
 * excess of the return value (this count includes the
 * terminating NUL byte)
 * 
 * On successful completion, if `size` is positive,
 * the output to `out_buffer` is NUL terminated even
 * if this truncates the string
 * 
 * @seealso  librecrypt_get_encoding
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
size_t librecrypt_encode(char *out_buffer, size_t size, const void *binary, size_t len,
                         const char lut[restrict static 256], char pad);


/**
 * Decode a hash result or salt, from ASCII to binary
 * 
 * This is the inverse of `librecrypt_encode`
 * 
 * @param   out_buffer  Output buffer for the raw binary data
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   ascii       The ASCII encoding of the data, the text to decode
 * @param   len         The number of bytes in `ascii`
 * @param   lut         Alphabet reverse lookup table, shall map any valid
 *                      character (except the padding character) to the value
 *                      of that character in the encoding alphabet, and map
 *                      any other character to the value `0xFF`
 * @param   pad         The padding character to used at the end; the NUL byte if none
 * @param   strict_pad  Zero if the padding at the end is optional, non-zero otherwise
 * @return              The number of bytes that would have been written to `out_buffer`,
 *                      if `size` was sufficiently large, -1 on failure
 * 
 * @throws  EINVAL  `ascii` uses an invalid encoding
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and the
 * return value
 * 
 * @seealso  librecrypt_get_encoding
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_decode(void *out_buffer, size_t size, const char *ascii, size_t len,
                          const unsigned char lut[restrict static 256], char pad, int strict_pad);


/**
 * Get the ASCII (base-64) encoding used for the
 * last algorithm in a chain
 * 
 * @param   settings        The algorithm chain
 * @param   len             The number of bytes in `settings`
 * @param   pad_out         Output parameter for the padding character,
 *                          will be set to the NUL byte if there is none
 * @param   strict_pad_out  Set to 1 if encodings must be padded to a
 *                          multiple of 4 bytes using `*pad_out` at the end,
 *                          0 otherwise; set arbitrarily if `*pad_out` is
 *                          set to the NUL byte
 * @param   decoding        0 if the returned pointer should be useful for,
 *                          `librecrypt_encode`, otherwise it will be useful
 *                          for `librecrypt_decode`
 * @return                  If `decoding` is 0:
 *                             the encoding alphabet, consisting of 64 characters,
 *                             repeated 4 times;
 *                          otherwise:
 *                             alphabet reverse lookup table, mapping any valid
 *                             character (except the padding character) to the
 *                             value of that character in the encoding alphabet,
 *                             and any other character to the value `0xFF`;
 *                          but `NULL` on failure
 * 
 * @throws  ENOSYS  The last algorithm in `settings` is not recognised
 *                  or was disabled at compile-time
 * 
 * The return type is `const char *` if `decoding` is 0,
 * and `const unsigned char *` otherwise
 * 
 * `*pad_out` shall be used for the `pad` parameter of the `librecrypt_encode`
 * and `librecrypt_decode` functions, however the NUL byte may also be used
 * for the `librecrypt_encode` function if `*strict_pad_out` is set to 0
 * 
 * `*strict_pad_out` shall be used for the `strict_pad` parameter of the
 * `librecrypt_decode` function
 * 
 * The returned pointer (unless `NULL`) shall be used for the `lut` parameter
 * of the `librecrypt_encode` function if `decoding` is 0, and for the `lut`
 * parameter of the `librecrypt_decode` function otherwise
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_STR__(1) LIBRECRYPT_NONNULL__ LIBRECRYPT_WUR__
const void *librecrypt_get_encoding(const char *settings, size_t len, char *pad_out,
                                    int *strict_pad_out, int decoding);


/**
 * Securely erase a memory buffer
 * 
 * @param  buffer  The memory to erase
 * @param  size    The number of bytes in `buffer` to erase
 * 
 * @seealso  librecrypt_wipe_str
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_WRITE_MEM__(1, 2)
void librecrypt_wipe(void *buffer, size_t size);


/**
 * Securely erase a string
 * 
 * @param  string  The string to erase
 * 
 * @seealso  librecrypt_wipe
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_WRITE_STR__(1)
inline void
librecrypt_wipe_str(char *string)
{
	if (string)
		librecrypt_wipe(string, strlen(string));
}


/**
 * Compare two memory segments in constant-time
 * 
 * @param   a    One of the segments to compare
 * @param   b    The other segments to compare
 * @param   len  The number of bytes to compare
 * @return       1 if the `a` and `b` are equal in their
 *               first `len` bytes, 0 otherwise
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_MEM__(1, 3) LIBRECRYPT_READ_MEM__(2, 3) LIBRECRYPT_WUR__
int librecrypt_equal_binary(const void *a, const void *b, size_t len);


/**
 * Compare two strings in constant-time
 * 
 * If the strings are of different length,
 * it will stop immediately after measurement;
 * this should not happen in the real world as
 * this function is used to compare password
 * hashes, whose length depends strictly on the
 * configuration, not the input password
 * 
 * @param   a  One of the strings to compare
 * @param   b  The other string to compare
 * @return     1 if the `a` and `b` are equal, 0 otherwise
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_STR__(1) LIBRECRYPT_READ_STR__(2) LIBRECRYPT_WUR__ LIBRECRYPT_NONNULL__
inline int
librecrypt_equal(const char *a, const char *b)
{
	size_t n = strlen(a);
	size_t m = strlen(b);
	return n == m && librecrypt_equal_binary(a, b, n);
}


/**
 * Locate all asteriskes followed by a non-negative
 * decimal number and replace each with ASCII-encded
 * random bytes (as many bytes as the number specifies),
 * except those used to specify the desired hash size
 * 
 * @param   out_buffer  Output buffer for the ASCII representation
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   settings    The string to replace the asterisk-encoding in
 *                      (the asterisk-free version is written to `out_buffer`)
 * @param   rng         Random number generating function, `NULL` can be used
 *                      for a default cryptographic random number generator;
 *                      the function shall generate between 1 and `n` (inclusively)
 *                      bytes and write them to the front of `out`, and return
 *                      the number of generated bytes, or -1 on failure
 * @param   user        Passed as the third argument to `*rng` for user-defined
 *                      purposes, ignored if `rng` is `NULL`
 * @return              The number of bytes that would have been written to `out_buffer`,
 *                      if `size` was sufficiently large, -1 on failure
 * @throws  ERANGE      The expected return value is greater than {SSIZE_MAX}
 * @throws  ENOSYS      `settings` contain an algorithm that is not recognised
 *                      or was disabled at compile-time
 * 
 * If `rng` is `NULL`, any encountered `EINTR` is ignored,
 * however, if it is encountered `errno` will be set to `EINTR`,
 * but `errno` will remain unmodified otherwise, except if
 * the function fails due to one of the above listed reasons
 * 
 * Failure can only happen through `*rng`, it is
 * responsible for setting `errno` if desired, or
 * because of the conditions listed above`
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and 1 in
 * excess of the return value (this count includes the
 * terminating NUL byte)
 * 
 * On successful completion, if `size` is positive,
 * the output to `out_buffer` is NUL terminated even
 * if this truncates the string
 * 
 * On failure, `out_buffer` may be partially written
 * 
 * The encoding depend on the algorithm, which is why
 * it can fail with `ENOSYS`
 * 
 * When `rng` is non-`NULL`, this function inherits any
 * MT-Unsafe and AS-Unsafe properties from `*rng`, being
 * is MT-Safe and AS-Safe as a baseline; however when
 * `rng` is `NULL`, this function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_WUR__
ssize_t librecrypt_realise_salts(char *restrict out_buffer, size_t size, const char *settings,
                                 ssize_t (*rng)(void *out, size_t n, void *user), void *user);


/**
 * Generate a password hash setting string
 * 
 * @param   out_buffer  Output buffer for the ASCII representation
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   algorithm   Hash algorithm string; it need not specify any parameters
 *                      however any unspecified parameter that cannot be determined
 *                      by `memcost` or `timecost` will be set to an arbitrary,
 *                      valid value. If `NULL`, a default, strong algorithm is
 *                      selected. Note that the empty string represents the
 *                      deprecated DES algorithm. Algorithm chains are disallowed.
 * @param   memcost     Approximate memory cost in bytes, ignored if not supported;
 *                      a default value is selected if 0 is specified
 * @param   timecost    Total time cost, in an arbitrary, algorithm-dependent,
 *                      implementation-dependent, monotonic (may have flat sections)
 *                      unit and scale that is approximately linear; a default value
 *                      is selected if 0 is specified
 * @param   gensalt     Zero if salts shall specified to be randomly generated
 *                      (reusable password hash setting string),
 *                      non-zero if random salts shall be included in the generated
 *                      output (non-reusable password hash setting string)
 * @param   rng         Random number generating function, `NULL` can be used
 *                      for a default cryptographic random number generator;
 *                      the function shall generate between 1 and `n` (inclusively)
 *                      bytes and write them to the front of `out`, and return
 *                      the number of generated bytes, or -1 on failure;
 *                      ignored if `gensalt` is zero
 * @param   user        Passed as the third argument to `*rng` for user-defined
 *                      purposes, ignored if `rng` is `NULL` or if `gensalt` is zero
 * @return              The number of bytes that would have been written to
 *                      `out_buffer`, if `size` was sufficiently large, -1 on failure
 * 
 * @throws  EINVAL  `algorithm` represents a chain of algorithms
 * @throws  ENOSYS  `algorithm` represents an algorithm that is not
 *                  recognised or was disabled at compile-time
 * @throws  ENOSYS  `algorithm` is `NULL` but all algorithms were
 *                  disabled at compile-time
 * 
 * If `rng` is `NULL`, any encountered `EINTR` is ignored,
 * however, if it is encountered `errno` will be set to `EINTR`,
 * but `errno` will remain unmodified otherwise, except if
 * the function fails due to `EINVAL` or `ENOSYS`
 * 
 * Failure can only happen through `*rng`, it is
 * responsible for setting `errno` if desired, or
 * because of the conditions for `EINVAL` or `ENOSYS`
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and 1 in
 * excess of the return value (this count includes the
 * terminating NUL byte)
 * 
 * On successful completion, if `size` is positive,
 * the output to `out_buffer` is NUL terminated even
 * if this truncates the string
 * 
 * On failure, `out_buffer` may be partially written
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_WUR__
ssize_t librecrypt_make_settings(char *out_buffer, size_t size, const char *algorithm,
                                 size_t memcost, uintmax_t timecost, int gensalt,
                                 ssize_t (*rng)(void *out, size_t n, void *user), void *user);


/**
 * Compute the hash of a password
 * 
 * The hash will be stored in raw binary format without any settings
 * 
 * @param   out_buffer  Output buffer for the hash result
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   phrase      The password to hash, may contain NUL bytes
 * @param   len         The number of bytes in `phrase`
 * @param   settings    The password hash configuration string,
 *                      may contain resulting hash, which will be ignored
 * @param   reserved    Reserved for future use, should be `NULL`
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large; -1 on failure
 * 
 * @throws  EINVAL  `reserved` is non-`NULL` (this case will be removed
 *                  once `reserved` as being used by the library)
 * @throws  EINVAL  `settings` is invalid (invalid algorithm configuration,
 *                  invalid configuration syntax, or the output from one
 *                  chained hash algorithm cannot be input the next algorithm
 *                  in the chain (either because of format or length issues))
 * @throws  EINVAL  `settings` uses asterisk-encoding to specify random salts
 * @throws  ERANGE  `len` is too large or too small for the the selected
 *                  initial algorithm in the algorithm chain
 * @throws  ENOMEM  Failed to allocate internal scratch memory
 * @throws  ENOSYS  A selected hash algorithm is either not recognised
 *                  disabled at compile-time
 * 
 * Any encountered `EINTR` is ignored
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and the
 * return value
 * 
 * On failure, `out_buffer` will remain unmodified
 * 
 * @seealso  librecrypt_hash
 * @seealso  librecrypt_crypt
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_READ_STR__(5)
LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_hash_binary(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                               const char *settings, void *reserved);


/**
 * Compute the hash of a password
 * 
 * The hash will be encoded with `librecrypt_encode`
 * but stored without any settings
 * 
 * @param   out_buffer  Output buffer for the hash result
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   phrase      The password to hash, may contain NUL bytes
 * @param   len         The number of bytes in `phrase`
 * @param   settings    The password hash configuration string,
 *                      may contain resulting hash, which will be ignored
 * @param   reserved    Reserved for future use, should be `NULL`
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte; -1 on failure
 * 
 * @throws  EINVAL  `reserved` is non-`NULL` (this case will be removed
 *                  once `reserved` as being used by the library)
 * @throws  EINVAL  `settings` is invalid (invalid algorithm configuration,
 *                  invalid configuration syntax, or the output from one
 *                  chained hash algorithm cannot be input the next algorithm
 *                  in the chain (either because of format or length issues))
 * @throws  EINVAL  `settings` uses asterisk-encoding to specify random salts
 * @throws  ERANGE  `len` is too large or too small for the the selected
 *                  initial algorithm in the algorithm chain
 * @throws  ENOMEM  Failed to allocate internal scratch memory
 * @throws  ENOSYS  A selected hash algorithm is either not recognised
 *                  disabled at compile-time
 * 
 * Any encountered `EINTR` is ignored
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and 1 in
 * excess of the return value (this count includes the
 * terminating NUL byte)
 * 
 * On successful completion, if `size` is positive,
 * the output to `out_buffer` is NUL terminated even
 * if this truncates the string
 * 
 * On failure, `out_buffer` will remain unmodified
 * 
 * @seealso  librecrypt_hash_binary
 * @seealso  librecrypt_crypt
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_READ_STR__(5)
LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                        const char *settings, void *reserved);


/**
 * Compute the hash of a password
 * 
 * The hash will be encoded with `librecrypt_encode`;
 * and the settings will be included in the front
 * 
 * @param   out_buffer  Output buffer for the hash result
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   phrase      The password to hash, may contain NUL bytes
 * @param   len         The number of bytes in `phrase`
 * @param   settings    The password hash configuration string,
 *                      may contain resulting hash, which will be ignored
 * @param   reserved    Reserved for future use, should be `NULL`
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte; -1 on failure
 * 
 * @throws  EINVAL  `reserved` is non-`NULL` (this case will be removed
 *                  once `reserved` as being used by the library)
 * @throws  EINVAL  `settings` is invalid (invalid algorithm configuration,
 *                  invalid configuration syntax, or the output from one
 *                  chained hash algorithm cannot be input the next algorithm
 *                  in the chain (either because of format or length issues))
 * @throws  ERANGE  `len` is too large or too small for the the selected
 *                  initial algorithm in the algorithm chain
 * @throws  ENOMEM  Failed to allocate internal scratch memory
 * @throws  ENOSYS  A selected hash algorithm is either not recognised
 *                  disabled at compile-time
 * 
 * Any encountered `EINTR` is ignored
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and 1 in
 * excess of the return value (this count includes the
 * terminating NUL byte)
 * 
 * On successful completion, if `size` is positive,
 * the output to `out_buffer` is NUL terminated even
 * if this truncates the string
 * 
 * On failure, `out_buffer` may be partially written
 * 
 * @seealso  librecrypt_hash_binary
 * @seealso  librecrypt_hash
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_READ_STR__(5)
LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_crypt(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                         const char *settings, void *reserved);


/**
 * Check whether a hash algorithm chain is supported,
 * for the given input, and that each algorithm
 * configuration is valid
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
 * @return            1 if the configuration is supported, 0 otherwise, which
 *                    means part of the string is invalid: the algorithm does
 *                    not exist, supported was disabled at compile-time, or an
 *                    algorithm it does not support the output of the previous
 *                    algorithm in the chain as input; additionally a small
 *                    number of legacy algorithms require the passphrase to
 *                    be within a specific length range or be valid text,
 *                    if the selected word does not match such constraints
 *                    for the first algorithm in the chain, 0 is returned
 * 
 * This function is MT-Safe and AS-Safe
 */
LIBRECRYPT_READ_STR__(4) LIBRECRYPT_NONNULL_I__(4) LIBRECRYPT_WUR__
int librecrypt_test_supported(const char *phrase, size_t len, int text, const char *settings);


/**
 * Chain togather another set of hash algorithms
 * 
 * If you are using the `librecrypt_crypt` format,
 * you just run this function over the password hash
 * string to get the augmented one with an updated
 * hash, however if you are using `librecrypt_hash`
 * or `librecrypt_hash_binary`, you must also (since
 * `augend` would not contain the hash result) run
 * `librecrypt_hash` or `librecrypt_hash_binary` over
 * the old hash result with `augment` as the `settings`
 * argument to get the new hash result
 * 
 * @param   out_buffer  Output buffer for the new password hash string
 * @param   size        The number bytes the function may write to `out_buffer`
 * @param   augend      THe existing password hash string; if it contains a
 *                      hash result, a new hash result will be computed and
 *                      any random number generation specification in `augment`
 *                      will be realised
 * @param   augment     Password hash setting string describing the additional
 *                      hashing to perform; if it contains a hash result, that
 *                      part will be ignored
 * @param   reserved    Reserved for future use, should be `NULL`
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte; -1 on failure
 * 
 * @throws  EINVAL  `reserved` is non-`NULL` (this case will be removed
 *                  once `reserved` as being used by the library)
 * @throws  EINVAL  `settings` is invalid (invalid algorithm configuration,
 *                  invalid configuration syntax, or the output from one
 *                  chained hash algorithm cannot be input the next algorithm
 *                  in the chain (either because of format or length issues))
 * @throws  ERANGE  `len` is too large or too small for the the selected
 *                  initial algorithm in the algorithm chain
 * @throws  ENOMEM  Failed to allocate internal scratch memory
 * @throws  ENOSYS  A selected hash algorithm is either not recognised
 *                  disabled at compile-time
 * 
 * On successful completion, the N bytes is written to
 * `out_buffer` where N is the lesser of `size` and 1 in
 * excess of the return value (this count includes the
 * terminating NUL byte)
 * 
 * On successful completion, if `size` is positive,
 * the output to `out_buffer` is NUL terminated even
 * if this truncates the string
 * 
 * On failure, `out_buffer` will remain unmodified
 * 
 * This function is MT-Safe but AS-Unsafe
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_READ_STR__(4)
LIBRECRYPT_NONNULL_I__(3) LIBRECRYPT_NONNULL_I__(4) LIBRECRYPT_WUR__
ssize_t librecrypt_add_algorithm(char *out_buffer, size_t size, const char *augend,
                                 const char *restrict augment, void *reserved);


#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#endif
