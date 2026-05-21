/* See LICENSE file for copyright and license details. */
#ifndef LIBRECRYPT_H
#define LIBRECRYPT_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


#if defined(__GNUC__)
# define LIBRECRYPT_PURE__ __attribute__((__pure__))
# define LIBRECRYPT_CONST__ __attribute__((__const__))
# define LIBRECRYPT_NONNULL__ __attribute__((__nonnull__))
# define LIBRECRYPT_NONNULL_I__(I) __attribute__((__nonnull__(I)))
# define LIBRECRYPT_WUR__ __attribute__((__warn_unused_result__))
#else
# define LIBRECRYPT_PURE__
# define LIBRECRYPT_CONST__
# define LIBRECRYPT_NONNULL__
# define LIBRECRYPT_NONNULL_I__(I)
# define LIBRECRYPT_WUR__
#endif
#if defined(__GNUC__) && !defined(__clang__)
# define LIBRECRYPT_READ_STR__(S) __attribute__((__access__(read_only, S)))
# define LIBRECRYPT_READ_MEM__(B, N) __attribute__((__access__(read_only, B, N)))
# define LIBRECRYPT_WRITE_MEM__(B, N) __attribute__((__access__(write_only, B, N)))
# define LIBRECRYPT_READ_WRITE_STR__(S) __attribute__((__access__(read_write, S)))
# define LIBRECRYPT_MALLOC__(D, D_ARG) __attribute__((__malloc__(D, D_ARG)))
#else
# define LIBRECRYPT_READ_STR__(S)
# define LIBRECRYPT_READ_MEM__(B, N)
# define LIBRECRYPT_WRITE_MEM__(B, N)
# define LIBRECRYPT_READ_WRITE_STR__(S)
# define LIBRECRYPT_MALLOC__(D, D_ARG)
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
 * 
 * @since  1.0
 */
#define LIBRECRYPT_HASH_COMPOSITION_DELIMITER '$'

/**
 * Symbol used to delimit algorithms in a chain
 * 
 * @since  1.0
 */
#define LIBRECRYPT_ALGORITHM_LINK_DELIMITER '>'



/**
 * Opaque structure for library tweaking
 *
 * @seealso  librecrypt_create_context
 * 
 * @since  1.1
 */
typedef struct librecrypt_context LIBRECRYPT_CONTEXT;


/**
 * Hash algorithms that the library might support
 * 
 * @seealso  librecrypt_hash_algorithm_end
 * 
 * @since  1.1
 */
enum librecrypt_hash_algorithm {
	/**
	 * Argon2i, version 1.0 ("$argon2i$v=13$", optionally without "$v=13")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2I_V1_0,

	/**
	 * Argon2i, version 1.3 ("$argon2i$v=19$")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2I_V1_3,

	/**
	 * Argon2d, version 1.0 ("$argon2d$v=13$", optionally without "$v=13")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2D_V1_0,

	/**
	 * Argon2d, version 1.3 ("$argon2d$v=19$")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2D_V1_3,

	/**
	 * Argon2id, version 1.0 ("$argon2id$v=13$", optionally without "$v=13")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2ID_V1_0,

	/**
	 * Argon2id, version 1.3 ("$argon2id$v=19$")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2ID_V1_3,

	/**
	 * Argon2ds, version 1.0 ("$argon2ds$v=13$", optionally without "$v=13")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2DS_V1_0,

	/**
	 * Argon2ds, version 1.3 ("$argon2ds$v=19$")
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_ARGON2DS_V1_3,

	/** - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - **/

	/**
	 * Marks the end of this enum, so you can iterate over it
	 * 
	 * @since  1.1
	 */
	LIBRECRYPT_HASH_ALGORITHM_END
};


/**
 * Hash algorithm information and implementation
 *
 * This is provided so you can implement custom
 * hash algorithms; must user's will not need this
 * 
 * Current limitations:
 * 
 * -  The algorithm must not use the '*' symbol except
 *    in the way the librecrypt library uses '*' for
 *    specifying sizes, in bytes (after base64-decoding),
 *    of randomised data (salt) and the hash result
 * 
 * -  The algorithm must not use the '>' symbol
 * 
 * -  The hash must be att the end, immediately after
 *    the last '$' (some expections exists for legacy
 *    hash algorithms), and empty must be usable to
 *    specify default hash size
 * 
 * -  Salts and hashes must be encoded in some variant
 *    of base64 where the bytes (represented with the
 *    most significant bit first) a₇a₆a₅a₄a₃a₂a₁a₀,
 *    b₇b₆b₅b₄b₃b₂b₁b₀, and c₇c₆c₅c₄c₃c₂c₁c₀ are
 *    rearranged to a₇a₆a₅a₄a₃a₂, a₁a₀b₇b₆b₅b₄,
 *    b₃b₂b₁b₀c₇c₆, c₅c₄c₃c₂c₁c₀, and missing bits
 *    are set to 0; and padding if supported at all,
 *    is only allowed, up to 3 pad letters, at the
 *    end to pad the output to a multiple of 4 letters
 * 
 * @since  1.1
 */
struct librecrypt_algorithm {
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
	 * @param   ctx         See `librecrypt_hash_binary`
	 * @return              0 on success, -1 on failure
	 * @throws              See `librecrypt_hash_binary`
	 * 
	 * This function shall be MT-Safe but may be AS-Unsafe
	 */
	int (*hash)(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
	            const char *settings, size_t prefix, LIBRECRYPT_CONTEXT *ctx);

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
	int (*test_supported)(const char *phrase, size_t len, int text, const char *settings,
	                      size_t prefix, size_t *len_out);

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
	 * @param   rng         See `librecrypt_make_settings`,
	 *                      except the function will not be called
	 *                      with `rng` set to `NULL`
	 * @param   user        See `librecrypt_make_settings`
	 * @return              See `librecrypt_make_settings`
	 * @throws              See `librecrypt_make_settings`
	 * 
	 * This function shall be MT-Safe but may be AS-Safe
	 */
	ssize_t (*make_settings)(char *out_buffer, size_t size, const char *algorithm,
	                         size_t memcost, uintmax_t timecost, int gensalt,
	                         ssize_t (*rng)(void *out, size_t n, void *user), void *user);

	/**
	 * Expected argument for the `lut` parameter
	 * of the `librecrypt_encode` function
	 * 
	 * This shall repeat a 64 character ASCII
	 * alphabet 4 times
	 */
	const char *encoding_lut;

	/**
	 * Expected argument for the `lut` parameter
	 * of the `librecrypt_decode` function
	 * 
	 * This shall unique map the letters in
	 * `.encoding_lut` to there initial position
	 * in `.encoding_lut` (that's, uniquely to
	 * the range [0, 63]). All other bytes
	 * (including `.pad`) shall map to `0xFFu`
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
	 * 
	 * Shall be either 1 (always pad when encoding,
	 * and require padding when decoding) or 0
	 * (do not pad when encoding, but allow padding
	 * (provided that `.pad != 0`) when decoding)
	 */
	signed char strict_pad;

	/**
	 * Expected argument for the `pad` parameter
	 * of the `librecrypt_decode` function
	 *
	 * The pad character, used to pad base64-encoding
	 * to a multiple of 4 letters, shall be `'\0'` if
	 * not specified
	 */
	char pad;
};


/**
 * The value `LIBRECRYPT_HASH_ALGORITHM_END` as in the
 * version of the library the application is linked against
 * (rather than compiled against)
 * 
 * @since  1.1
 */
extern const enum librecrypt_hash_algorithm librecrypt_hash_algorithm_end;


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
 * @param   ctx           Library configuration
 * @return                The number of bytes, from the front of `hash`,
 *                        that make up the algorithm configuration; may be 0
 * 
 * For the return value `r`, `&hash[r]` points to the
 * hash result proper
 * 
 * This function is MT-Safe and AS-Safe
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`
 */
LIBRECRYPT_READ_STR__(1) LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__ LIBRECRYPT_PURE__
size_t librecrypt_settings_prefix(const char *hash, size_t *hashsize_out, LIBRECRYPT_CONTEXT *ctx);


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
 * 
 * @since  1.0
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
 * 
 * @since  1.0
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
 * 
 * @since  1.0
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
 * 
 * @since  1.0
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
 * @return  len_out     The number of bytes that would have been written to `out_buffer`,
 *                      excluding the terminating NUL byte, if `size` was sufficiently
 *                      large; `SIZE_MAX` is returned on failure
 * 
 * @throws  EOVERFLOW  The for value `*len_out` cannot be represented
 *                     because it is greater than `SIZE_MAX` (`len` is
 *                     too great)
 * 
 * Despite being used as the failure indicator, `SIZE_MAX`
 * is a legal return value on successful, is and returned
 * (without modifying `errno`) when `pad` is the NUL byte
 * and `len` is (`SIZE_MAX` - 3) / 4 * 3 + 2
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
 * 
 * @since  1.0
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
 * 
 * @since  1.0
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
 * @param   ctx             Library configuration
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
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_READ_STR__(1) LIBRECRYPT_NONNULL_I__(1) LIBRECRYPT_NONNULL_I__(3)
LIBRECRYPT_NONNULL_I__(4) LIBRECRYPT_WUR__
const void *librecrypt_get_encoding(const char *settings, size_t len, char *pad_out,
                                    int *strict_pad_out, int decoding, LIBRECRYPT_CONTEXT *ctx);


/**
 * Securely erase a memory buffer
 * 
 * @param  buffer  The memory to erase
 * @param  size    The number of bytes in `buffer` to erase
 * 
 * @seealso  librecrypt_wipe_str
 * 
 * This function is MT-Safe and AS-Safe
 * 
 * @since  1.0
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
 * 
 * @since  1.0
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
 * @seealso  librecrypt_equal
 * @seealso  librecrypt_verify
 * 
 * This function is MT-Safe and AS-Safe
 * 
 * @since  1.0
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
 * @seealso  librecrypt_equal_binary
 * @seealso  librecrypt_verify
 * 
 * This function is MT-Safe and AS-Safe
 * 
 * @since  1.0
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
 * @param   ctx         Library configuration
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
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_WUR__
ssize_t librecrypt_realise_salts(char *restrict out_buffer, size_t size, const char *settings,
                                 ssize_t (*rng)(void *out, size_t n, void *user), void *user,
                                 LIBRECRYPT_CONTEXT *ctx);


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
 * @param   ctx         Library configuration
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
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_WUR__
ssize_t librecrypt_make_settings(char *out_buffer, size_t size, const char *algorithm,
                                 size_t memcost, uintmax_t timecost, int gensalt,
                                 ssize_t (*rng)(void *out, size_t n, void *user), void *user,
                                 LIBRECRYPT_CONTEXT *ctx);


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
 * @param   ctx         Library configuration
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large; -1 on failure
 * 
 * @throws  EINVAL     `settings` is invalid (invalid algorithm configuration,
 *                     invalid configuration syntax, or the output from one
 *                     chained hash algorithm cannot be input the next algorithm
 *                     in the chain (either because of format or length issues))
 * @throws  EINVAL     `settings` uses asterisk-encoding to specify random salts
 * @throws  ERANGE     `len` is too large or too small for the the selected
 *                     initial algorithm in the algorithm chain
 * @throws  EOVERFLOW  The expected return value is greater than {SSIZE_MAX}
 * @throws  ENOMEM     Failed to allocate internal scratch memory
 * @throws  ENOSYS     A selected hash algorithm is either not recognised
 *                     disabled at compile-time
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
 * @seealso  librecrypt_verify
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe but AS-Unsafe
 * 
 * @since  1.0  Initial version
 * @since  1.1  First parameter is `void *` rather than `char *`
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_READ_STR__(5)
LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_hash_binary(void *restrict out_buffer, size_t size, const char *phrase,
                               size_t len, const char *settings, LIBRECRYPT_CONTEXT *ctx);


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
 * @param   ctx         Library configuration
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte; -1 on failure
 * 
 * @throws  EINVAL     `settings` is invalid (invalid algorithm configuration,
 *                     invalid configuration syntax, or the output from one
 *                     chained hash algorithm cannot be input the next algorithm
 *                     in the chain (either because of format or length issues))
 * @throws  EINVAL     `settings` uses asterisk-encoding to specify random salts
 * @throws  ERANGE     `len` is too large or too small for the the selected
 *                     initial algorithm in the algorithm chain
 * @throws  EOVERFLOW  The expected return value is greater than {SSIZE_MAX}
 * @throws  ENOMEM     Failed to allocate internal scratch memory
 * @throws  ENOSYS     A selected hash algorithm is either not recognised
 *                     disabled at compile-time
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
 * @seealso  librecrypt_verify
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe but AS-Unsafe
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_READ_STR__(5)
LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                        const char *settings, LIBRECRYPT_CONTEXT *ctx);


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
 * @param   ctx         Library configuration
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte; -1 on failure
 * 
 * @throws  EINVAL     `settings` is invalid (invalid algorithm configuration,
 *                     invalid configuration syntax, or the output from one
 *                     chained hash algorithm cannot be input the next algorithm
 *                     in the chain (either because of format or length issues))
 * @throws  ERANGE     `len` is too large or too small for the the selected
 *                     initial algorithm in the algorithm chain
 * @throws  EOVERFLOW  The expected return value is greater than {SSIZE_MAX}
 * @throws  ENOMEM     Failed to allocate internal scratch memory
 * @throws  ENOSYS     A selected hash algorithm is either not recognised
 *                     disabled at compile-time
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
 * @seealso  librecrypt_verify
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe but AS-Unsafe
 * 
 * @since  1.0
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_MEM__(3, 4) LIBRECRYPT_READ_STR__(5)
LIBRECRYPT_NONNULL_I__(5) LIBRECRYPT_WUR__
ssize_t librecrypt_crypt(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                         const char *settings, LIBRECRYPT_CONTEXT *ctx);


/**
 * Compare a password against a hash
 * 
 * @param   phrase      The password to hash, may contain NUL bytes
 * @param   len         The number of bytes in `phrase`
 * @param   settings    The password hash configuration string,
 *                      may contain resulting hash, which will be ignored
 * @param   ctx         Library configuration
 * @return              1 if the password is correct and 0 if the password
 *                      is incorrect; -1 on failure
 * 
 * @throws  EINVAL     `settings` is invalid (invalid algorithm configuration,
 *                     invalid configuration syntax, or the output from one
 *                     chained hash algorithm cannot be input the next algorithm
 *                     in the chain (either because of format or length issues))
 * @throws  EINVAL     `settings` uses asterisk-encoding to specify random salts
 * @throws  EINVAL     `settings` uses asterisk-encoding in place of a hash result
 * @throws  EINVAL     `settings` contains no hash result
 * @throws  ERANGE     `len` is too large or too small for the the selected
 *                     initial algorithm in the algorithm chain
 * @throws  ENOMEM     Failed to allocate internal scratch memory
 * @throws  ENOSYS     A selected hash algorithm is either not recognised
 *                     disabled at compile-time
 * 
 * Any encountered `EINTR` is ignored
 * 
 * @seealso  librecrypt_hash_binary
 * @seealso  librecrypt_hash
 * @seealso  librecrypt_crypt
 * @seealso  librecrypt_equal
 * @seealso  librecrypt_equal_binary
 * 
 * This function is MT-Safe but AS-Unsafe
 * 
 * @since  1.1
 */
LIBRECRYPT_READ_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_NONNULL_I__(3) LIBRECRYPT_WUR__
int librecrypt_verify(const char *phrase, size_t len, const char *settings, LIBRECRYPT_CONTEXT *ctx);


/**
 * Check whether a hash algorithm chain is supported,
 * for the given input, and that each algorithm
 * configuration is valid
 * 
 * @param   phrase     The password to hash, may contain NUL bytes;
 *                     may be `NULL` even if `len` is non-zero
 * @param   len        The number of bytes in `phrase`, if `phrase` is `NULL`,
 *                     the function will check that the specified number of
 *                     bytes is supported as well as any byte sequence unless
 *                     `text` is non-zero
 * @param   text       Assume the password is valid UTF-8 text (without NUL bytes)
 *                     iff non-zero; ignored if `phrase` is non-`NULL`
 * @param   settings   The password hash string; it is allowed for algorithm
 *                     tuning parameters, and the hash result, to be omitted
 * @param   ctx        Library configuration
 * @return             1 if the configuration is supported, 0 otherwise, which
 *                     means part of the string is invalid: the algorithm does
 *                     not exist, supported was disabled at compile-time, or an
 *                     algorithm it does not support the output of the previous
 *                     algorithm in the chain as input; additionally a small
 *                     number of legacy algorithms require the passphrase to
 *                     be within a specific length range or be valid text,
 *                     if the selected word does not match such constraints
 *                     for the first algorithm in the chain, 0 is returned
 * 
 * @seealso  librecrypt_is_enabled
 * 
 * This function is MT-Safe and AS-Safe
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_READ_STR__(4) LIBRECRYPT_NONNULL_I__(4) LIBRECRYPT_WUR__
int librecrypt_test_supported(const char *phrase, size_t len, int text, const char *settings, LIBRECRYPT_CONTEXT *ctx);


/**
 * Check whether the library has been compiled to
 * support a specific hash algorithm
 *
 * @param   algo  The hash algorithm
 * @return        1 if the hash algorithm is enabled, 0 otherwise
 * 
 * @seealso  librecrypt_test_supported
 * 
 * This function is MT-Safe and AS-Safe
 * 
 * @since  1.1
 */
LIBRECRYPT_CONST__ LIBRECRYPT_WUR__
int librecrypt_is_enabled(enum librecrypt_hash_algorithm algo);


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
 * @param   ctx         Library configuration
 * @return              The number of bytes that would have been written to `out_buffer`
 *                      if `size` was sufficiently large, excluding a terminating
 *                      NUL byte; -1 on failure
 * 
 * @throws  EINVAL     `settings` is invalid (invalid algorithm configuration,
 *                     invalid configuration syntax, or the output from one
 *                     chained hash algorithm cannot be input the next algorithm
 *                     in the chain (either because of format or length issues))
 * @throws  ERANGE     `len` is too large or too small for the the selected
 *                     initial algorithm in the algorithm chain
 * @throws  EOVERFLOW  The expected return value is greater than {SSIZE_MAX}.
 * @throws  ENOMEM     Failed to allocate internal scratch memory
 * @throws  ENOSYS     A selected hash algorithm is either not recognised
 *                     disabled at compile-time
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
 * 
 * @since  1.0
 * @since  1.1  `void *reserved` was replaced with `LIBRECRYPT_CONTEXT *ctx`;
 *              provided `NULL` to this parameter no longer causes `EINVAL`-failure
 */
LIBRECRYPT_WRITE_MEM__(1, 2) LIBRECRYPT_READ_STR__(3) LIBRECRYPT_READ_STR__(4)
LIBRECRYPT_NONNULL_I__(3) LIBRECRYPT_NONNULL_I__(4) LIBRECRYPT_WUR__
ssize_t librecrypt_add_algorithm(char *out_buffer, size_t size, const char *augend,
                                 const char *restrict augment, LIBRECRYPT_CONTEXT *ctx);


/**
 * Deallocate object created with `librecrypt_create_context`
 *
 * @param  ctx  The object to deallocate
 * 
 * This function is MT-Safe but AS-Unsafe
 * 
 * @since  1.1
 */
void librecrypt_free_context(LIBRECRYPT_CONTEXT *ctx);


/**
 * Create a new library configuration object
 * 
 * @return  The configuration object, shall be deallocated
 *          using `librecrypt_free_context` when no longer
 *          needed; `NULL` on failuare
 * 
 * @throws  ENOMEM  Failed to allocate enough memory
 * 
 * @seealso  librecrypt_set_pepper
 * @seealso  librecrypt_set_custom_algorithms
 * 
 * This function is MT-Safe but AS-Unsafe
 * 
 * @since  1.1
 */
LIBRECRYPT_MALLOC__(librecrypt_free_context, 1) LIBRECRYPT_WUR__
LIBRECRYPT_CONTEXT *librecrypt_create_context(void);


/**
 * Set application-defined data in a library configuration object
 * 
 * The data can be used by application-defined hash functions
 * 
 * @param  ctx   The library configuration object
 * @param  user  The application-defined data
 * 
 * The caller is responsible for the lifetime of `user`:
 * deallocating it will deallocate it for `ctx` as it
 * only holds a reference to `user`, not a copy of it
 * 
 * @seealso  librecrypt_create_context
 * @seealso  librecrypt_get_user_data
 * @seealso  librecrypt_set_custom_algorithms
 * 
 * @since  1.1
 */
LIBRECRYPT_NONNULL_1__
void librecrypt_set_user_data(LIBRECRYPT_CONTEXT *ctx, void *user);


/**
 * Get application-defined data, in a library configuration object,
 * which was set using the `librecrypt_set_user_data` function
 * 
 * @param   ctx   The library configuration object
 * @return  user  The application-defined data, `NULL` if
 *                it hasn't been set (or if it was set to `NULL`)
 * 
 * @seealso  librecrypt_create_context
 * @seealso  librecrypt_set_user_data
 * @seealso  librecrypt_set_custom_algorithms
 * 
 * @since  1.1
 */
LIBRECRYPT_NONNULL_1__ LIBRECRYPT_PURE__ LIBRECRYPT_WUR__
void *librecrypt_get_user_data(const LIBRECRYPT_CONTEXT *ctx);


/**
 * Sets the pepper for a hash algorithm
 * 
 * @param   ctx   The library configuration object
 * @param   algo  The hash algorithm to apply the pepper to
 * @param   data  The pepper
 * @param   len   The number of bytes in `data`
 * @return        0 on success, -1 on failure
 * 
 * @throws  ENOSYS  The hash algorithm `algo` is either not
 *                  recognised or was disabled at compile-time
 * @throws  ENOSUP  The hash algorithm `algo` does not support
 *                  peppers; the application is instead adviced
 *                  to, itself, append or prepend the pepper
 *                  to the password
 * @throws  EINVAL  The size of the pepper is unsupported
 *                  for the hash algorithm `algo`
 * 
 * The caller is responsible for the lifetime of `data`:
 * deallocating it will deallocate it for `ctx` as it
 * only holds a reference to `data`, not a copy of it
 * 
 * @seealso  librecrypt_create_context
 * @seealso  librecrypt_hash_algorithm_end
 * 
 * @since  1.1
 */
LIBRECRYPT_NONNULL_1__ LIBRECRYPT_WUR__
int librecrypt_set_pepper(LIBRECRYPT_CONTEXT *ctx, enum librecrypt_hash_algorithm algo, const void *data, size_t len);


/**
 * Set the custom hash algorithms
 * 
 * @param   ctx     The library configuration object
 * @param   algos   The hash algorithms implementions to support
 *                  in addition to those implemented by the library
 * @param   nalgos  The number of elements in `algos`
 * 
 * The caller is responsible for the lifetime of `algos`:
 * deallocating it will deallocate it for `ctx` as it
 * only holds a reference to `algos`, not a copy of it
 * 
 * @seealso  librecrypt_create_context
 * @seealso  librecrypt_set_user_data
 * @seealso  librecrypt_get_user_data
 * @seealso  librecrypt_scan_settings
 * 
 * @since  1.1
 */
LIBRECRYPT_NONNULL_1__
void librecrypt_set_custom_algorithms(LIBRECRYPT_CONTEXT *ctx, const struct librecrypt_algorithm *algos, size_t nalgos);


/**
 * Parse and validate a password hash string
 * 
 * This function is provided as a helper function
 * for those wishing to implement custom hash
 * algorithms
 * 
 * @param   settings  The string to validate
 * @param   len       The number of bytes in `settings`
 * @param   fmt       The expected format of the string, it may contain
 *                    the metacharacter '%' (`fmt` is parsed left to right)
 *                    to perform special string content checks:
 *                      "%%"  - Literal '%'
 *                      "%*"  - Any sequence of non-'$' bytes (greedily matched)
 *                      "%s"  - String
 *                      "%u"  - Unsigned integer that may start with a leading zeroes
 *                      "%p"  - Unsigned integer that must not start with a leading zeroes
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
 *                              one `const unsigned char[static 256]`: the ASCII-encoding decoding table,
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
 * @return            1 if `settings` matches `fmt`, 0 otherwise
 * 
 * This function will call abort(3) if misused.
 * 
 * @seealso  librecrypt_set_custom_algorithms
 * 
 * @since  1.1
 */
LIBRECRYPT_READ_MEM__(1, 2) LIBRECRYPT_NONNULL_I__(3) LIBRECRYPT_WUR__
int librecrypt_scan_settings(const char *settings, size_t len, const char *fmt, ...);


#if defined(__clang__)
# pragma clang diagnostic pop
#endif

#endif
