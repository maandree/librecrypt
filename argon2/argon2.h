/* See LICENSE file for copyright and license details. */
/* included from "algorithms.h" */

#if defined(SUPPORT_ARGON2I) || defined(SUPPORT_ARGON2D) || defined(SUPPORT_ARGON2ID) || defined(SUPPORT_ARGON2DS)
# if !defined(ARGON2_VERSION)
#  include <libar2.h>
#  ifndef NO_LIBAR2SIMPLIFIED
#   include <libar2simplified.h>
#  else
#   define libar2simplified_init_context init_context
#  endif
# else
#  include <argon2.h>
#  define LIBAR2_ARGON2D 0
#  define LIBAR2_ARGON2I 1
#  define LIBAR2_ARGON2ID 2
#  define LIBAR2_ARGON2DS 4
#  define LIBAR2_ARGON2_VERSION_10 0x10
#  define LIBAR2_ARGON2_VERSION_13 0x13
#  define LIBAR2_MIN_M_COST ARGON2_MIN_MEMORY
#  define LIBAR2_MAX_M_COST ARGON2_MAX_MEMORY
#  define LIBAR2_MIN_T_COST ARGON2_MIN_TIME
#  define LIBAR2_MAX_T_COST ARGON2_MAX_TIME
#  define LIBAR2_MIN_LANES ARGON2_MIN_LANES
#  define LIBAR2_MAX_LANES ARGON2_MAX_LANES
#  define LIBAR2_MIN_SALTLEN ARGON2_MIN_SALT_LENGTH
#  define LIBAR2_MAX_SALTLEN ARGON2_MAX_SALT_LENGTH
#  define LIBAR2_MIN_HASHLEN ARGON2_MIN_OUTLEN
#  define LIBAR2_MAX_HASHLEN ARGON2_MAX_OUTLEN
#  if ARGON2_VERSION < 20161029L
#   ifdef SUPPORT_ARGON2ID
#    undef SUPPORT_ARGON2ID
#   endif
#  endif
#  if ARGON2_VERSION < 20160406L
#   define NO_ARGON2_VERSION_13__
#  else
#   ifdef SUPPORT_ARGON2DS
#    undef SUPPORT_ARGON2DS
#   endif
#  endif
# endif
#endif


#define IF__argon2i__SUPPORTED(A)
#define IF__argon2d__SUPPORTED(A)
#define IF__argon2id__SUPPORTED(A)
#define IF__argon2ds__SUPPORTED(A)


#if defined(SUPPORT_ARGON2I)
# undef IF__argon2i__SUPPORTED
# define IF__argon2i__SUPPORTED(A) A
# define argon2i__HASH_SIZE argon2__HASH_SIZE
# define argon2i__FLEXIBLE_HASH_SIZE argon2__FLEXIBLE_HASH_SIZE
# define argon2i__STRICT_PAD argon2__STRICT_PAD
# define argon2i__PAD argon2__PAD
# define librecrypt__argon2i__hash librecrypt__argon2__hash
# define librecrypt__argon2i__test_supported librecrypt__argon2__test_supported
# define librecrypt__argon2i__encoding_lut librecrypt_common_rfc4848s4_encoding_lut_
# define librecrypt__argon2i__decoding_lut librecrypt_common_rfc4848s4_decoding_lut_
HIDDEN PURE unsigned librecrypt__argon2i__is_algorithm(const char *settings, size_t len);
HIDDEN ssize_t librecrypt__argon2i__make_settings(char *out_buffer, size_t size, const char *algorithm,
                                                  size_t memcost, uintmax_t timecost, int gensalt,
                                                  ssize_t (*rng)(void *out, size_t n, void *user), void *user);
#endif

#if defined(SUPPORT_ARGON2D)
# undef IF__argon2d__SUPPORTED
# define IF__argon2d__SUPPORTED(A) A
# define argon2d__HASH_SIZE argon2__HASH_SIZE
# define argon2d__FLEXIBLE_HASH_SIZE argon2__FLEXIBLE_HASH_SIZE
# define argon2d__STRICT_PAD argon2__STRICT_PAD
# define argon2d__PAD argon2__PAD
# define librecrypt__argon2d__hash librecrypt__argon2__hash
# define librecrypt__argon2d__test_supported librecrypt__argon2__test_supported
# define librecrypt__argon2d__encoding_lut librecrypt_common_rfc4848s4_encoding_lut_
# define librecrypt__argon2d__decoding_lut librecrypt_common_rfc4848s4_decoding_lut_
HIDDEN PURE unsigned librecrypt__argon2d__is_algorithm(const char *settings, size_t len);
HIDDEN ssize_t librecrypt__argon2d__make_settings(char *out_buffer, size_t size, const char *algorithm,
                                                  size_t memcost, uintmax_t timecost, int gensalt,
                                                  ssize_t (*rng)(void *out, size_t n, void *user), void *user);
#endif

#if defined(SUPPORT_ARGON2ID)
# undef IF__argon2id__SUPPORTED
# define IF__argon2id__SUPPORTED(A) A
# define argon2id__HASH_SIZE argon2__HASH_SIZE
# define argon2id__FLEXIBLE_HASH_SIZE argon2__FLEXIBLE_HASH_SIZE
# define argon2id__STRICT_PAD argon2__STRICT_PAD
# define argon2id__PAD argon2__PAD
# define librecrypt__argon2id__hash librecrypt__argon2__hash
# define librecrypt__argon2id__test_supported librecrypt__argon2__test_supported
# define librecrypt__argon2id__encoding_lut librecrypt_common_rfc4848s4_encoding_lut_
# define librecrypt__argon2id__decoding_lut librecrypt_common_rfc4848s4_decoding_lut_
HIDDEN PURE unsigned librecrypt__argon2id__is_algorithm(const char *settings, size_t len);
HIDDEN ssize_t librecrypt__argon2id__make_settings(char *out_buffer, size_t size, const char *algorithm,
                                                   size_t memcost, uintmax_t timecost, int gensalt,
                                                   ssize_t (*rng)(void *out, size_t n, void *user), void *user);
#endif

#if defined(SUPPORT_ARGON2DS)
# undef IF__argon2ds__SUPPORTED
# define IF__argon2ds__SUPPORTED(A) A
# define argon2ds__HASH_SIZE argon2__HASH_SIZE
# define argon2ds__FLEXIBLE_HASH_SIZE argon2__FLEXIBLE_HASH_SIZE
# define argon2ds__STRICT_PAD argon2__STRICT_PAD
# define argon2ds__PAD argon2__PAD
# define librecrypt__argon2ds__hash librecrypt__argon2__hash
# define librecrypt__argon2ds__test_supported librecrypt__argon2__test_supported
# define librecrypt__argon2ds__encoding_lut librecrypt_common_rfc4848s4_encoding_lut_
# define librecrypt__argon2ds__decoding_lut librecrypt_common_rfc4848s4_decoding_lut_
HIDDEN PURE unsigned librecrypt__argon2ds__is_algorithm(const char *settings, size_t len);
HIDDEN ssize_t librecrypt__argon2ds__make_settings(char *out_buffer, size_t size, const char *algorithm,
                                                   size_t memcost, uintmax_t timecost, int gensalt,
                                                   ssize_t (*rng)(void *out, size_t n, void *user), void *user);
#endif

#define IF__argon2_v1_0__SUPPORTED(A)
#define IF__argon2_v1_3__SUPPORTED(A)
#if defined(SUPPORT_ARGON2I) || defined(SUPPORT_ARGON2D) || defined(SUPPORT_ARGON2ID) || defined(SUPPORT_ARGON2DS)
# undef IF__argon2_v1_0__SUPPORTED
# define IF__argon2_v1_0__SUPPORTED(A) A
# define SUPPORT_ARGON2_V1_0
# ifndef NO_ARGON2_VERSION_13__
#  undef IF__argon2_v1_3__SUPPORTED
#  define IF__argon2_v1_3__SUPPORTED(A) A
#  define SUPPORT_ARGON2_V1_3
# endif
# define argon2__HASH_SIZE 32u
# define argon2__FLEXIBLE_HASH_SIZE 1
# define argon2__STRICT_PAD 0
# define argon2__PAD '='
HIDDEN int librecrypt__argon2__hash(char *restrict out_buffer, size_t size, const char *phrase, size_t len,
                                    const char *settings, size_t prefix, LIBRECRYPT_CONTEXT *ctx);
HIDDEN PURE int librecrypt__argon2__test_supported(const char *phrase, size_t len, int text,
                                                   const char *settings, size_t prefix, size_t *len_out);
# ifndef REQUIRES_COMMON_RFC4848S4
#  define REQUIRES_COMMON_RFC4848S4
# endif
#endif


#define IF__argon2i_v1_0__SUPPORTED(A) IF__argon2_v1_0__SUPPORTED(IF__argon2i__SUPPORTED(A))
#define IF__argon2d_v1_0__SUPPORTED(A) IF__argon2_v1_0__SUPPORTED(IF__argon2d__SUPPORTED(A))
#define IF__argon2id_v1_0__SUPPORTED(A) IF__argon2_v1_0__SUPPORTED(IF__argon2id__SUPPORTED(A))
#define IF__argon2ds_v1_0__SUPPORTED(A) IF__argon2_v1_0__SUPPORTED(IF__argon2ds__SUPPORTED(A))

#define IF__argon2i_v1_3__SUPPORTED(A) IF__argon2_v1_3__SUPPORTED(IF__argon2i__SUPPORTED(A))
#define IF__argon2d_v1_3__SUPPORTED(A) IF__argon2_v1_3__SUPPORTED(IF__argon2d__SUPPORTED(A))
#define IF__argon2id_v1_3__SUPPORTED(A) IF__argon2_v1_3__SUPPORTED(IF__argon2id__SUPPORTED(A))
#define IF__argon2ds_v1_3__SUPPORTED(A) IF__argon2_v1_3__SUPPORTED(IF__argon2ds__SUPPORTED(A))
