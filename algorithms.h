/* See LICENSE file for copyright and license details. */
/* included from "common.h" */


/* ordered by preference */
#define LIST_ALGORITHMS(X) /* TODO add algorithms */


#define Y(ALGO)\
	HIDDEN size_t librecrypt__##ALGO##__get_prefix(const char *settings, size_t len);\
	HIDDEN unsigned librecrypt__##ALGO##__is_algorithm(const char *settings, size_t len);\
	HIDDEN int librecrypt__##ALGO##__hash(char *restrict out_buffer, size_t size, const char *phrase,\
	                                      size_t len, const char *settings, size_t prefix, void *reserved);\
	HIDDEN int librecrypt__##ALGO##__test_supported(const char *phrase, size_t len, int text,\
	                                                const char *settings, size_t prefix);\
	HIDDEN ssize_t librecrypt__##ALGO##__make_settings(char *out_buffer, size_t size, const char *algorithm,\
	                                                   size_t memcost, uintmax_t timecost, int gensalt,\
	                                                   ssize_t (*rng)(void *out, size_t n, void *user), void *user);\
	NONSTRING extern const char librecrypt__##ALGO##__encoding_lut[256];\
	extern const unsigned char librecrypt__##ALGO##__decoding_lut[256];

#define X(ALGO) IF__##ALGO##__SUPPORTED(Y(ALGO))
LIST_ALGORITHMS(X)
#undef X
#undef Y
