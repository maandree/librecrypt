/* See LICENSE file for copyright and license details. */
/* included from "common.h" */


#include "argon2/argon2.h"


/* ordered by preference */
#define LIST_ALGORITHMS(X)\
	X(argon2id) /* argon2 variant:: recommended hybrid */ \
	X(argon2i) /* argon2 variant:: data-independent: weaker against GPU/ASIC, stronger against side-channel attacks */\
	X(argon2d) /* argon2 variant:: data-dependent: weaker against side-channel attacks, stronger against GPU/ASIC */\
	X(argon2ds) /* argon2 variant:: data-dependent though S-box, not properly cryptoanalysed */




#ifdef REQUIRES_COMMON_RFC4848S4

/**
 * RFC 4648 §4 implementation of `struct algorithm.encoding_lut_`
 */
NONSTRING extern const char librecrypt_common_rfc4848s4_encoding_lut_[256u];

/**
 * RFC 4648 §4 implementation of `struct algorithm.decoding_lut_`
 */
extern const unsigned char librecrypt_common_rfc4848s4_decoding_lut_[256u];

#endif
