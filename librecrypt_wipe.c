/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
# pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
#endif


void *(*volatile librecrypt_explicit_memset_____)(void *, int, size_t) = &memset;


#if defined(__clang__) /* before __GNUC__ because that is also set in clang */
# if __has_attribute(optnone)
__attribute__((optnone))
# endif
#elif defined(__GNUC__)
# if __GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__ >= 40400
__attribute__((optimize("-O0")))
# endif
#endif
void
librecrypt_wipe(void *buffer, size_t size)
{
	if (buffer && size) {
		buffer = (*librecrypt_explicit_memset_____)(buffer, 0, size);
#if defined(__GNUC__)
		__asm__ volatile ("" :: "g" (buffer) : "memory");
#else
		(void) buffer;
#endif
	}
}


#else


int
main(void)
{
	char *buf;

	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

#if defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wnonnull"
#endif

	librecrypt_wipe(NULL, 0u);
	librecrypt_wipe(NULL, 4094u);
	librecrypt_wipe((void *)(intptr_t)-1, 0u);

	buf = malloc(256u);
	memset(buf, 99, 256u);
	librecrypt_wipe(buf, 256u);
	free(buf);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
