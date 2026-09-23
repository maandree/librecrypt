/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST


const int librecrypt_version_major = LIBRECRYPT_VERSION_MAJOR;
const int librecrypt_version_minor = LIBRECRYPT_VERSION_MINOR;
const int librecrypt_version_patch = LIBRECRYPT_VERSION_PATCH;


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	EXPECT(librecrypt_version_major == LIB_MAJOR);
	EXPECT(librecrypt_version_minor == LIB_MINOR);
	EXPECT(librecrypt_version_patch == LIB_PATCH);
	EXPECT(LIBRECRYPT_VERSION_MAJOR == LIB_MAJOR);
	EXPECT(LIBRECRYPT_VERSION_MINOR == LIB_MINOR);
	EXPECT(LIBRECRYPT_VERSION_PATCH == LIB_PATCH);

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
