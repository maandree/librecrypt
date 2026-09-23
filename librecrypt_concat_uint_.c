/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifndef TEST
#include <stdio.h>

/* TODO use of sprintf(3) should be eliminated;
 *      this will make it easier to use in an unhosted environment (kernels)
 *      and make_settings will be AS-Safe,
 *      however librecrypt_add_algorithm will not be AS-Safe as hash
 *         functions may require memory allocations which is AS-Unsafe
 */


void
librecrypt_concat_uint_(struct concat_state *state, uintmax_t value)
{
	char buf[3u * sizeof(uintmax_t) + 1u];
	int len = sprintf(buf, "%ju", value);
        if (len < 1)
		abort(); /* $covered$ (impossible reliably) */
	librecrypt_concat_mem_(state, buf, (size_t)len);
}


#else


int
main(void)
{
	SET_UP_ALARM();
	INIT_RESOURCE_TEST();

	/* TODO test */

	STOP_RESOURCE_TEST();
	return 0;
}


#endif
