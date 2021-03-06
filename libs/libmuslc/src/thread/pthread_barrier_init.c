/* @LICENSE(MUSLC_MIT) */

#include "pthread_impl.h"

int pthread_barrier_init(pthread_barrier_t *b, const pthread_barrierattr_t *a, unsigned count)
{
	if (count-1 > INT_MAX-1) return EINVAL;
	*b = (pthread_barrier_t){ ._b_limit = count-1 | (a?*a:0) };
	return 0;
}
