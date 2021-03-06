/* @LICENSE(MUSLC_MIT) */

#include "libm.h"

float complex cprojf(float complex z)
{
	if (isinf(crealf(z)) || isinf(cimagf(z)))
		return cpackf(INFINITY, copysignf(0.0, crealf(z)));
	return z;
}
