#define _GNU_SOURCE
#include "libm.h"

#define M_E             2.7182818284590452354   /* e */
#define M_LOG2E         1.4426950408889634074   /* log_2 e */
#define M_LOG10E        0.43429448190325182765  /* log_10 e */
#define M_LN2           0.69314718055994530942  /* log_e 2 */
#define M_LN10          2.30258509299404568402  /* log_e 10 */
#define M_PI            3.14159265358979323846  /* pi */
#define M_PI_2          1.57079632679489661923  /* pi/2 */
#define M_PI_4          0.78539816339744830962  /* pi/4 */
#define M_1_PI          0.31830988618379067154  /* 1/pi */
#define M_2_PI          0.63661977236758134308  /* 2/pi */
#define M_2_SQRTPI      1.12837916709551257390  /* 2/sqrt(pi) */
#define M_SQRT2         1.41421356237309504880  /* sqrt(2) */
#define M_SQRT1_2       0.70710678118654752440  /* 1/sqrt(2) */

#if LDBL_MANT_DIG == 53 && LDBL_MAX_EXP == 1024
void sincosl(long double x, long double *sin, long double *cos)
{
	double sind, cosd;
	sincos(x, &sind, &cosd);
	*sin = sind;
	*cos = cosd;
}
#elif (LDBL_MANT_DIG == 64 || LDBL_MANT_DIG == 113) && LDBL_MAX_EXP == 16384
void sincosl(long double x, long double *sin, long double *cos)
{
	union ldshape u = {x};
	unsigned n;
	long double y[2], s, c;

	u.i.se &= 0x7fff;
	if (u.i.se == 0x7fff) {
		*sin = *cos = x - x;
		return;
	}
	if (u.f < M_PI_4) {
		if (u.i.se < 0x3fff - LDBL_MANT_DIG) {
			/* raise underflow if subnormal */
			if (u.i.se == 0) FORCE_EVAL(x*0x1p-120f);
			*sin = x;
			/* raise inexact if x!=0 */
			*cos = 1.0 + x;
			return;
		}
		*sin = __sinl(x, 0, 0);
		*cos = __cosl(x, 0);
		return;
	}
	n = __rem_pio2l(x, y);
	s = __sinl(y[0], y[1], 1);
	c = __cosl(y[0], y[1]);
	switch (n & 3) {
	case 0:
		*sin = s;
		*cos = c;
		break;
	case 1:
		*sin = c;
		*cos = -s;
		break;
	case 2:
		*sin = -s;
		*cos = -c;
		break;
	case 3:
	default:
		*sin = -c;
		*cos = s;
		break;
	}
}
#endif
