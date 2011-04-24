#ifndef __Encryption__RationalUtilities_h__
#define __Encryption__RationalUtilities_h__

#include <gmpxx.h>


inline mpq_class r_floor(mpq_class n) {
	return mpq_class(n.get_num() - (n.get_num() % n.get_den()), n.get_den());
}

inline mpq_class r_round(mpq_class n) {
	mpq_class half(1,2);
	return r_floor(n + half);
}

inline mpq_class r_modulo(mpq_class a, int b) {
	return mpq_class(a.get_num() % (b*a.get_den()),a.get_den());
}

inline mpq_class fix_precision_bits(mpq_class a, int bits) {
	mpz_class power = mpz_class(2) << (bits-1);
	return r_floor(a * power) / power;
}

#endif
