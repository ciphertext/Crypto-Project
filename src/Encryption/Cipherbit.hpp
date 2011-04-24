
#ifndef __Encryption__Cipherbit_h__
#define __Encryption__Cipherbit_h__

#include <vector>
#include <gmp.h>
#include <gmpxx.h>

namespace Encryption
{
	class Cipherbit
	{
		private:
			mpz_class value;
			std::vector<mpq_class> Z;
			unsigned int multCount;
		public:
			Cipherbit(mpz_class c, std::vector<mpq_class> z);
			mpz_class getValue();
			mpq_class getZ(unsigned int index);
			unsigned int getMultCount();
			void setMultCount(unsigned int c);
	};
}

#endif
