#ifndef __Encryption__Keys__PublicKey_h__
#define __Encryption__Keys__PublicKey_h__

#include "Encryption/Cipherbit.hpp"
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <vector>
#include <gmpxx.h>

namespace Encryption
{
	
   class Cipherbit;

	namespace Keys
	{

	 
		class PublicKey
		{
			friend class boost::serialization::access;



			public:
				PublicKey();
				PublicKey(std::vector<mpz_class> x,
						  std::vector<mpq_class> Y,
						  std::vector<Cipherbit> sk);
				mpz_class getX(unsigned int index);
				mpq_class getY(unsigned int index);
				Cipherbit getEncryptedSkBit(unsigned int index);
				unsigned int xsize();
				unsigned int ysize();

			private:
				std::vector<mpz_class> x;
				std::vector<mpq_class> y;
				std::vector<Cipherbit> encryptedPrivateKey;  



				template<class Archive>
				void serialize( Archive & ar, const unsigned int version)
				{
					ar & x;
					ar & y;
					ar & encryptedPrivateKey;
				};
				
		};
	}
}

#endif
