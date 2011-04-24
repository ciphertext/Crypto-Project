#ifndef __Encryption__Keys__KeyPair_h__
#define __Encryption__Keys__KeyPair_h__

#include <exception>
#include <vector>
#include <gmpxx.h>
#include <boost/nondet_random.hpp>
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"
#include "Encryption/Encryptor.hpp"
#include "Encryption/RationalUtilities.hpp"

namespace Encryption
{
	namespace Keys
	{
		class KeyPair
		{
			
			public:
				KeyPair();
				PublicKey getPublicKey();
				PrivateKey getPrivateKey();
				
			private:
				PrivateKey privateKey;
				PublicKey publicKey;
				
				boost::random_device rd;
				gmp_randclass rand_gen;
   			
				typedef std::vector<bool> bitmap_t;
				typedef std::vector<mpz_class> publicKey_array_t;
				typedef std::vector<mpz_class> u_array_t;
				typedef std::set<unsigned int> s_set_t; 
				typedef std::vector<mpq_class> y_rational_array_t;
				typedef std::vector<Cipherbit> encryptedSecretKey_array_t;
				
				publicKey_array_t getPk(mpz_class p);
				s_set_t getS();
				bitmap_t getSArrow(s_set_t S);
				u_array_t getU(mpz_class p, s_set_t S);
				y_rational_array_t getY(u_array_t u);
				encryptedSecretKey_array_t getSk(bitmap_t sArrow, publicKey_array_t pk, y_rational_array_t y);
				







		};
	}
}

#endif
