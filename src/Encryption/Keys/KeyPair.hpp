#ifndef __Encryption__Keys__KeyPair_h__
#define __Encryption__Keys__KeyPair_h__

#include <exception>
#include <vector>

#include <boost/shared_ptr.hpp>


#include <iterator>
#include <gmpxx.h>

#include <boost/nondet_random.hpp>
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"
#include "Encryption/Encryptor.hpp"
#include "Encryption/RationalUtilities.hpp"
#include "Encryption/Cipherstring.hpp"

namespace Encryption
{
	namespace Keys
	{
		class KeyPair
		{
			
			public:
				KeyPair();
				boost::shared_ptr<PublicKey> getPublicKey();
				boost::shared_ptr<PrivateKey> getPrivateKey();
				
			private:
				boost::shared_ptr<PrivateKey> privateKey;
				boost::shared_ptr<PublicKey> publicKey;
				
				boost::random_device rd;
				gmp_randclass rand_gen;

				typedef std::vector<bool> bitmap_t;
				typedef boost::shared_ptr<std::vector<mpz_class> > publicKey_array_t;
				typedef std::vector<mpz_class> u_array_t;
				typedef std::set<unsigned int> s_set_t; 
				typedef boost::shared_ptr<std::vector<mpq_class> > y_rational_array_t;
				
				publicKey_array_t getPk(mpz_class p);
				s_set_t getS();
				bitmap_t getSArrow(s_set_t S);
				u_array_t getU(mpz_class p, s_set_t S);
				y_rational_array_t getY(u_array_t u);
				Cipherstring getSk(bitmap_t sArrow,boost::shared_ptr<PublicKey> pk, y_rational_array_t y);
		};
	}
}

#endif
