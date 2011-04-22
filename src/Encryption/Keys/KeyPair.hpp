#ifndef __Encryption__Keys__KeyPair_h__
#define __Encryption__Keys__KeyPair_h__

#include <exception>
#include <vector>
#include <boost/rational.hpp>
#include <boost/nondet_random.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/variate_generator.hpp>
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"
#include "Encryption/Encryptor.hpp"
#include <algorithm>
#include <boost/foreach.hpp>


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
				boost::mt19937 base_gen;
   			
				typedef	boost::variate_generator<boost::mt19937&, boost::uniform_int<> > var_gen_t;
				typedef  boost::variate_generator<boost::mt19937&, boost::uniform_int<long int> > var_gen_u_t;
				typedef long int int_t;
				typedef unsigned long int uint_t;
				typedef std::vector<bool> bitmap_t;
				typedef std::vector<int_t> publicKey_array_t;
				typedef std::vector<int_t> u_array_t;
				typedef std::set<int> s_set_t; 
				typedef std::vector<boost::rational<int_t> > y_rational_t;
				typedef std::vector<Cipherbit> encryptedSecretKey_t;
				
				publicKey_array_t getPk(int_t p);
				s_set_t getS();
				bitmap_t getSArrow(s_set_t S);
				u_array_t getU();
				u_array_t getU2();
				int_t getUFinal(int_t p, u_array_t u2);
				void stillNeedADamnedName(s_set_t S, u_array_t & u, u_array_t u2, int_t u_final);
				y_rational_t getY(u_array_t u);
				encryptedSecretKey_t getSk(bitmap_t sArrow, publicKey_array_t pk, y_rational_t y);
				







		};
	}
}

#endif
