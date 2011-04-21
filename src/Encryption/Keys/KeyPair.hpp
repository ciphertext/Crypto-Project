#ifndef __Encryption__Keys__KeyPair_h__
#define __Encryption__Keys__KeyPair_h__

#include <exception>
#include <vector>
#include <boost/rational.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/linear_congruential.hpp>
#include <boost/random/variate_generator.hpp>
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"



namespace Encryption
{
	namespace Keys
	{
		class KeyPair
		{
			private:
				PrivateKey privateKey;
				PublicKey publicKey;

			public:
				KeyPair();
				PublicKey getPublicKey();
				PrivateKey getPrivateKey();
		};
	}
}

#endif
