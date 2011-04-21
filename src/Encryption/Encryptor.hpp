#ifndef __Encryption__Encryptor_h__
#define __Encryption__Encryptor_h__

#include <exception>
#include <string>
#include <set>
#include <ctime>
#include <cmath>
#include <boost/rational.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/linear_congruential.hpp>
#include <boost/random/variate_generator.hpp>
#include "Encryption/Cipherbit.hpp"
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"



namespace Encryption
{
	class Encryptor
	{
		public:
			static Cipherbit encrypt(bool aM, Keys::PublicKey aPk);
			static bool decrypt(Cipherbit aC, Keys::PrivateKey aSk);
	};
}

#endif
