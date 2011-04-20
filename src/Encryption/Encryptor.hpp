#include <exception>
#include <string>

#ifndef __Encryption__Encryptor_h__
#define __Encryption__Encryptor_h__

#include "Encryption/Cipherbit.hpp"
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"



namespace Encryption
{
	class Encryptor
	{
	   public:
	         static Cipherbit encrypt(std::string aM, Keys::PublicKey aPk);

		 static std::string decrypt(Cipherbit aC, Keys::PrivateKey aSk);
	};
}

#endif
