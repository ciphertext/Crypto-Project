#include <exception>
#include <string>
using namespace std;

#ifndef __Encryption__Encryptor_h__
#define __Encryption__Encryptor_h__

#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Keys/PrivateKey.h"

namespace Encryption
{
	class Ciphertext;
	class Encryptor;
	namespace Keys
	{
		class PublicKey;
		class PrivateKey;
	}
}

namespace Encryption
{
	class Encryptor
	{

		public: Encryption::Ciphertext encrypt(string aM, Encryption::Keys::PublicKey aPk);

		public: string decrypt(Encryption::Ciphertext aC, Encryption::Keys::PrivateKey aSk);
	};
}

#endif
