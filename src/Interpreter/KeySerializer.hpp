
#ifndef __Interpreter__KeySerializer_h__
#define __Interpreter__KeySerializer_h__

#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"

#include <exception>
#include <string>

namespace Interpreter
{
	class KeySerializer
	{
		public:
			std::string serialize(Encryption::Keys::PublicKey aP);

			std::string serialize(Encryption::Keys::PrivateKey aP);

			Encryption::Keys::PublicKey unserializePk(std::string aPk);

			Encryption::Keys::PrivateKey unserializeSk(std::string aSk);
	};
}

#endif
