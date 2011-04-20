#include <exception>
#include <list>

#ifndef __Encryption__CircuitProgram_h__
#define __Encryption__CircuitProgram_h__

#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Operations/CircuitBinaryOperation.h"

namespace Encryption
{
	class CircuitProgram
	{
		public: 
			Encryption::Ciphertext execute(Encryption::Keys::PublicKey aKey, list<Encryption::Ciphertext> aArgs);
	};
}

#endif
