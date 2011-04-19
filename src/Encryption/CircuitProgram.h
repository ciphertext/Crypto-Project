#include <exception>
#include <list>
using namespace std;

#ifndef __Encryption__CircuitProgram_h__
#define __Encryption__CircuitProgram_h__

#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
// #include "Encryption/Operations/CircuitBinaryOperation.h"

namespace Encryption
{
	class Ciphertext;
	class CircuitProgram;
	namespace Keys
	{
		class PublicKey;
	}
	namespace Operations
	{
		__interface CircuitBinaryOperation;
	}
}

namespace Encryption
{
	class CircuitProgram
	{
		public: Encryption::Operations::CircuitBinaryOperation* _::._;

		public: Encryption::Ciphertext execute(Encryption::Keys::PublicKey aKey, list<Encryption::Ciphertext> aArgs);
	};
}

#endif
