#include <exception>
using namespace std;

#ifndef __Encryption__Operations__XorOperation_h__
#define __Encryption__Operations__XorOperation_h__

#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Operations/CircuitBinaryOperation.h"

namespace Encryption
{
	class Ciphertext;
	namespace Keys
	{
		class PublicKey;
	}
	namespace Operations
	{
		// __interface CircuitBinaryOperation;
		class XorOperation;
	}
}

namespace Encryption
{
	namespace Operations
	{
		class XorOperation: public Encryption::Operations::CircuitBinaryOperation
		{

			public: Encryption::Ciphertext operate(Encryption::Keys::PublicKey aKey, Encryption::Ciphertext aA, Encryption::Ciphertext aB, int aBit_addr);
		};
	}
}

#endif