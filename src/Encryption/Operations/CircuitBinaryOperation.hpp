#include <exception>
using namespace std;

#ifndef __Encryption__Operations__CircuitBinaryOperation_h__
#define __Encryption__Operations__CircuitBinaryOperation_h__

#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"

namespace Encryption
{
	class Ciphertext;
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
	namespace Operations
	{
		__interface CircuitBinaryOperation
		{

			public: Encryption::Ciphertext operate(Encryption::Keys::PublicKey aKey, Encryption::Ciphertext aA, Encryption::Ciphertext aB, int aBit_addr) = 0;
		};
	}
}

#endif
