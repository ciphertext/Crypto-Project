
#ifndef __Encryption__Operations__CipherStringBinaryOperation_h__
#define __Encryption__Operations__CipherStringBinaryOperation_h__

#include "Encryption/Cipherstring.hpp"

#include "Encryption/Operations/CipherStringOperators.hpp"

namespace Encryption
{
	namespace Operations
	{
		class CipherStringBinaryOperation
		{
			public: 
				virtual Encryption::Cipherstring operate(Encryption::Cipherstring aA, Encryption::Cipherstring aB) = 0;
		};
	}
}

#endif
