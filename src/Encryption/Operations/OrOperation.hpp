#ifndef __Encryption__Operations__OrOperation_h__
#define __Encryption__Operations__OrOperation_h__

#include "Encryption/Operations/CipherStringBinaryOperation.hpp"

namespace Encryption
{
	namespace Operations
	{
		class OrOperation: public Encryption::Operations::CipherStringBinaryOperation
		{
			public:
				Encryption::Cipherstring operate(Encryption::Cipherstring aA, Encryption::Cipherstring aB);
		};
	}
}

#endif
