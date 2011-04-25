
#ifndef __Encryption__Operations__AddOperation_h__
#define __Encryption__Operations__AddOperation_h__

#include "Encryption/Operations/CipherStringBinaryOperation.hpp"

namespace Encryption
{
	namespace Operations
	{
		class AddOperation: public Encryption::Operations::CipherStringBinaryOperation
		{
			public:
				Encryption::Cipherstring operate(Encryption::Cipherstring aA, Encryption::Cipherstring aB);
		};
	}
}

#endif
