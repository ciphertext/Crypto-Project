#ifndef __Encryption__Operations__MultOperation_h__
#define __Encryption__Operations__MultOperation_h__

#include "Encryption/Operations/CipherStringBinaryOperation.hpp"
#include "Encryption/Operations/AddOperation.hpp"

namespace Encryption
{
	namespace Operations
	{
		class MultOperation: public Encryption::Operations::CipherStringBinaryOperation
		{
			public:
				Encryption::Cipherstring operate(Encryption::Cipherstring aA, Encryption::Cipherstring aB);
		};
	}
}

#endif
