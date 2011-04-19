#include <exception>
using namespace std;

#ifndef __Encryption__Keys__PrivateKey_h__
#define __Encryption__Keys__PrivateKey_h__

#include "Encryption/Keys/PublicKey.h"

namespace Encryption
{
	namespace Keys
	{
		class PublicKey;
		class PrivateKey;
	}
}

namespace Encryption
{
	namespace Keys
	{
		class PrivateKey
		{

			public: Encryption::Keys::PublicKey getPublicKey();
		};
	}
}

#endif
