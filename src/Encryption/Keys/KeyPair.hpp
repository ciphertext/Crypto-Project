#include <exception>


#ifndef __Encryption__Keys__KeyPair_h__
#define __Encryption__Keys__KeyPair_h__

#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"


namespace Encryption
{
	namespace Keys
	{
		class KeyPair
		{

			public: 
			      KeyPair();
			      PublicKey getPublicKey();
			      PrivateKey getPrivateKey();
		};
	}
}

#endif
 
