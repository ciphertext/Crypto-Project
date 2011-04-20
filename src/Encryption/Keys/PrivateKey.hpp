#include <exception>

#ifndef __Encryption__Keys__PrivateKey_h__
#define __Encryption__Keys__PrivateKey_h__


#include<vector>

namespace Encryption
{
	namespace Keys
	{
		class PrivateKey
		{

			public: 
			      PrivateKey(std::vector<bool> bits);
			      
			      bool getBit(int index);
			      
		};
	}
}

#endif
