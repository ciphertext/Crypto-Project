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
			private:
				std::vector<bool> sArrow;

			public:
				PrivateKey();
				PrivateKey(std::vector<bool> bits);
				bool getBit(int index);
				unsigned int size();
		};
	}
}

#endif
