#ifndef __Encryption__Keys__PublicKey_h__
#define __Encryption__Keys__PublicKey_h__

#include <boost/rational.hpp>
#include "Encryption/Cipherbit.hpp"
#include <vector>

namespace Encryption
{
	namespace Keys
	{
	 
		class PublicKey
		{
			private:
				std::vector<long int> pk;
				std::vector<boost::rational<long int> > y;
				std::vector<Cipherbit> encryptedPrivateKey;  

			public:
				PublicKey(std::vector<long int> x,
						  std::vector<boost::rational<long int> > Y,
						  std::vector<Cipherbit> sk);
				long int getX(int index);
				boost::rational<long int> getY(int index);
				Cipherbit getEncryptedSkBit(int index);
				int size();
		};
	}
}

#endif
