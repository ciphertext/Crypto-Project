#ifndef __Encryption__Keys__PublicKey_h__
#define __Encryption__Keys__PublicKey_h__

#include <boost/rational.hpp>
#include "Encryption/Cipherbit.hpp"
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <vector>

namespace Encryption
{
	namespace Keys
	{
	 
		class PublicKey
		{

			public:
				PublicKey();
				PublicKey(std::vector<long int> x,
						  std::vector<boost::rational<long int> > Y,
						  std::vector<Cipherbit> sk);
				long int getX(int index);
				boost::rational<long int> getY(int index);
				Cipherbit getEncryptedSkBit(int index);
				unsigned int xsize();
				unsigned int ysize();

			private:
				std::vector<long int> x;
				std::vector<boost::rational<long int> > y;
				std::vector<Cipherbit> encryptedPrivateKey;  

				friend class boost::serialization::access;
				template<class Archive>
				void serialize( Archive & ar, const unsigned int version);
				
				
		};
	}
}

#endif
