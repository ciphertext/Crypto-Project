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
		  
		  public:
		    PublicKey(std::vector<long int> x, std::vector<boost::rational<long int> > Y, std::vector<Cipherbit> sk); 
		    
		    int getX(int index);
		    boost::rational<long int> getY(int index);
		    Cipherbit getEncryptedSkBit(int index);
		    


		};
	}
}

#endif
