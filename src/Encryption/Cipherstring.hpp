#ifndef ENCRYPTOR_CIPHERSTRING
#define ENCRYPTOR_CIPHERSTRING

#include "Encryption/Cipherbit.hpp"
#include <vector>

namespace Encryption
{
	class Cipherstring
	{
		public:
		  Cipherbit & operator [] (unsigned int index);
		  void push_back(const Cipherbit & b);
		  unsigned int size();
		  
		  
		private:
			std::vector<Cipherbit> mBits;
	};
}


#endif