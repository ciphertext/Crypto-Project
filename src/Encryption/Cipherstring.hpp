#ifndef ENCRYPTOR_CIPHERSTRING
#define ENCRYPTOR_CIPHERSTRING


#include "Encryption/Cipherbit.hpp"
#include <vector>
#include <boost/serialization/serialization.hpp>

namespace Encryption
{
	class Cipherstring
	{
		public:
			Cipherbit & operator [] (unsigned int index);
			Cipherbit at(unsigned int index) const;
			void push_back(const Cipherbit & b);
			unsigned int size() const;
			
		private:
			std::vector<Cipherbit> mBits;
			
			friend class boost::serialization::access;
			template<class Archive>
			void serialize( Archive & ar, const unsigned int version);
	};
	

	
	
}


#endif