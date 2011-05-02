#ifndef ENCRYPTOR_CIPHERSTRING
#define ENCRYPTOR_CIPHERSTRING



#include <vector>
#include <boost/serialization/serialization.hpp>

namespace Encryption
{
	class Cipherbit;
}
#include "Encryption/Cipherbit.hpp"
	
	
namespace Encryption
{
	
	class Cipherstring
	{
		public:
			Cipherstring();
			Cipherstring(int count, const Cipherbit & value);

			Cipherbit & operator [] (unsigned int index);
			Cipherbit at(unsigned int index) const;
			Cipherbit back() const;
			void push_back(const Cipherbit & b);
			void pop_back();
			unsigned int size() const;
			void insert(std::vector<Cipherbit>::iterator it, Cipherbit a);
			std::vector<Cipherbit>::iterator begin();
			std::vector<Cipherbit>::iterator end();
			bool empty();


			void unsaturate();
			
		private:
			std::vector<Cipherbit> mBits;
			
			friend class boost::serialization::access;
			template<class Archive>
			void serialize( Archive & ar, const unsigned int version)
			{
				ar & mBits;
			};
	};
}


#endif
