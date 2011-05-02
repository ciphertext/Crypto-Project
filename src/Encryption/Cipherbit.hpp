
#ifndef __Encryption__Cipherbit_h__
#define __Encryption__Cipherbit_h__

#include "Encryption/Encryptor.hpp"

#include "Encryption/RationalUtilities.hpp"

#include "Encryption/GmpSerialization.hpp"
#include "Encryption/Operations/CipherStringOperators.hpp"

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/dynamic_bitset.hpp>

#include <boost/scoped_ptr.hpp>

#include <vector>
#include <deque>
#include <gmpxx.h>

namespace Encryption
{
	class Cipherstring;
	namespace Keys
	{
		class PublicKey;
	}
}
#include "Encryption/Cipherstring.hpp"
#include "Encryption/Keys/PublicKey.hpp"

namespace Encryption
{
	
	
	
	class Cipherbit
	{
		public:
			
			Cipherbit(){};
			Cipherbit(mpz_class c, std::vector<mpq_class> z, const Keys::PublicKey & pubkey);
			mpz_class getValue() const;
			mpq_class getZ(unsigned int index) const;
			void setSaturated(bool s);

			Cipherbit operator & ( const Cipherbit & cb) const;
			Cipherbit operator ^ ( const Cipherbit & cb) const;
			Cipherbit operator | ( const Cipherbit & cb) const;
			~Cipherbit();

		private:
			typedef boost::dynamic_bitset<unsigned char> bitstring_t;

			mpz_class value;
			std::vector<mpq_class> Z;
			Keys::PublicKey * pubkey;
			bool saturated;
			
			friend class boost::serialization::access;
			template<class Archive>
			void serialize( Archive & ar, const unsigned int version)
			{
				ar & Z;
				ar & value;
				ar & pubkey;
			}
			void recrypt();
			Cipherstring getHammingColumn(std::vector<Cipherstring> M, unsigned int col);
			bitstring_t mpzToBitstring(mpz_class a);
			bitstring_t mpqToBitstring(mpq_class a);
			
			
	};
}


#endif
