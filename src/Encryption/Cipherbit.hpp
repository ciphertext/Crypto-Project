
#ifndef __Encryption__Cipherbit_h__
#define __Encryption__Cipherbit_h__


#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/GmpSerialization.hpp"
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/rational.hpp>

#include <vector>
#include <gmpxx.h>

namespace Encryption
{
	class Cipherbit
	{

		public:
			
			Cipherbit(mpz_class c, std::vector<mpq_class> z);
			mpz_class getValue();
			mpq_class getZ(unsigned int index);

			Cipherbit operator & ( const Cipherbit & cb) const;
			Cipherbit operator ^ ( const Cipherbit & cb) const;

		private:
         Cipherbit(){};
		//	boost::shared_ptr<Keys::PublicKey> pubkey;
			
			friend class boost::serialization::access;
			template<class Archive>
			void serialize( Archive & ar, const unsigned int version)
			{
				ar & Z;
				ar & value;
				//ar & pubkey;
			}
			mpz_class value;
			std::vector<mpq_class> Z;

	};
}

#endif
