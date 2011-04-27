
#ifndef __Encryption__Cipherbit_h__
#define __Encryption__Cipherbit_h__

#include "Encryption/Keys/PublicKey.hpp"
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/rational.hpp>
#include <vector>

namespace Encryption
{
	class Cipherbit
	{

		public:
			Cipherbit(int c, std::vector<boost::rational<long int> > z, boost::shared_ptr<Keys::PublicKey> pubkey);
			int getValue() const;
			boost::rational<long int> getZ(int index) const;

			Cipherbit operator & ( const Cipherbit & cb) const;
			Cipherbit operator ^ ( const Cipherbit & cb) const;

		private:
			int value;
			std::vector<boost::rational<long int> > Z;
			boost::shared_ptr<Keys::PublicKey> pubkey;
			
			friend class boost::serialization::access;
			template<class Archive>
			void serialize( Archive & ar, const unsigned int version);
	};
}

#endif
