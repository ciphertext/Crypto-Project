#ifndef __Encryption__Keys__PublicKey_h__
#define __Encryption__Keys__PublicKey_h__


#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <vector>
#include <gmpxx.h>
#include <boost/shared_ptr.hpp>

namespace Encryption
{
	class Cipherbit;
	class Cipherstring;
}

#include "Encryption/Cipherbit.hpp"
#include "Encryption/Cipherstring.hpp"


namespace Encryption
{

	namespace Keys
	{
		class PublicKey
		{
			friend class boost::serialization::access;

			public:
				PublicKey();
				PublicKey(boost::shared_ptr<std::vector<mpz_class> > x,
						  boost::shared_ptr<std::vector<mpq_class> > Y,
						  const Cipherstring & sk);
				mpz_class getX(unsigned int index) const;
				mpq_class getY(unsigned int index) const;
				Cipherbit getEncryptedSkBit(unsigned int index) const;
				unsigned int xsize() const;
				unsigned int ysize() const;
				unsigned int encryptedKeySize() const;
				
				void setSk(Cipherstring sk);

				

			private:
				boost::shared_ptr<Cipherstring> encryptedPrivateKey;  
				boost::shared_ptr<std::vector<mpz_class> > x;
				boost::shared_ptr<std::vector<mpq_class> > y;
				

				template<class Archive>
				void serialize( Archive & ar, const unsigned int version)
				{
					ar & x;
					ar & y;
					ar & encryptedPrivateKey;
				};
				
		};
	}
}

#endif
