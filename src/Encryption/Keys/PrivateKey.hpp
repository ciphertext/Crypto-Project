#include <exception>

#ifndef __Encryption__Keys__PrivateKey_h__
#define __Encryption__Keys__PrivateKey_h__

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include<vector>

namespace Encryption
{
	namespace Keys
	{
		class PrivateKey
		{

			public:
				PrivateKey();
				PrivateKey(std::vector<bool> bits);
				bool getBit(int index);
				unsigned int size();
				
			private:
				std::vector<bool> sArrow;
				
				friend class boost::serialization::access;
				template<class Archive>
				void serialize( Archive & ar, const unsigned int version);

		};
	}
}

#endif
