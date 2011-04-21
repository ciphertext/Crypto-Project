
#ifndef __Encryption__Cipherbit_h__
#define __Encryption__Cipherbit_h__

#include <boost/rational.hpp>
#include <vector>

namespace Encryption
{
	class Cipherbit
	{
		private:
			int value;
			std::vector<boost::rational<int> > Z;
			int multCount;
		public:
			Cipherbit(int c, std::vector<boost::rational<int> > z);
			int getValue();
			boost::rational<int> getZ(int index);
			int getMultCount();
			void setMultCount(int c);
	};
}

#endif
