
#ifndef __Encryption__Cipherbit_h__
#define __Encryption__Cipherbit_h__

#include <boost/rational.hpp>

namespace Encryption
{
	class Cipherbit
	{
	  int getValue();
	  boost::rational<int> getZ(int index);
	  int getMultCount();
	  void setMultCount(int c);
	};
}

#endif
