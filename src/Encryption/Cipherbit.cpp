
#include "Encryption/Cipherbit.hpp"

using namespace boost;
using namespace std;
using namespace Encryption;

int Cipherbit::getValue()
{
	return value;
}

boost::rational<int> Cipherbit::getZ(int index)
{
	return Z[i];
}

int Cipherbit::getMultCount()
{
	return multCount;
}

void Cipherbit::setMultCount(int c)
{
	multCount = c;
}
