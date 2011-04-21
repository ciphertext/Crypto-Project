
#include "Encryption/Cipherbit.hpp"

using namespace boost;
using namespace std;
using namespace Encryption;

Cipherbit::Cipherbit(int c, vector<boost::rational<int> > z)
{
	this.value = c;
	this.Z = z;
}
int Cipherbit::getValue()
{
	return this.value;
}

boost::rational<int> Cipherbit::getZ(int index)
{
	return this.Z[i];
}

int Cipherbit::getMultCount()
{
	return this.multCount;
}

void Cipherbit::setMultCount(int c)
{
	this.multCount = c;
}
