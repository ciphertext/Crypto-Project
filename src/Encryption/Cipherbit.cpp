
#include "Encryption/Cipherbit.hpp"

using namespace boost;
using namespace std;
using namespace Encryption;

Cipherbit::Cipherbit(int c, vector<boost::rational<long int> > z)
{
	this->value = c;
	this->Z = z;
}
int Cipherbit::getValue()
{
	return this->value;
}

boost::rational<long int> Cipherbit::getZ(int index)
{
	return this->Z.at(index);
}

int Cipherbit::getMultCount()
{
	return this->multCount;
}

void Cipherbit::setMultCount(int c)
{
	this->multCount = c;
}
