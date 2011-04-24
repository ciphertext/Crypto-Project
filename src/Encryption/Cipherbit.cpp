
#include "Encryption/Cipherbit.hpp"

using namespace std;
using namespace Encryption;

Cipherbit::Cipherbit(mpz_class c, vector<mpq_class> z)
{
	this->value = c;
	this->Z = z;
}
mpz_class Cipherbit::getValue()
{
	return this->value;
}

mpq_class Cipherbit::getZ(unsigned int index)
{
	return this->Z.at(index);
}

unsigned int Cipherbit::getMultCount()
{
	return this->multCount;
}

void Cipherbit::setMultCount(unsigned int c)
{
	this->multCount = c;
}
