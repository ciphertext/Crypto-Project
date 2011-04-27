#include <exception>
#include "Encryption/Keys/PrivateKey.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

PrivateKey::PrivateKey()
{
}

PrivateKey::PrivateKey(vector<bool> bits)
{
	this->sArrow = bits;
}

bool PrivateKey::getBit(int index)
{
	return this->sArrow[index];
}

unsigned int PrivateKey::size()
{
	return this->sArrow.size();
}

template<class Archive>
void PrivateKey::serialize( Archive & ar, const unsigned int version)
{
	ar & sArrow;
}