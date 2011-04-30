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

bool PrivateKey::getBit(int index) const
{
	return this->sArrow[index];
}

unsigned int PrivateKey::size() const
{
	return this->sArrow.size();
}

