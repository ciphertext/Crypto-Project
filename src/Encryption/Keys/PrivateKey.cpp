#include <exception>
#include "Encryption/Keys/PrivateKey.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

vector<bool> sArrow;

PrivateKey::PrivateKey(vector<bool> bits)
{
	sArrow = bits;
}

bool PrivateKey::getBit(int index)
{
	return sArrow.at(index);
}