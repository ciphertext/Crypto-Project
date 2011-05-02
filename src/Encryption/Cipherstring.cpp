#include "Encryption/Cipherstring.hpp"
using namespace Encryption;
using namespace std;

Cipherbit & Cipherstring::operator [] (unsigned int index)
{
	return mBits[index];
}

Cipherbit Cipherstring::at(unsigned int index) const
{
	return mBits.at(index);
}

void Cipherstring::push_back(const Cipherbit & b)
{
	mBits.push_back(b);
}

unsigned int Cipherstring::size() const
{
	return mBits.size();
}

