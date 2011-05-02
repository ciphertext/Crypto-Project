#include "Encryption/Cipherstring.hpp"
using namespace Encryption;
using namespace std;

Cipherstring::Cipherstring()
: mBits()
{
}

Cipherstring(int count, const Cipherbit& value)
: mBits(count, value)
{
}

Cipherbit & Cipherstring::operator [] (unsigned int index)
{
	return mBits[index];
}

Cipherbit Cipherstring::at(unsigned int index) const
{
	return mBits.at(index);
}

Cipherbit Cipherstring::back() const
{
	return mBits.back();
}

void Cipherstring::push_back(const Cipherbit & b)
{
	mBits.push_back(b);
}

unsigned int Cipherstring::size() const
{
	return mBits.size();
}

void unsaturate()
{
	for(vector<Cipherbit>::iterator it; it = mBits.begin(); it++)
		*it.setSaturated(false);
}
