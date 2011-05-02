#include "Encryption/Cipherstring.hpp"
using namespace Encryption;
using namespace std;

Cipherstring::Cipherstring()
: mBits()
{
}

Cipherstring::Cipherstring(int count, const Cipherbit& value)
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

void Cipherstring::pop_back()
{
	mBits.pop_back();
}

unsigned int Cipherstring::size() const
{
	return mBits.size();
}

void Cipherstring::insert(std::vector<Cipherbit>::iterator it, Cipherbit a)
{
	mBits.insert(it,a);
}

std::vector<Cipherbit>::iterator Cipherstring::begin()
{
	return mBits.begin();
}

std::vector<Cipherbit>::iterator Cipherstring::end()
{
	return mBits.end();
}

bool Cipherstring::empty()
{
	return mBits.empty();
}


void Cipherstring::unsaturate()
{
	for(vector<Cipherbit>::iterator it = mBits.begin(); it != mBits.end(); it++)
		(*it).setSaturated(false);
}
