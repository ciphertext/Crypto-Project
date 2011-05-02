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

void pop_back()
{
	mBits.pop_back();
}

unsigned int Cipherstring::size() const
{
	return mBits.size();
}

void insert(std::vector<Cipherbit>::iterator it, Cipherbit a)
{
	mBits.insert(it,a);
}

std::vector<Cipherbit>::iterator begin()
{
	return mBits.begin();
}

std::vector<Cipherbit>::iterator end()
{
	return mBits.end();
}

bool empty()
{
	return mBits.empty();
}


void unsaturate()
{
	for(vector<Cipherbit>::iterator it; it = mBits.begin(); it++)
		*it.setSaturated(false);
}
