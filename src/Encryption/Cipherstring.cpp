#include "Encryption/Cipherstring.hpp"
using namespace Encryption;
using namespace std;

Cipherbit & Cipherstring::operator [] (unsigned int index)
{
	return mBits[index];
}

void Cipherstring::push_back(const Cipherbit & b)
{
	mBits.push_back(b);
}

unsigned int Cipherstring::size()
{
	return mBits.size();
}