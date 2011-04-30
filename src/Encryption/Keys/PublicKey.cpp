
#include "Encryption/Keys/PublicKey.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;


PublicKey::PublicKey()
{
}

PublicKey::PublicKey(vector<mpz_class> x, vector<mpq_class> Y, vector<Cipherbit> sk)
{
	this->x = x;
	this->y = Y;
	this->encryptedPrivateKey = sk;
}

mpz_class PublicKey::getX(unsigned int index) const
{
	return x.at(index);
}

mpq_class PublicKey::getY(unsigned int index) const
{
	return y.at(index);
}

Cipherbit PublicKey::getEncryptedSkBit(unsigned int index) const
{
	return encryptedPrivateKey[index];
}

unsigned int PublicKey::ysize() const
{
	return y.size();
}

unsigned int PublicKey::xsize() const
{
	return x.size();
}


unsigned int PublicKey::encryptedKeySize() const
{
	return encryptedPrivateKey.size();
}

