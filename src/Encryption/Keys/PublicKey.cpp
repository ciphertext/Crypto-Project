
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

mpz_class PublicKey::getX(unsigned int index)
{
	return this->x[index];
}

mpq_class PublicKey::getY(unsigned int index)
{
	return this->y[index];
}

Cipherbit PublicKey::getEncryptedSkBit(unsigned int index)
{
	return this->encryptedPrivateKey[index];
}

unsigned int PublicKey::ysize()
{
	return this->y.size();
}

unsigned int PublicKey::xsize()
{
	return this->x.size();
}




