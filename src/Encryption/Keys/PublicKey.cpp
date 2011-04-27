
#include "Encryption/Keys/PublicKey.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;


PublicKey::PublicKey()
{
}

PublicKey::PublicKey(vector<long int> x, vector<boost::rational<long int> > Y, vector<Cipherbit> sk)
{
	this->x = x;
	this->y = Y;
	this->encryptedPrivateKey = sk;
}

long int PublicKey::getX(int index)
{
	return this->x[index];
}

boost::rational<long int> PublicKey::getY(int index)
{
	return this->y[index];
}

Cipherbit PublicKey::getEncryptedSkBit(int index)
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




template<class Archive>
void PublicKey::serialize( Archive & ar, const unsigned int version)
{
	ar & x;
	ar & y;
	ar & encryptedPrivateKey;
}