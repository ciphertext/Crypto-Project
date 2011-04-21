
#include "Encryption/Keys/PublicKey.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;


PublicKey::PublicKey(vector<int> x, vector<boost::rational<long int> > Y, vector<Cipherbit> sk)
{
	this->pk = x;
	this->y = Y;
	this->encryptedPrivateKey = sk;
}

long int PublicKey::getX(int index)
{
	return this->pk[index];
}

boost::rational<long int> PublicKey::getY(int index)
{
	return this->y[index];
}

Cipherbit PublicKey::getEncryptedSkBit(int index)
{
	return this->encryptedPrivateKey[index];
}

int PublicKey::size()
{
	return this->pk.size();
}
