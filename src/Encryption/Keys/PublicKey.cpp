
#include "Encryption/Keys/PublicKey.hpp"

using namespace std;
using namespace boost;
using namespace Encryption;
using namespace Encryption::Keys;

vector<long int> pk;
vector<rational<long int>> y;
vector<Cipherbit> encryptedPrivateKey;  

PublicKey::PublicKey(vector<int> x, vector<rational<int> > Y, vector<Cipherbit> sk)
{
	pk = x;
	y = Y;
	encryptedPrivateKey = sk;
}

long int PublicKey::getX(int index)
{
	return pk.at(index);
}

rational<long int> PublicKey::getY(int index)
{
	return y.at(index);
}

Cipherbit PublicKey::getEncryptedSkBit(int index)
{
	return encryptedPrivateKey.at(index);
}
