
#include "Encryption/Keys/PublicKey.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;


PublicKey::PublicKey()
{
}

PublicKey::PublicKey(boost::shared_ptr <vector<mpz_class> > x, boost::shared_ptr <vector<mpq_class> > Y, const Cipherstring & sk)
:encryptedPrivateKey(boost::shared_ptr<Cipherstring>(new Cipherstring(sk))),
x(x), y(Y)
{
	//this->x = boost::shared_ptr<vector<mpz_class> > (new vector<mpz_class> (x));
	//this->y = boost::shared_ptr<vector<mpq_class> > (new vector<mpq_class> (Y));
	
}

mpz_class PublicKey::getX(unsigned int index) const
{
	return x->at(index);
}

mpq_class PublicKey::getY(unsigned int index) const
{
	return y->at(index);
}

Cipherbit PublicKey::getEncryptedSkBit(unsigned int index) const
{
	return encryptedPrivateKey->at(index);
}

unsigned int PublicKey::ysize() const
{
	return y->size();
}

unsigned int PublicKey::xsize() const
{
	return x->size();
}


unsigned int PublicKey::encryptedKeySize() const
{
	return encryptedPrivateKey->size();
}
