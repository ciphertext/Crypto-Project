
#include "Encryption/Cipherbit.hpp"

using namespace boost;
using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

Cipherbit::Cipherbit(int c, vector<rational<long int> > z, shared_ptr<PublicKey> pubkey)
{
	
	this->value = c;
	this->Z = z;
	this->pubkey=pubkey;
}
int Cipherbit::getValue()
{
	return this->value;
}

boost::rational<long int> Cipherbit::getZ(int index)
{
	return this->Z.at(index);
}


Cipherbit Cipherbit::operator & ( const Cipherbit & cb)
{
	
	//TODO: ADD REAL IMPLEMENTATION
	//TODO: check for ciphertext with different public keys
	return Cipherbit(value*cb.value,vector<boost::rational<long int> >(),pubkey);
}

Cipherbit Cipherbit::operator ^ ( const Cipherbit & cb)
{
	
	//TODO: ADD REAL IMPLEMENTATION
	//TODO: check for ciphertext with different public keys
	return Cipherbit(value+cb.value,vector<boost::rational<long int> >(),pubkey);
}


template<class Archive>
void Cipherbit::serialize( Archive & ar, const unsigned int version)
{
	ar & Z;
	ar & c;
	ar & pubkey;
}