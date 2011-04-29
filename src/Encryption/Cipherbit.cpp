
#include "Encryption/Cipherbit.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;


Cipherbit::Cipherbit(mpz_class c, vector<mpq_class> z)
{
	
	this->value = c;
	this->Z = z;
	this->pubkey=pubkey;
}
mpz_class Cipherbit::getValue()
{
	return this->value;
}

mpq_class Cipherbit::getZ(unsigned int index)
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
