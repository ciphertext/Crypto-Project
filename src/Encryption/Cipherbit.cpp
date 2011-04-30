
#include "Encryption/Cipherbit.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;


Cipherbit::Cipherbit(mpz_class c, vector<mpq_class> z)
{
	
	this->value = c;
	this->Z = z;
	//this->pubkey=pubkey;
}
mpz_class Cipherbit::getValue()
{
	return this->value;
}

mpq_class Cipherbit::getZ(unsigned int index)
{
	return this->Z.at(index);
}

Cipherbit Cipherbit::operator & ( const Cipherbit & cb) const
{
	
	//TODO: ADD REAL IMPLEMENTATION
	//TODO: check for ciphertext with different public keys
	return Cipherbit(value*cb.value,vector<mpq_class>(1,1));//,pubkey);
}


Cipherbit Cipherbit::operator ^ ( const Cipherbit & cb) const
{
	
	//TODO: ADD REAL IMPLEMENTATION
	//TODO: check for ciphertext with different public keys
	return Cipherbit(value+cb.value,vector<mpq_class>(1,1));//,pubkey);
}



