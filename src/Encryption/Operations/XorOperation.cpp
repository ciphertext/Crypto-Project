
#include "Encryption/Operations/XorOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;

//TODO: Need to figure out default behavior for XORing strings of different length.
Cipherstring XorOperation::operate(Cipherstring aA, Cipherstring aB)
{
	Cipherstring s;
	for(unsigned int i=0; i < min(aA.size(),aB.size()); i++)
		s.push_back(aA[i] ^ aB[i]);
	
	return s;
}