
#include "Encryption/Operations/AndOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


//TODO: Need to figure out default behavior for ANDing strings of different length.
Cipherstring AndOperation::operate(Cipherstring aA, Cipherstring aB)
{
	Cipherstring s;
	for(int i=0; i < min(aA.size(),aB.size()); i++)
		s.push_back(aA[i] & aB[i]);
	
	return s;
}