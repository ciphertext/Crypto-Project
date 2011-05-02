
#include "Encryption/Operations/AddOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


Cipherstring AddOperation::operate(Cipherstring aA, Cipherstring aB)
{
	Cipherstring s;
	for(unsigned int i=0; i < min(aA.size(),aB.size()); i++)
		; //TODO: implement me
	
	return s;
}
