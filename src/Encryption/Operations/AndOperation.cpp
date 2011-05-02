
#include "Encryption/Operations/AndOperation.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


Cipherstring AndOperation::operate(Cipherstring aA, Cipherstring aB)
{
	
	return aA & aB;
}