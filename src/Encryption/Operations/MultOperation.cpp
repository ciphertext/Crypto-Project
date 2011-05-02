
#include "Encryption/Operations/MultOperation.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


Cipherstring MultOperation::operate(Cipherstring aA, Cipherstring aB)
{
	return aA*aB;
}
