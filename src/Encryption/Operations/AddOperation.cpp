
#include "Encryption/Operations/AddOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


Cipherstring AddOperation::operate(Cipherstring aA, Cipherstring aB)
{
	return aA+aB;
}
