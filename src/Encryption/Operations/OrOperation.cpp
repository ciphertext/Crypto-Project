
#include "Encryption/Operations/OrOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


//TODO: Need to figure out default behavior for ANDing strings of different length.
Cipherstring OrOperation::operate(Cipherstring aA, Cipherstring aB)
{

	return aA|aB;
}
