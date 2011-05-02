
#include "Encryption/Operations/XorOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;

//TODO: Need to figure out default behavior for XORing strings of different length.
Cipherstring XorOperation::operate(Cipherstring aA, Cipherstring aB)
{

	return aA^aB;
}