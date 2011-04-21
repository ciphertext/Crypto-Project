#include <exception>
using namespace std;

#include "Encryption/Operations/XorOperation.h"
#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Operations/CircuitBinaryOperation.h"

Encryption::Ciphertext Encryption::Operations::XorOperation::operate(Encryption::Keys::PublicKey aKey, Encryption::Ciphertext aA, Encryption::Ciphertext aB, int aBit_addr) {
	throw "Not yet implemented";
}
