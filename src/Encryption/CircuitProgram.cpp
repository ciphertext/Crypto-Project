#include <exception>
#include <list>
using namespace std;

#include "Encryption/CircuitProgram.h"
#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Operations/CircuitBinaryOperation.h"

Encryption::Ciphertext Encryption::CircuitProgram::execute(Encryption::Keys::PublicKey aKey, list<Encryption::Ciphertext> aArgs) {
	throw "Not yet implemented";
}

