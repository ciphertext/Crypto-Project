#include <exception>
#include <list>
using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

#include "Encryption/CircuitProgram.h"
#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Operations/CircuitBinaryOperation.h"

Ciphertext CircuitProgram::execute(PublicKey aKey, list<Ciphertext> aArgs) {
	throw "Not yet implemented";
}

