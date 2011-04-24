
#include "Interpreter/KeySerializer.hpp"
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"
#include "Interpreter/InterpreterFacade.hpp"

#include <exception>
#include <string>
using namespace std;
using namespace Interpreter;
using namespace Encryption;
using namespace Encryption::Keys;

string KeySerializer::serialize(PublicKey aP) {
	throw "Not yet implemented";
}

string KeySerializer::serialize(PrivateKey aP) {
	throw "Not yet implemented";
}

PublicKey KeySerializer::unserializePk(string aPk) {
	throw "Not yet implemented";
}

PrivateKey KeySerializer::unserializeSk(string aSk) {
	throw "Not yet implemented";
}

