#include <exception>
#include <string>
using namespace std;

#include "Interpreter/KeySerializer.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Keys/PrivateKey.h"
#include "Interpreter/InterpreterFacade.h"

string Interpreter::KeySerializer::serialize(Encryption::Keys::PublicKey aP) {
	throw "Not yet implemented";
}

string Interpreter::KeySerializer::serialize(Encryption::Keys::PrivateKey aP) {
	throw "Not yet implemented";
}

Encryption::Keys::PublicKey Interpreter::KeySerializer::unserializePk(string aPk) {
	throw "Not yet implemented";
}

Encryption::Keys::PrivateKey Interpreter::KeySerializer::unserializeSk(string aSk) {
	throw "Not yet implemented";
}

