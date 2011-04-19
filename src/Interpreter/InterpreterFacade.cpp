#include <exception>
#include <string>
#include <list>
using namespace std;

#include "Interpreter/InterpreterFacade.h"
#include "Interpreter/ProgramLoader.h"
#include "Interpreter/CiphertextSerializer.h"
#include "Interpreter/KeySerializer.h"
#include "UI/UserInterface.h"

string Interpreter::InterpreterFacade::executeProgram(string aProgramdata, list<string> aArgs, string aKey) {
	throw "Not yet implemented";
}

string Interpreter::InterpreterFacade::decrypt(string aCiphertext, string aKey) {
	throw "Not yet implemented";
}

void Interpreter::InterpreterFacade::encrypt(string aMessage, string aKey, string aOutput) {
	throw "Not yet implemented";
}

pair<publicKey : string, privateKey : string> Interpreter::InterpreterFacade::genKeyPair() {
	throw "Not yet implemented";
}

