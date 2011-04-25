#include "Encryption/EncryptorFacade.hpp"
#include <exception>
#include <string>
#include <list>

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;

string EncryptionFacade::executeOperation(std::string command, std::string arg1, std::string arg2, std::string aPublicKey) 
{

}

string EncryptionFacade::decrypt(std::string aCiphertext, std::string aPrivateKey) {
	throw "Not yet implemented";
}

void EncryptionFacade::encrypt(std::string aMessage, std::string aPublicKey) {
	throw "Not yet implemented";
}

pair<string, string> EncryptionFacade::genKeyPair() {
	throw "Not yet implemented";
}

