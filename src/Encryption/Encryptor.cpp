#include <exception>
#include <string>
using namespace std;

#include "Encryption/Encryptor.h"
#include "Encryption/Ciphertext.h"
#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Keys/PrivateKey.h"

Encryption::Ciphertext Encryption::Encryptor::encrypt(string aM, Encryption::Keys::PublicKey aPk) {
	throw "Not yet implemented";
}

string Encryption::Encryptor::decrypt(Encryption::Ciphertext aC, Encryption::Keys::PrivateKey aSk) {
	throw "Not yet implemented";
}

