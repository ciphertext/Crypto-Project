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
	if(mCmdMap.count(command)==0)
		throw "Invalid command";
	
	CipherStringBinaryOperation op= mCmdMap.at(command);
	
	return serialize( op.operate(unserialize<Cipherstring>(arg1), unserialize<Cipherstring>(arg2)) );
		
}

string EncryptionFacade::decrypt(std::string aCiphertext, std::string aPrivateKey) 
{
	
	return serialize( Encryptor.decrypt( unserialize<Cipherstring>(aCiphertext), unserialize<PrivateKey>(aPrivateKey) ));
}

string EncryptionFacade::encrypt(std::string aMessage, std::string aPublicKey) 
{
	//TODO: Implement me
}

pair<string, string> EncryptionFacade::genKeyPair() 
{
	//TODO: Implement me	
}

template<typename T>
string serialize(T t)
{
	ostringstream oss;
	archive::text_oarchive ar(oss);

	ar << t;
	return oss.str();
}


template<typename T>
T unserialize(string s)
{
	T t;
	istringstream iss(s);
	archive::text_iarchive ar(iss);
	ar >> t;
	return t;
}