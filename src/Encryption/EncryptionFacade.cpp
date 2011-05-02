#include "Encryption/EncryptionFacade.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;


EncryptionFacade::EncryptionFacade()
{
   addOperation("add",new AddOperation());
   addOperation("and",new AndOperation());
   addOperation("or",new OrOperation());
   addOperation("xor",new XorOperation());
   addOperation("mult",new MultOperation());
	
}


string EncryptionFacade::executeOperation(std::string command, std::string arg1, std::string arg2, std::string aPublicKey) 
{
	if(mCmdMap.count(command)==0)
		throw "Invalid command!";
	
	CipherStringBinaryOperation & op= mCmdMap.at(command);
	
	return serialize( op.operate(unserialize<Cipherstring>(arg1), unserialize<Cipherstring>(arg2)) );
}

string EncryptionFacade::decrypt(std::string aCiphertext, std::string aPrivateKey) 
{
	return toString( decryptString( unserialize<Cipherstring>(aCiphertext), unserialize<PrivateKey>(aPrivateKey) ));
}

string EncryptionFacade::encrypt(std::string aMessage, std::string aPublicKey) 
{
	return serialize( encryptString( aMessage, unserialize<PublicKey>(aPublicKey) ) );
}

pair<string, string> EncryptionFacade::genKeyPair() 
{
	KeyPair kp;
	return pair<string,string>(serialize(kp.getPublicKey()),serialize(kp.getPrivateKey()));
}



Cipherstring EncryptionFacade::encryptString(std::string message, const PublicKey & pk) const
{
	Cipherstring ciphertext;
	bitstring_t bits = toBits(message);
	for(unsigned long i=0; i< bits.size(); i++)
	{
		ciphertext.push_back( Encryptor::encrypt(bits[i],pk));
	}
	return ciphertext;
}

EncryptionFacade::bitstring_t EncryptionFacade::decryptString(const Cipherstring & ciphertext, const PrivateKey & sk) const
{
	bitstring_t bits;
	for(unsigned long i=0; i< ciphertext.size();i++)
	{
		bits.push_back( Encryptor::decrypt(ciphertext.at(i),sk));
	}
	return bits;
}

EncryptionFacade::bitstring_t EncryptionFacade::toBits(std::string text) const
{
	bitstring_t bits;
	reverse(text.begin(),text.end());
	BOOST_FOREACH(char c, text)
	{
		bits.append(c);
	}
	return bits;
}

std::string EncryptionFacade::toString(bitstring_t bits) const
{
	ostringstream oss;
	for(unsigned int i=0; i < bits.size(); i+=8)
	{
		unsigned char c=0;
		for(unsigned int j=0; j < 8 ; j++)
		{
			c *=2;
			if(bits.test(bits.size()-(i+j)-1))
				c++;
		}
		oss << c;
	}
	
	return oss.str();
}


void EncryptionFacade::addOperation(string opname, CipherStringBinaryOperation * operation)
{
	mCmdMap.insert(opname,operation);
}


