


#ifndef __Encryption__EncryptionFacade_h__
#define __Encryption__EncryptionFacade_h__


#include "Encryption/Encryptor.hpp"
#include "Encryption/Operations/CipherStringBinaryOperation.hpp"
#include <exception>
#include <string>
#include <list>
#include <map>
#include <boost/serialization/string.hpp>
#include <sstream>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

namespace Encryption
{
	class EncryptionFacade
	{
		public:
			std::string executeOperation(std::string command, std::string arg1, std::string arg2, std::string aPublicKey);
			
			std::string decrypt(std::string aCiphertext, std::string aPrivateKey);
			
			std::string encrypt(std::string aMessage, std::string aPublicKey);
			
			std::pair<std::string,std::string> genKeyPair();
			
		private:
			typedef std::map<std::string, Encryption::Operations::CipherStringBinaryOperation> CommandMap;
			CommandMap mCmdMap;
			
			
	};   
	
	template<typename T>
	std::string serialize(T t);
	
	template<typename T>
	T unserialize(std::string s);
}

#endif
