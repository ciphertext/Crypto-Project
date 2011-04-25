


#ifndef __Encryption__EncryptionFacade_h__
#define __Encryption__EncryptionFacade_h__

#include <exception>
#include <string>
#include <list>
#include <map>
#include "Encryption/Encryptor.hpp"
#include "Encryption/Operations/CipherStringBinaryOperation.hpp"

// #include "Interpreter/ProgramLoader.h"
// #include "Interpreter/CiphertextSerializer.h"
// #include "Interpreter/KeySerializer.h"
// #include "UI/UserInterface.h"


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
}

#endif
