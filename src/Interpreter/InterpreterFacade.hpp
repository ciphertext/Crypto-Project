

#ifndef __Interpreter__InterpreterFacade_h__
#define __Interpreter__InterpreterFacade_h__


#include <exception>
#include <string>
#include <utility>
#include <list>
#include "Interpreter/ProgramLoader.hpp"
#include "Interpreter/CiphertextSerializer.hpp"
#include "Interpreter/KeySerializer.hpp"
#include "UI/UserInterface.hpp"


namespace Interpreter
{
	
	class InterpreterFacade
	{
		public:
			
			ProgramLoader mProgramLoader;
			CiphertextSerializer mCiphertextSerializer;
			KeySerializer mKeySerializer;

			string executeProgram(std::string aProgramdata, std::list<std::string> aArgs, std::string aKey);

			string decrypt(std::string aCiphertext, std::string aKey);

			void encrypt(std::string aMessage, std::string aKey, std::string aOutput);

			std::pair<std::string, std::string> genKeyPair();
	};
}

#endif
