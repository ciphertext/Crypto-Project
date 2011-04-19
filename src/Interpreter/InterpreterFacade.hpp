#include <exception>
#include <string>
#include <list>
using namespace std;

#ifndef __Interpreter__InterpreterFacade_h__
#define __Interpreter__InterpreterFacade_h__

// #include "Interpreter/ProgramLoader.h"
// #include "Interpreter/CiphertextSerializer.h"
// #include "Interpreter/KeySerializer.h"
// #include "UI/UserInterface.h"

namespace Interpreter
{
	class ProgramLoader;
	class CiphertextSerializer;
	class KeySerializer;
	class InterpreterFacade;
}
namespace UI
{
	class UserInterface;
}

namespace Interpreter
{
	class InterpreterFacade
	{
		public: UI::UserInterface* _unnamed_UserInterface_;
		public: Interpreter::ProgramLoader* _unnamed_ProgramLoader_;
		public: Interpreter::CiphertextSerializer* _unnamed_CiphertextSerializer_;
		public: Interpreter::KeySerializer* _unnamed_KeySerializer_;

		public: string executeProgram(string aProgramdata, list<string> aArgs, string aKey);

		public: string decrypt(string aCiphertext, string aKey);

		public: void encrypt(string aMessage, string aKey, string aOutput);

		public: pair<publicKey : string, privateKey : string> genKeyPair();
	};
}

#endif
