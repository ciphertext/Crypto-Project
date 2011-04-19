#include <exception>
#include <string>
using namespace std;

#ifndef __Interpreter__CiphertextSerializer_h__
#define __Interpreter__CiphertextSerializer_h__

#include "Encryption/Ciphertext.h"
// #include "Interpreter/InterpreterFacade.h"

namespace Encryption
{
	class Ciphertext;
}
namespace Interpreter
{
	class InterpreterFacade;
	class CiphertextSerializer;
}

namespace Interpreter
{
	class CiphertextSerializer
	{
		public: Interpreter::InterpreterFacade* _unnamed_InterpreterFacade_;

		public: string serialize(Encryption::Ciphertext aC);

		public: Encryption::Ciphertext unserialize(string aSerialized);
	};
}

#endif
