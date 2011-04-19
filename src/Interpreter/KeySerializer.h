#include <exception>
#include <string>
using namespace std;

#ifndef __Interpreter__KeySerializer_h__
#define __Interpreter__KeySerializer_h__

#include "Encryption/Keys/PublicKey.h"
#include "Encryption/Keys/PrivateKey.h"
// #include "Interpreter/InterpreterFacade.h"

namespace Encryption
{
	namespace Keys
	{
		class PublicKey;
		class PrivateKey;
	}
}
namespace Interpreter
{
	class InterpreterFacade;
	class KeySerializer;
}

namespace Interpreter
{
	class KeySerializer
	{
		public: Interpreter::InterpreterFacade* _unnamed_InterpreterFacade_;

		public: string serialize(Encryption::Keys::PublicKey aP);

		public: string serialize(Encryption::Keys::PrivateKey aP);

		public: Encryption::Keys::PublicKey unserializePk(string aPk);

		public: Encryption::Keys::PrivateKey unserializeSk(string aSk);
	};
}

#endif
