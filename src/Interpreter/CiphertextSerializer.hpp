#include <exception>
#include <string>
using namespace std;

#ifndef __Interpreter__CiphertextSerializer_h__
#define __Interpreter__CiphertextSerializer_h__

#include "Encryption/Cipherbit.hpp"


namespace Interpreter
{
	class CiphertextSerializer
	{
		public:
			string serialize(Encryption::Cipherbit aC);
			Encryption::Cipherbit unserialize(std::string aSerialized);
	};
}

#endif
