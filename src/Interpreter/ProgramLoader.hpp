#include <exception>
#include <string>
using namespace std;

#ifndef __Interpreter__ProgramLoader_h__
#define __Interpreter__ProgramLoader_h__

// #include "Interpreter/InterpreterFacade.h"

namespace Interpreter
{
	class InterpreterFacade;
	class ProgramLoader;
}

namespace Interpreter
{
	class ProgramLoader
	{
		public: Interpreter::InterpreterFacade* _unnamed_InterpreterFacade_;

		public: void loadProgram(string aProgramdata);
	};
}

#endif
