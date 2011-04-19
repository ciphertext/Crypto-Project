#include <exception>
using namespace std;

#ifndef __UI__UserInterface_h__
#define __UI__UserInterface_h__

// #include "Interpreter/InterpreterFacade.h"

namespace Interpreter
{
	class InterpreterFacade;
}
namespace UI
{
	class UserInterface;
}

namespace UI
{
	class UserInterface
	{
		public: Interpreter::InterpreterFacade* _unnamed_InterpreterFacade_;

		public: void start();
	};
}

#endif
