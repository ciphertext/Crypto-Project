
#ifndef __UI__UserInterface_h__
#define __UI__UserInterface_h__

#include <string>

namespace UI
{
	class UserInterface
	{
		public:
		  void start();
		  
		private:
			std::string readFile(std::string file);
			void writeFile(std::string file, std::string data);
	};
}

#endif
