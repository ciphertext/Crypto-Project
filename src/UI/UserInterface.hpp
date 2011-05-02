
#ifndef __UI__UserInterface_h__
#define __UI__UserInterface_h__
#include <boost/tokenizer.hpp>
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
			std::vector<std::string> tokenize(std::string line);
	};
}

#endif
