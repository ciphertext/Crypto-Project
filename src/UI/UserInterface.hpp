
#ifndef __UI__UserInterface_h__
#define __UI__UserInterface_h__
#include <boost/tokenizer.hpp>
#include <string>
#include "Encryption/EncryptionFacade.hpp"
#include <exception>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>

namespace UI
{
	class UserInterface
	{
		public:
		  void start();
		  
		private:
			Encryption::EncryptionFacade encryption;
			bool running;
			
			std::string readFile(std::string file);
			void writeFile(std::string file, std::string data);
			std::vector<std::string> tokenize(std::string line);
			
			void handleEncrypt(std::string message, std::string pkfile, std::string outfile);
			void handleDecrypt(std::string csfile, std::string skfile);
			void handleKeygen (std::string pkfile, std::string skfile);
			void handleOperation(std::string operation, std::string csfile1, 
										std::string csfile2, std::string pkfile, std::string outfile);
			void handleExit();
			
			bool checkParameters(std::vector<std::string> tokens,int count);
			
			void displayHelp();
			
			
	};
}

#endif
