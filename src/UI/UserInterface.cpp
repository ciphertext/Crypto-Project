#include <exception>
#include <iostream>
#include <fstream>
#include <string>
#include <boost/algorithm/string.hpp>
#include <Encryption/EncryptionFacade.hpp>


#include "UI/UserInterface.hpp"
#include "Encryption/EncryptionFacade.hpp"
using namespace std;
using namespace UI;
using namespace Encryption;
using namespace boost;

void UserInterface::start() {
	string input;
	bool repeat = true;
	cout << "Available Commands\n";	
	cout << "==================\n";

	cout << "encrypt <message> <public key file> <output file>\n";
	cout << "decrypt <ciphertext file> <secret key file>\n";
	cout << "keygen <public key file> <private key file>\n";
	cout << "operation <operation name> <ciphertext file 1> <ciphertext file 2>  <public key file> <output file>\n";
	cout << "==================\n";
		
	EncryptionFacade ef;
	while(repeat)
	{
		// Get input from user
		// encrypt <message> <public key file> <output file>
		// decrypt <ciphertext file> <secret key file>
		// keygen <public key file> <private key file>
		// operation <op name> <ciphertext file 1> <ciphertext file 2> <public key file> <output file>
				
		cout << "Enter command: ";
		getline(cin, input);
		
		// split input on space
		// token compress to discount extra spacing
		vector<string> split_input;
		split(split_input,input,is_any_of(" "), token_compress_on);
		
		string command(split_input[0]);
		to_lower(command);
		
		if(command.compare("encrypt") == 0)
		{
			// check command before continuing
			if(split_input.size() != 4)
			{
				cout << "Check command parameters.";
				break;
			}
			else
			{
				string message(split_input[1]);
				string pkFileName(split_input[2]);
				string outputFileName(split_input[3]);
				
				// read in public key
				string pk = readFile(pkFileName);
				
				string ciphertext = ef.encrypt(message, pk);
				
				writeFile(outputFileName,ciphertext);
			}
		}
		else if(command.compare("decrypt") == 0)
		{
			// check command before continuing
			if(split_input.size() != 3)
			{
				cout << "Check command parameters.";
				break;
			}
			else
			{
				string csFileName(split_input[1]);
				string skFileName(split_input[2]);
				
				string ciphertext = readFile(csFileName);
				
				string sk = readFile(skFileName);
				
				string message = ef.decrypt(ciphertext, sk);
				
				cout << message;
			}
		}
		else if(command.compare("keygen") == 0)
		{
			// check command before continuing
			if(split_input.size() != 3)
			{
				cout << "Check command parameters.";
				break;
			}
			else
			{
				pair<string, string> kp = ef.genKeyPair();					
				
				// get file names
				string pkFileName(split_input[1]);
				string skFileName(split_input[2]);
				
				// create files
				writeFile(pkFileName,kp.first);
				writeFile(skFileName,kp.second);
			}
		}
		else if(command.compare("operation") == 0)
		{
			// check command before continuing
			if(split_input.size() != 6)
			{
				cout << "Check command parameters.";
				break;
			}
			else
			{
				// operations: add, and, xor
				string op(split_input[1]);
				string cs1Name(split_input[2]);
				string cs2Name(split_input[3]);
				string pkName(split_input[4]);
				string outName(split_input[5]);
				
				string cs1 = readFile(cs1Name);
				string cs2 = readFile(cs2Name);
				string pk  = readFile(pkName);
				
				
				
				string result = ef.executeOperation(op, cs1, cs2, pk);
				
				writeFile(outName, result);
			}
		}
		else if(command.compare("exit") == 0)
		{
			repeat = false;
		}
		else
		{
			cout << "Invalid command.";
		}
	}
}
std::string UserInterface::readFile(std::string file)
{
	ifstream input(file.c_str());
   return string((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
}

void UserInterface::writeFile(std::string file, std::string data)
{
	ofstream output(file.c_str());
	copy(data.begin(), data.end(), ostreambuf_iterator<char>(output));
}
 
