#include <exception>
#include <iostream>
#include <fstream>
#include <string>
#include <boost/algorithm/string.hpp>
#include <Encryption/EncryptionFacade.hpp>

using namespace std;

#include "UI/UserInterface.h"

void UI::UserInterface::start() {
	string input;
	bool repeat = true;
	cout << "Available Commands";	
	cout << "==================";

	cout << "encrypt <message> <public key file> <output file>";
	cout << "decrypt <ciphertext file> <secret key file>";
	cout << "keygen <public key file> <private key file>";
	cout << "operation <operation name> <ciphertext file 1> <ciphertext file 2>  <public key file> <output file>";
	cout << "==================\n";
		
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
				string pk;
				ifstream pkFile(pkFileName);
				pkFile >> pk;
				pkFile.close();
				
				EncryptionFacade ef;
				string ciphertext = ef.encrypt(message, pk);
				
				// save cipherstring to archive
				ofstream csFile(outputFileName);
				csFile << ciphertext;
				csFile.close();
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
				
				string ciphertext;
				ifstream csFile(csFileName);
				csFile >> ciphertext;
				csFile.close();
				
				string sk;
				ifstream skFile(skFileName);
				skFile >> sk;
				skFile.close();
				
				EncryptionFacade ef;
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
				EncryptionFacade ef;
				pair<string, string> kp = ef.genKeyPair();					
				
				// get file names
				string pkFileName(split_input[1]);
				string skFileName(split_input[2]);
				
				// create files
				ofstream pkFile(pkFileName);
				ofstream skFile(skFileName);	
				
				// save data
				pkFile << kp.first;
				skFile << kp.second;
				
				pkFile.close();
				skFile.close();
			}
		}
		else if(command.compare("operation") == 0)
		{
			// check command before continuing
			if(split_input.size() != 5)
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
				
				string cs1;
				string cs2;
				string pk;
				ifstream cs1File(cs1Name);
				cs1File >> cs1;
				ifstream cs2File(cs2Name);
				cs2File >> cs2;
				ifstream pkFile(pkName);
				pkFile >> pk;
				
				cs1File.close();
				cs2File.close();
				pkFile.close();
				
				EncryptionFacade ef;
				string result = ef.executeOperation(op, cs1, cs2, pk);
				
				ofstream outFile(outName);
				outFile << result;
				outFile.close();
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



