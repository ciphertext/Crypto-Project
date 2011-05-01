#include <exception>
#include <iostream>
#include <fstream>
#include <string>
#include <boost/algorithm/string.hpp>


#include "UI/UserInterface.hpp"
#include "Encryption/EncryptionFacade.hpp"
using namespace std;
using namespace UI;
using namespace Encryption;


void UserInterface::start() {
	string input;
	
	// Get input from user
	// encrypt <message> <public key file> <output file>
	// decrypt <ciphertext file> <secret key file>
	// keygen <public key file> <private key file>
	// operation <op name> <ciphertext file 1> <ciphertext file 2> <output file>
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
			PublicKey pk;
			ifstream pkFile(pkFileName);
			boost::archive::text_iarchive iaPK(pkFile);
			iaPK >> pk;
			
			Cipherstring c;
			for(int x = 0; x < message.size(); x++)
			{
				if(message[x] == '0')
				{
					Cipherbit b = Encryptor::encrypt(0,pk);
					c.push_back(b);
				}
				else
				{
					Cipherbit b = Encryptor::encrypt(1,pk);
					c.push_back(b);
				}
			}
			
			// save cipherstring to archive
			ofstream csFile(outputFileName);
			boost::archive::text_oarchive oaCS(csFile);
			oaCS << c;
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
			
			Cipherstring c; 
			ifstream csFile(csFileName);
			boost::archive::text_iarchive iaCS(csFile);
			iaCS >> c;
			
			PrivateKey sk;
			ifstream skFile(skFileName);
			boost::archive::text_iarchive iaPK(skFile);
			iaPK >> sk;
			
			string message;
			int size = c.size();
			for(int x = 0; x < size; x++)
			{
				bool b = Encryptor::decrypt(c[x],sk);
				if(b)
					message.push_back('1');
				else
					message.push_back('0');
			}
			
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
			KeyPair kp;
			PublicKey pk = kp.getPublicKey();
			PrivateKey sk = kp.getPrivateKey();
			
			// get file names
			string pkFileName(split_input[1]);
			string skFileName(split_input[2]);
			
			// create files
			ofstream pkFile(pkFileName);
			ofstream skFile(skFileName);	
			
			// save data to archive
			boost::archive::text_oarchive oaPK(pkFile);
			oaPK << pk;
			
			boost::archive::text_oarchive oaSK(skFile);
			oaSK << sk;
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
			string outName(split_input[4]);
			
			Cipherstring cs1;
			Cipherstring cs2;
			ifstream cs1File(cs1Name);
			boost::archive::text_iarchive iaCS1(cs1File);
			iaCS1 >> cs1;
			ifstream cs2File(cs2Name);
			boost::archive::text_iarchive iaCS2(cs2File);
			iaCS2 >> cs2;
			
			to_lower(op);
			Cipherstring result;
			
			if(op.compare("add") == 0)
			{
				result = AddOperation(cs1, cs2);
				ofstream outFile(outName);
				boost::archive::text_oarchive oaOutput(outFile);
				oaOutput << result;
			}
			else if(op.compare("and") == 0)
			{
				result = AndOperation(cs1, cs2);
				ofstream outFile(outName);
				boost::archive::text_oarchive oaOutput(outFile);
				oaOutput << result;
			}
			else if(op.compare("xor") == 0)
			{
				result = XorOperation(cs1, cs2);
				ofstream outFile(outName);
				boost::archive::text_oarchive oaOutput(outFile);
				oaOutput << result;
			}
			else
			{
				cout << "Invalid operation specified";
			}
		}
	}
	else
	{
		cout << "Invalid command.";
	}
}



