

#include "UI/UserInterface.hpp"

using namespace std;
using namespace UI;
using namespace Encryption;
using namespace boost;

void UserInterface::start() {
	string input;
   running=true;

	displayHelp();
		

	while(running)
	{
		// Get input from user
		// encrypt <message> <public key file> <output file>
		// decrypt <ciphertext file> <secret key file>
		// keygen <public key file> <private key file>
		// operation <op name> <ciphertext file 1> <ciphertext file 2> <public key file> <output file>
				
		input = getInput();
		
		vector<string> split_input = tokenize(input);
		// split input on space
		// token compress to discount extra spacing
		//split(split_input,input,is_any_of(" "), token_compress_on);
		
		string command(split_input[0]);
		to_lower(command);
		
		if(command =="encrypt")
		{
          if(!checkParameters(split_input, 3)) 
				 continue;
          handleEncrypt(split_input[1],split_input[2],split_input[3]);
		}
		
		else if(command == "decrypt")
		{
          if(!checkParameters(split_input,2)) 
				 continue;
          handleDecrypt(split_input[1],split_input[2]);
		}
		
		else if(command == "keygen")
		{
          if(!checkParameters(split_input,2)) 
				 continue;
          handleKeygen(split_input[1],split_input[2]);
		}
		
		else if(command == "operation")
		{
          if(!checkParameters(split_input,5)) 
				 continue;
          handleOperation(split_input[1],split_input[2],split_input[3],split_input[4],split_input[5]);
		}

		else if(command == "help")
		{
			if(!checkParameters(split_input,0)) 
				continue;
			displayHelp();
		}
		

		else if(command == "exit")
		{
			if(!checkParameters(split_input,0)) 
				continue;
			handleExit();
		}
		
		else
		{
			cout << "Invalid command.\n";
		}
	}
}

vector<string> UserInterface::tokenize(std::string line)
{
	boost::escaped_list_separator<char> els(std::string(""),std::string(" "),std::string("\"\'"));
        boost::tokenizer<boost::escaped_list_separator<char> > tok(line, els);
	
	//boost::tokenizer<> tok(line);
	vector<string> tokens;
	for(boost::tokenizer<boost::escaped_list_separator<char> >::iterator i=tok.begin(); i!=tok.end();i++)
	{
	  if(*i=="")
	    continue;
	  tokens.push_back(*i);
	}
	return tokens;
};


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
 

void UserInterface::handleEncrypt(std::string message, std::string pkfile, std::string outfile)
{
	
	unsigned char c = boost::lexical_cast<int>(message);
	 
	// read in public key
	string pk = readFile(pkfile);
	
	string s;
	
	s+=c;
	
	
	try{
		string ciphertext = encryption.encrypt(s, pk);
		writeFile(outfile,ciphertext);
	}
	catch (boost::archive::archive_exception ex)
	{
		cout << "Invalid public key file!"<<endl;
	}
	
}


void UserInterface::handleDecrypt(std::string csfile, std::string skfile)
{
	
	string ciphertext = readFile(csfile);
	
	string sk = readFile(skfile);
	
	
	try{
		string message = encryption.decrypt(ciphertext, sk);
		
		cout <<endl<<(int)(unsigned char)message[0]<<endl;// boost::lexical_cast<int>(message) << endl;
	}
	catch (boost::archive::archive_exception ex)
	{
		cout << "Invalid input files!"<<endl;
	}
}


void UserInterface::handleKeygen (std::string pkfile, std::string skfile)
{
	pair<string, string> kp = encryption.genKeyPair();
	
	// create files
	writeFile(pkfile,kp.first);
	writeFile(skfile,kp.second);
}

void UserInterface::handleOperation(std::string operation, std::string csfile1, 
							std::string csfile2, std::string pkfile, std::string outfile)
{
		// operations: add, and, xor

	string cs1 = readFile(csfile1);
	string cs2 = readFile(csfile2);
	string pk  = readFile(pkfile);
	

	try{
		string result = encryption.executeOperation(operation, cs1, cs2, pk);
		writeFile(outfile, result);
	}
	catch (boost::archive::archive_exception ex)
	{
		cout << "Invalid input files!"<<endl;
	}
	catch (const char * ex)
	{
		cout << ex<<endl;
	}
}

void UserInterface::handleExit()
{
	cout<<"\nExiting...\n";
	running=false;
}

bool UserInterface::checkParameters(vector<string> tokens,unsigned int count)
{
  if ( tokens.size()!= count+1)
  {
	  cout<< "\nError: Incorrect number of arguments for command.\n";
	  return false;
  }
  return true;
}


void UserInterface::displayHelp()
{
 	cout << "Available Commands\n";	
	cout << "==================\n";

	cout << "encrypt <message> <public key file> <output file>\n";
	cout << "decrypt <ciphertext file> <secret key file>\n";
	cout << "keygen <public key file> <private key file>\n";
	cout << "operation <operation name> <ciphertext file 1> <ciphertext file 2>  <public key file> <output file>\n";
	cout << "help\n";
	cout << "exit\n";
	cout << "==================\n"; 
}


//use GNU Readline to get a line of input.
string UserInterface::getInput()
{
	string prompt = "Enter Command: ";
	char * line=NULL;
	while(line==NULL)
	{
	  line=readline(prompt.c_str());
	
	  add_history(line);
	  string sline(line);
  	  free(line);
	  line=NULL;
	  if(sline!="")
	    return sline;
	}
	
	//needed to get rid of annoying compiler warning
	return string();
}
    