#include "Encryption/EncryptionFacade.hpp"
#include <time.h>
#include <boost/lexical_cast.hpp>
#include <gmpxx.h>
#include "TestFramework.hpp"
#include "TestUtility.hpp"
#include <utility>

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;

bool testEncryption();

string getRandomString();

int main()
{
   bool success=true;
	
	success&= runTest(testEncryption,"Encryption");
	
	if(!success)
		cout << "Some tests have failed." <<endl<<endl;
	else
		cout << "All tests succeeded." <<endl<<endl;
	
	return (success) ? 0 : -1;
}


bool testEncryption()
{
	EncryptionFacade ef;
	logmsg( "Generating keypair...");
	pair<string,string> kp = ef.genKeyPair();
	
	string message = getRandomString();
	
	logmsg( boost::lexical_cast<string>(message.size()) + " bytes to encrypt. Encrypting...");
	
	string ciphertext = ef.encrypt(message, kp.first);
	
	logmsg( "Encryption complete. "+ boost::lexical_cast<string>(ciphertext.size()) + " bytes.  Commencing decryption...");
	
	string message2 = ef.decrypt(ciphertext, kp.second);
	
	logmsg("Original Message : " + message);
	logmsg("Decrypted Message: " + message2);
	
	TESTASSERT("Message decrypted correctly", (message==message2))
	
	return true;
}





string getRandomString()
{
	gmp_randclass rnd(gmp_randinit_mt);
	rnd.seed(time(NULL));
	mpz_class length =rnd.get_z_range(20) + 10;
	string s;
	
	for(unsigned int i =0; i < length; i++)
	{
		mpz_class n=rnd.get_z_range(52)+'A';
		s+=(char)n.get_si();	
	}
	
	return s;	
}