
#include "Encryption/Keys/KeyPair.hpp"
#include "Encryption/Cipherbit.hpp"
#include "Encryption/Encryptor.hpp"
#include "TestFramework.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;

bool testCipherbit();

Keypair kp;
PublicKey pk;
PrivateKey sk;

int main()
{
	bool success=true;
	
	for(unsigned int i = 0; i < 15; i++) {
		logmsg("Generating keypair.");
		pk = kp.getPublicKey();
		sk = kp.getPrivateKey();

		success &= runTest(testCipherbitAndNorecrypt,"a & b, no recrypt");
		success &= runTest(testCipherbitXorNorecrypt,"a ^ b, no recrypt");
		success &= runTest(testCipherbitAnd,"a & b");
		success &= runTest(testCipherbitXor,"a ^ b");
	}
	
	if(!success)
		cout << "Some tests have failed." <<endl<<endl;
	else
		cout << "All tests succeeded." <<endl<<endl;
	
	return (success) ? 0 : -1;
}

bool testCipherbitAndNorecrypt()
{
	bool success = true;
	logmsg("Encrypting (0,1).");
	Cipherbit zero = Encryptor::encrypt(false,pk);
	Cipherbit one = Encryptor::encrypt(true,pk);
	one.setSaturated(false);
	zero.setSaturated(false);

	logmsg("Calculating 0 & 1...");
	Cipherbit prod = zero & one;
	logmsg("Decrypting 0 & 1...");
	bool dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("0 & 1 == 0", (!dprod));
	//================================================================

	logmsg("Calculating 1 & 0...");
	prod = one & zero;
	logmsg("Decrypting 1 & 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("1 & 0 == 0",(!dprod));
	//================================================================

	logmsg("Calculating 1 & 1...");
	prod = one & one;
	logmsg("Decrypting 1 & 1...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= dprod;

	TESTASSERT("1 & 1 == 1",(dprod));
	//================================================================

	logmsg("Calculating 0 & 0...");
	prod = zero & zero;
	logmsg("Decrypting 0 & 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("0 & 0 == 0",(!dprod));
	//================================================================

	return success;
}

bool testCipherbitXorNorecrypt()
{
	bool success = true;
	logmsg("Generating keypair.");
	KeyPair kp;
	PublicKey pk = kp.getPublicKey();
	PrivateKey sk = kp.getPrivateKey();

	logmsg("Encrypting (0,1).");
	Cipherbit zero = Encryptor::encrypt(false,pk);
	Cipherbit one = Encryptor::encrypt(true,pk);
	one.setSaturated(false);
	zero.setSaturated(false);

	logmsg("Calculating 0 ^ 1...");
	Cipherbit prod = zero ^ one;
	logmsg("Decrypting 0 ^ 1...");
	bool dprod = Encryptor::decrypt(prod,sk);

	success &= dprod;

	TESTASSERT("0 ^ 1 == 1", (dprod));
	//================================================================

	logmsg("Calculating 1 ^ 0...");
	prod = one ^ zero;
	logmsg("Decrypting 1 ^ 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= dprod;

	TESTASSERT("1 ^ 0 == 1",(dprod));
	//================================================================

	logmsg("Calculating 1 ^ 1...");
	prod = one ^ one;
	logmsg("Decrypting 1 ^ 1...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("1 ^ 1 == 0",(!dprod));
	//================================================================

	logmsg("Calculating 0 ^ 0...");
	prod = zero ^ zero;
	logmsg("Decrypting 0 ^ 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("0 ^ 0 == 0",(!dprod));
	//================================================================

	return success;
}



bool testCipherbitAnd()
{
	bool success = true;
	logmsg("Generating keypair.");
	KeyPair kp;
	PublicKey pk = kp.getPublicKey();
	PrivateKey sk = kp.getPrivateKey();

	logmsg("Encrypting (0,1).");
	Cipherbit zero = Encryptor::encrypt(false,pk);
	Cipherbit one = Encryptor::encrypt(true,pk);

	logmsg("Calculating 0 & 1...");
	Cipherbit prod = zero & one;
	logmsg("Decrypting 0 & 1...");
	bool dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("0 & 1 == 0", (!dprod));
	//================================================================

	logmsg("Calculating 1 & 0...");
	prod = one & zero;
	logmsg("Decrypting 1 & 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("1 & 0 == 0",(!dprod));
	//================================================================

	logmsg("Calculating 1 & 1...");
	prod = one & one;
	logmsg("Decrypting 1 & 1...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= dprod;

	TESTASSERT("1 & 1 == 1",(dprod));
	//================================================================

	logmsg("Calculating 0 & 0...");
	prod = zero & zero;
	logmsg("Decrypting 0 & 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("0 & 0 == 0",(!dprod));
	//================================================================

	return success;
}

bool testCipherbitXor()
{
	bool success = true;
	logmsg("Generating keypair.");
	KeyPair kp;
	PublicKey pk = kp.getPublicKey();
	PrivateKey sk = kp.getPrivateKey();

	logmsg("Encrypting (0,1).");
	Cipherbit zero = Encryptor::encrypt(false,pk);
	Cipherbit one = Encryptor::encrypt(true,pk);

	logmsg("Calculating 0 ^ 1...");
	Cipherbit prod = zero ^ one;
	logmsg("Decrypting 0 ^ 1...");
	bool dprod = Encryptor::decrypt(prod,sk);

	success &= dprod;

	TESTASSERT("0 ^ 1 == 1", (dprod));
	//================================================================

	logmsg("Calculating 1 ^ 0...");
	prod = one ^ zero;
	logmsg("Decrypting 1 ^ 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= dprod;

	TESTASSERT("1 ^ 0 == 1",(dprod));
	//================================================================

	logmsg("Calculating 1 ^ 1...");
	prod = one ^ one;
	logmsg("Decrypting 1 ^ 1...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("1 & 1 == 0",(!dprod));
	//================================================================

	logmsg("Calculating 0 ^ 0...");
	prod = one ^ one;
	logmsg("Decrypting 0 ^ 0...");
	dprod = Encryptor::decrypt(prod,sk);

	success &= !dprod;

	TESTASSERT("0 ^ 0 == 0",(!dprod));
	//================================================================

	return success;
}
