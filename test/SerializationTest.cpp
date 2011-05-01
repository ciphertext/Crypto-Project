#include "Encryption/EncryptionFacade.hpp"
#include <time.h>
#include <boost/lexical_cast.hpp>
#include <gmpxx.h>
#include "TestFramework.hpp"
#include "TestUtility.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;


bool testSerializeCipherbit();
bool testSerializeCipherstring();
bool testSerializePublicKey();
bool testSerializePrivateKey();


Cipherbit getRandomCipherbit();
PublicKey getRandomPublicKey();
PrivateKey getRandomPrivateKey();
Cipherstring getRandomCipherstring();

//----------------------------------------
//            Implementation
//----------------------------------------


int main()
{
   bool success=true;
	
	success&= runTest(testSerializeCipherbit,"Test Cipherbit Serialization");
	success&= runTest(testSerializeCipherstring,"Test Cipherstring Serialization");
	success&= runTest(testSerializePublicKey,"Test PublicKey Serialization");
	success&= runTest(testSerializePrivateKey,"Test PrivateKey Serialization");
	
	if(!success)
		cout << "Some tests have failed." <<endl<<endl;
	else
		cout << "All tests succeeded." <<endl<<endl;
	
	return (success) ? 0 : -1;
}


//-----------------------------------------------
//                  TESTS
//-----------------------------------------------


bool testSerializeCipherbit()
{
	Cipherbit b(getRandomCipherbit());
	string s= serialize(b);
	TESTASSERTV("Data was serialized", !s.empty(), boost::lexical_cast<string>(s.size())+" bytes.");
	
	Cipherbit b2 (unserialize<Cipherbit>(s));
	
	TESTASSERT("Values preserved", (b==b2));
	
	return true;
}


bool testSerializeCipherstring()
{
	Cipherstring cs(getRandomCipherstring());
	logmsg("Using cipherstring of length " + boost::lexical_cast<string>(cs.size()));
	
	string s = serialize(cs);
	TESTASSERTV("Data was serialized", !s.empty(), boost::lexical_cast<string>(s.size())+" bytes.");
	
	Cipherstring cs2(unserialize<Cipherstring>(s));
	
	TESTASSERT("Cipherstrings of same length", (cs.size()==cs2.size()));
	
   bool equal = (cs==cs2);
	
	TESTASSERT("Cipherstring unserialized correctly", equal);
	
	return true;
}


bool testSerializePublicKey()
{
	PublicKey pk(getRandomPublicKey());
	
	string s = serialize(pk);
	TESTASSERTV("Data was serialized", !s.empty(), boost::lexical_cast<string>(s.size())+" bytes.");
	
	PublicKey pk2( unserialize<PublicKey>(s) );
	
	TESTASSERT("Data unserialized correctly", (pk==pk2));
	
	return true;
}


bool testSerializePrivateKey()
{
	PrivateKey sk(getRandomPrivateKey());
	
	string s= serialize(sk);

	TESTASSERTV("Data was serialized", !s.empty(), boost::lexical_cast<string>(s.size())+" bytes.");
	
	PrivateKey sk2( unserialize<PrivateKey>(s) );
	
	TESTASSERT("Data unserialized correctly", (sk==sk2));
	
	return true;
}






///////////////////////////////////////////////////////////
/////////////helpers///////////////////////////////////////
///////////////////////////////////////////////////////////

Cipherbit getRandomCipherbit()
{
   vector<mpq_class> z;
	gmp_randclass rnd(gmp_randinit_mt);
	rnd.seed(time(NULL));
	
	for(unsigned int i=0;i<1000;i++)
	  z.push_back( mpq_class(rnd.get_z_range(50000),rnd.get_z_range(50000)+1));
	
	mpz_class v =rnd.get_z_range(50000);
	
	return Cipherbit(v,z);
}


Cipherstring getRandomCipherstring()
{
	gmp_randclass rnd(gmp_randinit_mt);
	rnd.seed(time(NULL));
	mpz_class length =rnd.get_z_range(50) + 10;
	Cipherstring s;
	
	for(unsigned int i =0; i < length; i++)
		s.push_back(getRandomCipherbit());
	
	return s;	
}


PublicKey getRandomPublicKey()
{
	gmp_randclass rnd(gmp_randinit_mt);
	rnd.seed(time(NULL));

	std::vector<mpz_class> x;
	std::vector<mpq_class> y;
	std::vector<Cipherbit> sk;
	
	for(unsigned int i = 0; i< 1000;i++)
	{
		x.push_back(rnd.get_z_range(500) + 10);
		y.push_back(mpq_class(rnd.get_z_range(1000),rnd.get_z_range(1000)+1));
	}
	
	mpz_class length =rnd.get_z_range(50) + 10;
	for(unsigned int i =0; i < length; i++)
		sk.push_back(getRandomCipherbit());
	
	return PublicKey(x,y,sk);	
}


PrivateKey getRandomPrivateKey()
{
	gmp_randclass rnd(gmp_randinit_mt);
	rnd.seed(time(NULL));

	std::vector<bool> bits;
	
	mpz_class len = rnd.get_z_range(1000)+1;
	
	for(unsigned int i = 0; i< len;i++)
		bits.push_back(rnd.get_z_range(1)==0);
	
	return PrivateKey(bits);
}

