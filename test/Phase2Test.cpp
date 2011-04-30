#include "Encryption/EncryptionFacade.hpp"
#include <time.h>
#include <boost/lexical_cast.hpp>
#include <gmpxx.h>
const bool verbose=true;

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;

#define TESTASSERT(_exprname,_expr) testAssert(_exprname,_expr); if(!_expr) return false;
#define TESTASSERTV(_exprname,_expr,_extra) testAssert(_exprname,_expr,_extra); if(!_expr) return false;

void testAssert(string exprname, bool expr, string extra="");
void log(string msg);
void startTest(string testname);
void endTest();
void failTest();
bool runTest(bool(test)(void), string name);

bool testSerializeCipherbit();
bool testSerializeCipherstring();
bool testSerializePublicKey();
bool testSerializePrivateKey();


Cipherbit getRandomCipherbit();
PublicKey getRandomPublicKey();
PrivateKey getRandomPrivateKey();
Cipherstring getRandomCipherstring();
//bool equalCipherbit(Cipherbit c1, Cipherbit c2);
//bool equalCipherstring(Cipherstring c1, Cipherstring c2);
//bool equalPublicKey(PublicKey p1, PublicKey p2);
//bool equalPrivateKey(PrivateKey p1, PrivateKey p2);

bool operator == (const Cipherbit & c1, const Cipherbit & c2);
bool operator == (const Cipherstring & c1, const Cipherstring & c2);
bool operator == (const PublicKey & p1, const PublicKey & p2);
bool operator == (const PrivateKey & p1, const PrivateKey & p2);

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
	
	return (success) ? 0 : -1;
}



//------------------------------------------
//               Test Framework
//------------------------------------------


void log(string msg)
{
	if(verbose)
	{
		cout<<"INFO: "<<msg<<endl;
		cout.flush();
	}
}

void testAssert(string exprname, bool expr, string extra)
{
	if(!expr)
		cout<<"Testing ("<<exprname<<") : Failed. "<<extra<< endl;
	else if(verbose)
		cout<<"Testing ("<<exprname<<") : Passed. "<<extra<< endl;
}

void startTest(string testname)
{
	cout<<"Starting test " << testname<<"..."<<endl;
}

void endTest()
{
	cout << "Test succeeded "<<endl<<"-----------------"<<endl;
}

void failTest()
{
	cout << "Test failed"<<endl<<"-----------------"<<endl;
}


bool runTest(bool(test)(void), string name)
{
	bool success;
	startTest(name);
	success=test();
	if(success)
		endTest();
	else
		failTest();
	return success;
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
	
   //bool equal = equalCipherbit(b,b2);
	
	TESTASSERT("Values preserved", (b==b2));
	
	return true;
}

bool testSerializeCipherstring()
{
	Cipherstring cs(getRandomCipherstring());
	log("Using cipherstring of length " + boost::lexical_cast<string>(cs.size()));
	
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
	
	//bool equal = equalPublicKey(pk,pk2);
	
	TESTASSERT("Data unserialized correctly", (pk==pk2));
	
	return true;
}


bool testSerializePrivateKey()
{
	PrivateKey sk(getRandomPrivateKey());
	
	string s= serialize(sk);

	TESTASSERTV("Data was serialized", !s.empty(), boost::lexical_cast<string>(s.size())+" bytes.");
	
	PrivateKey sk2( unserialize<PrivateKey>(s) );
	
	//bool equal = equalSecretKey(sk,sk2);
	
	TESTASSERT("Data unserialized correctly", (sk==sk2));
	
	return true;
}







//----------------------------------------------
//    Implementation-specific helper functions
//----------------------------------------------
//
//        When a class changes, come here
//
//----------------------------------------------

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


//bool equalCipherbit(Cipherbit c1, Cipherbit c2)
bool operator == (const Cipherbit& c1, const Cipherbit& c2)
{	
   for(unsigned int i=0;i<1000;i++)
	  if(c1.getZ(i) != c2.getZ(i)) 
	    return false;
	if(c1.getValue()!=c2.getValue())
		return false;
	
	return true;
}


//bool equalCipherstring(Cipherstring c1, Cipherstring c2)
bool operator == (const Cipherstring & c1, const Cipherstring & c2)
{	
	if(c1.size()!=c2.size())
		return false;
	
	for(unsigned int i=0; i < c1.size(); i++)
		if(!(c1.at(i)==c2.at(i)))
			return false;
	
	return true;	
}

//bool equalPublicKey(PublicKey p1, PublicKey p2)
bool operator == (const PublicKey & p1, const PublicKey & p2)
{
	if(p1.xsize()!=p2.xsize())
		return false;
	if(p1.ysize()!=p2.ysize())
		return false;
	if(p1.encryptedKeySize()!=p2.encryptedKeySize())
		return false;
	
	for(unsigned int i=0; i < p1.xsize(); i++)
	  if(p1.getX(i)!=p2.getX(i))
		  return false;

	for(unsigned int i=0; i < p1.ysize(); i++)
		if(p1.getY(i)!=p2.getY(i))
		  return false;

	for(unsigned int i=0; i < p1.encryptedKeySize(); i++)
		if(!(p1.getEncryptedSkBit(i)==p2.getEncryptedSkBit(i)))
			return false;
	
	return true;
}

//bool equalPrivateKey(PrivateKey p1, PrivateKey p2)
bool operator == (const PrivateKey & p1, const  PrivateKey & p2)
{
	if(p1.size()!=p2.size())
		return false;
	
	for(unsigned int i=0; i < p1.size(); i++)
	  if(p1.getBit(i)!=p2.getBit(i))
		  return false;
	
	  return true;
}