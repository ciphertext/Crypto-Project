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
Cipherstring getRandomCipherstring();
bool equalCipherbit(Cipherbit c1, Cipherbit c2);
bool equalCipherstring(Cipherstring c1, Cipherstring c2);

int main()
{
   bool success=true;
	
	success&= runTest(testSerializeCipherbit,"Test Cipherbit Serialization");
	success&= runTest(testSerializeCipherstring,"Test Cipherstring Serialization");
	
	return (success) ? 0 : -1;
}


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

bool testSerializeCipherbit()
{
	Cipherbit b(getRandomCipherbit());
	string s= serialize(b);
	TESTASSERTV("Data was serialized", !s.empty(), boost::lexical_cast<string>(s.size())+" bytes.");
	
	Cipherbit b2 (unserialize<Cipherbit>(s));
	
   bool equal = equalCipherbit(b,b2);
	
	TESTASSERT("Values preserved", equal);
	
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
	
   bool equal = equalCipherstring(cs,cs2);
	
	TESTASSERT("Cipherstrings equal", equal);
	
	return true;
}
bool testSerializePublicKey()
{
	return true;
}
bool testSerializePrivateKey()
{
	return true;
}









Cipherbit getRandomCipherbit()
{
   vector<mpq_class> z;
	gmp_randclass rnd(gmp_randinit_mt);
	rnd.seed(time(NULL));
	
	for(int i=0;i<1000;i++)
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
	
	for(int i =0; i < length; i++)
		s.push_back(getRandomCipherbit());
	
	return s;	
}

bool equalCipherbit(Cipherbit c1, Cipherbit c2)
{	
   for(int i=0;i<1000;i++)
	  if(c1.getZ(i) != c2.getZ(i)) 
	    return false;
	if(c1.getValue()!=c2.getValue())
		return false;
	
	return true;
}


bool equalCipherstring(Cipherstring c1, Cipherstring c2)
{	
	if(c1.size()!=c2.size())
		return false;
	
	for(int i=0; i < c1.size(); i++)
		if(!equalCipherbit(c1.at(i),c2.at(i)))
			return false;
	
	return true;	
}