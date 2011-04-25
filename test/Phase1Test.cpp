#include "Encryption/Encryptor.hpp"
#include "Encryption/Keys/KeyPair.hpp"
#include <iostream>

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

int main()
{
	cout << "Starting test." << endl;
	for(int i = 0; i < 10; i++) {
		cout << "Generating key pair " << i << endl;
		KeyPair kp;
		PublicKey pk = kp.getPublicKey();
		PrivateKey sk = kp.getPrivateKey();
		
		/*cout << "pk: x(";
		for(unsigned int i = 0; i < pk.xsize(); i++)
			cout << pk.getX(i) << ", ";
		cout << "), y(";
		for(unsigned int i = 0; i < pk.ysize(); i++)
			cout << pk.getY(i) << ", ";
		cout << ")" << endl;
		
		cout << "sk: s(";
		for(unsigned int i = 0; i < sk.size(); i++)
			cout << sk.getBit(i) << ", ";
		cout << ")" << endl;*/
		
		for(int j = 0; j < 10; j++) {
			Cipherbit c_one_bit = Encryptor::encrypt(1,pk);
			bool one_bit = Encryptor::decrypt(c_one_bit,sk);
			if(!one_bit)
				cout << "FAILED (1 -> 0)." << endl;

			Cipherbit c_zero_bit = Encryptor::encrypt(0,pk);
			bool zero_bit = Encryptor::decrypt(c_zero_bit,sk);
			if(zero_bit)
				cout << "FAILED (0 -> 1)." << endl;
		
		}
	}
	return 0;
	
}
