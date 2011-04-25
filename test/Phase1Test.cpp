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
			cout << "Encrypting one bit." << endl;
			Cipherbit c_one_bit = Encryptor::encrypt(1,pk);
			cout << "Encrypting zero bit." << endl;
			Cipherbit c_zero_bit = Encryptor::encrypt(0,pk);
		
			cout << "Decrypting one bit." << endl;
			bool one_bit = Encryptor::decrypt(c_one_bit,sk);
			cout << "Decrypting zero bit." << endl;
			bool zero_bit = Encryptor::decrypt(c_zero_bit,sk);
		
			cout << "One bit: " << one_bit << endl;
			cout << "Zero bit: " << zero_bit << endl;
		}
	}
	return 0;
	
}
