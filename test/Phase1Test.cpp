#include "Encryption/Encryptor.hpp"
#include "Encryption/Keys/KeyPair.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

int main()
{
	for(int i = 0; i < 100; i++) {
		KeyPair kp;
		PublicKey pk = kp.getPublicKey();
		PrivateKey sk = kp.getPrivateKey();
		
		Cipherbit c_one_bit = Encryptor.encrypt(1,pk);
		Cipherbit c_zero_bit = Encryptor.decrypt(0,pk);
		
		bool one_bit = Encryptor.decrypt(c_one_bit,sk);
		bool zero_bit = Encryptor.decrypt(c_zero_bit,sk);

		cout << "Trial " << i << endl;
		cout << "One bit: " << (one_bit?"PASSED\n":"FAILED\n");
		cout << "Zero bit: " << (!zero_bit?"PASSED\n":"FAILED\n");
	}
	return 0;
}
