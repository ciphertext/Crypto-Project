#include "Encryption/Encryptor.hpp"
#include "Encryption/Keys/KeyPair.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

int main()
{
		cout << "Starting test." << endl;
        for(int i = 0; i < 100; i++) {
                cout << "Generating key pair " << i << endl;
                KeyPair kp;
                PublicKey pk = kp.getPublicKey();
                PrivateKey sk = kp.getPrivateKey();

                cout << "Encrypting one bit." << endl;
                Cipherbit c_one_bit = Encryptor::encrypt(1,pk);
                cout << "Encrypting zero bit." << endl;
                Cipherbit c_zero_bit = Encryptor::encrypt(0,pk);

                cout << "Decrypting one bit." << endl;
                bool one_bit = Encryptor::decrypt(c_one_bit,sk);
                cout << "Decrypting zero bit." << endl;
                bool zero_bit = Encryptor::decrypt(c_zero_bit,sk);

                cout << "One bit: " << (one_bit?"PASSED\n":"FAILED\n");
                cout << "Zero bit: " << (!zero_bit?"PASSED\n":"FAILED\n");
        }
        return 0;
	
}
