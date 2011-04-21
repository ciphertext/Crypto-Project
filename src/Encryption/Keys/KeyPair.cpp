#include "Encryption/Keys/KeyPair.hpp"
#include <math.h>

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

// Lambda - security parameter
const long int lambda = 4;

// Key generation parameters calculated based off lamdba
// rho - bit length of noise = lambda
// rho' = 2 * lambda
// eta - bit length of secret key = lambda^2
// gamma - bit length of integers of public key = lambda^2
// tau - number of integers in public key = gamma + lambda
// kappa = (gamma * eta)/rho'
// theta = lambda
// big-theta = k * log_2(lambda)
const long int rho = 4;
const long int rho2 = 8;
const long int eta = 16;
const long int gamma = 16;
const long int tau = 20;
const long int kappa = 32;
const long int theta = 4;
const long int bigTheta = 32;

KeyPair::KeyPair()
{
	// sk* = p
	// p = random odd number [2^eta-1, 2^eta)
	// generate random number between 2^eta-1 / 2, 2^eta / 2
	// multiply by 2, subtract 1 to ensure odd number
	boost::rand48 base_gen(time(0)); 
	boost::variate_generator generate_p(base_gen&,
										boost::uniform_int<>(pow(2, eta-1)/2, pow(2, eta)/2 - 1));

	long int p = (2 * generate_p()) - 1;
	
	// pk*
	// for i = 0 to tau
	// choose random q, [0, 2^gamma / p)
	// choose random r, (-2^rho, 2^rho)
	// x_i = pq+r
	// x_0 largest and restart unless x_0 is odd and x_0 mod p is even
	boost::variate_generator generate_q(base_gen&,
										boost::uniform_int<>(0, pow(2,gamma)/p) - 1);
	boost::variate_generator generate_r(base_gen&,
										boost::uniform_int<>(-pow(2, rho) + 1, pow(2, rho) - 1));
	bool restart = true;
	vector<long int> pk;	
	vector<long int>::iterator it;
	
	while(restart) {	
		int largestIndex = 0;
		for (int i = 0; i <= tau; i++) {		
			long int q = generate_q();
			long int r = generate_r();
			long int x = (p * q) + r;
			
			pk.push_back(x);
			
			if( x > pk.at(largestIndex))
				largestIndex = i;
		}
		
		// move largest element to front of vector
		// store temp value
		// delete from location
		// insert to front of vector
		long int temp = pk.at(largestIndex);
		pk.erase(pk.begin() + largestIndex - 1);
		it = pk.begin();
		pk.insert (it , temp);
		
		// check if x_0 is odd and x_0 mod p is even
		// if not, restart
		if((temp % 2 == 1) && ((temp % p)%2 == 0))
			restart = false;
		else
			pk.clear();
	}
	
	// x_p = round(2^k/p)
	long int xP = (long int) round((pow(2, kappa)) / p);
	
	// sArrow = random big-theta bit bector with hamming weight theta
	boost::variate_generator generator_s(base_gen&,
										 boost::uniform_int<>(0,bigTheta-1));
	
	// choose random S
	int count = theta;
	vector<int> S;
	while(S.size() < count) {
		int temp = generator_s();
		bool found = false;
		for(int i = 0; i < S.size(); i++)
			if(S.at(i) == temp)
				found = true;

		if(!found)
			S.push_back(temp);
	}
	
	// create sArrow
	// set all values to 0
	// set indices i in S to 1
	vector<bool> sArrow;
	for(int i = 0; i < S.size(); i++)
		sArrow.at(S.at(i)) = true;
	
	// generate u_i = [0, 2^k+1) for i = 1...big-theta
	// sum of u_i, where i in S, = x_p mod 2^k+1
	// else restart
	
	restart = true;
	vector<long int> u;
	while(restart) {
		boost::variate_generator generate_u(base_gen&,
											boost::uniform_int<>(0, pow(2, kappa+1) -1));
											
		for(int i = 0; i < bigTheta, i++)
			u.at(i) = generate_u();
		
		// check sum
		long int sum = 0;
		for(int y = 0; y < S.size(); y++) {
			sum = sum + u.at(S.at(y));
			sum = sum % pow(2, kappa +1);
		}
		
		if(sum == (xP % pow(2, kappa + 1)))
			restart = false;
		else
			u.clear();
	}
	
	// calculate y_i = u_i/2^k
	vector<rational<long int>> y;
	for(int i = 0; i < bigTheta; i++)
		y.push_back(boost::rational(u.at(i), pow(2, kappa)));
	
	// private key is sArrow
	this.privateKey = PrivateKey(sArrow);
	
	// public key is pk, y, and encrypted private key	
	vector<Cipherbit> sk;
	this.publicKey = PublicKey(pk, y, sk);
	for(int z = 0; z < sArrow.size(); z++)
	{
		sk.at(z) = Encryptor.encrypt(sArrow.at(z));
	}
	this.publicKey = PublicKey(pk, y, sk);
}


PublicKey KeyPair::getPublicKey()
{
	return this.publicKey;
}

PrivateKey KeyPair::getPrivateKey()
{	
	return this.privateKey;
}
