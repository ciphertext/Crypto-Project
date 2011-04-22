#include "Encryption/Keys/KeyPair.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

// Lambda - security parameter
const long int _lambda = 4;

// Key generation parameters calculated based off lamdba
// rho - bit length of noise = lambda
// rho' = 2 * lambda
// eta - bit length of secret key = lambda^2
// gamma - bit length of integers of public key = lambda^2
// tau - number of integers in public key = gamma + lambda
// kappa = (gamma * eta)/rho'
// theta = lambda
// big-theta = k * log_2(lambda)
const long int _rho = 4;
const long int _rho2 = 8;
const long int _eta = 16;
const long int _gamma = 30;
const long int _tau = 34;
const long int _kappa = 60;
const long int _theta = 4;
const long int _bigTheta = 60;

KeyPair::KeyPair()
{
	// sk* = p
	// p = random odd number [2^_eta-1, 2^_eta)
	// generate random number between 2^_eta-1 / 2, 2^_eta / 2
	// multiply by 2, subtract 1 to ensure odd number
	boost::rand48 base_gen(time(0)); 
	boost::variate_generator<boost::rand48&, boost::uniform_int<> >
			generate_p(base_gen,
					   boost::uniform_int<>((int) pow(2.0, (double) _eta-1)/2, (int) pow(2.0, (double) _eta)/2 - 1));

	long int p = (2 * generate_p()) - 1;
	
	// pk*
	// for i = 0 to _tau
	// choose random q, [0, 2^_gamma / p)
	// choose random r, (-2^_rho, 2^_rho)
	// x_i = pq+r
	// x_0 largest and restart unless x_0 is odd and x_0 mod p is even
	boost::variate_generator<boost::rand48&, boost::uniform_int<> >
			generate_q(base_gen,
					   boost::uniform_int<>(0, (int) pow(2.0,(double) _gamma)/p - 1));

	boost::variate_generator<boost::rand48&, boost::uniform_int<> >
			generate_r(base_gen,
					   boost::uniform_int<>(-(int) pow(2.0, (double) _rho) + 1, (int) pow(2.0, (double) _rho) - 1));

	bool restart = true;
	vector<long int> pk;	
	vector<long int>::iterator it;
	
	while(restart) {	
		int largestIndex = 0;
		for (int i = 0; i <= _tau; i++) {		
			long int q = generate_q();
			long int r = generate_r();
			long int x = (p * q) + r;
			
			pk.push_back(x);
			
			if( x > pk[largestIndex])
				largestIndex = i;
		}
		
		// move largest element to front of vector
		// store temp value
		// delete from location
		// insert to front of vector
		long int temp = pk[largestIndex];
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
	long int xP = (long int) round(pow(2.0, (double) _kappa) / p);
	
	// sArrow = random big-_theta bit bector with hamming weight _theta
	boost::variate_generator<boost::rand48&, boost::uniform_int<> >
			generate_s(base_gen,
						boost::uniform_int<>(0,_bigTheta-1));
	
	// choose random S
	unsigned int count = _theta;
	set<int> S; //Use set to guarantee unique elements
	while(S.size() < count) {
		S.insert(generate_s());
	}
	
	// create sArrow
	// set all values to 0
	// set indices i in S to 1
	vector<bool> sArrow(_bigTheta, false);
	for(set<int>::iterator it = S.begin(); it != S.end(); it++)
		sArrow[*it] = true;
	
	// generate u_i = [0, 2^k+1) for i = 1...big-_theta
	// sum of u_i, where i in S, = x_p mod 2^k+1
	// else restart
	
	restart = true;
	vector<long int> u;
	while(restart) {
		boost::variate_generator<boost::rand48&, boost::uniform_int<long int> >
				generate_u(base_gen,
						   boost::uniform_int<long int>(0, (long int) pow(2.0, (double) _kappa+1) -1));
											
		/* generate _bigTheta - _theta random integers */
		for(int i = 0; i < _bigTheta - _theta; i++)
			u.push_back(generate_u());
		
		/* generate _theta - 1 more random integers */
		vector<long int> u2;
		for(int i = 0; i < _theta - 1; i++)
			u2.push_back(generate_u());

		/* calculate a final integer such that the sum
		 * of the u2 integers = xP mod 2^k+1 */
		long int sum = 0;
		for(vector<long int>::iterator it = u2.begin(); it != u2.end(); it++) {
			sum = sum + u[*it];
			sum = sum % (long int) pow(2.0, (double) _kappa +1);
		}
		long int u_final = (xP - sum) % (long int) pow(2.0, (double) _kappa +1);

		for(set<int>::iterator it = S.begin(); it != S.end(); it++) {
			vector<long int>::iterator ind = u.begin() + *it;
			if(!u2.empty()){
			cout << u2.back() << " + ";
				u.insert(ind, u2.pop_back());
			}
			else {
			cout << u_final << " = " << sum << " + " << u_final << " = " << ((sum + u_final) % (long int) pow(2.0, (double) _kappa +1)) << "   vs " << xP % (long int) pow(2.0, (double) _kappa +1);
				u.insert(ind, u_final);
		}
	}
	
	// calculate y_i = u_i/2^k
	vector<boost::rational<long int> > y;
	for(int i = 0; i < _bigTheta; i++)
		y.push_back(boost::rational<long int>(u[i], (int) pow(2.0, (double) _kappa)));
	
	// private key is sArrow
	this->privateKey = PrivateKey(sArrow);
	
	// public key is pk, y, and encrypted private key	
	vector<Cipherbit> sk;
	this->publicKey = PublicKey(pk, y, sk);

	for(unsigned int z = 0; z < sArrow.size(); z++)
		sk.push_back(Encryptor::encrypt(sArrow[z], this->publicKey));

	this->publicKey = PublicKey(pk, y, sk);
}


PublicKey KeyPair::getPublicKey()
{
	return this->publicKey;
}

PrivateKey KeyPair::getPrivateKey()
{	
	return this->privateKey;
}
