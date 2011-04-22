#include "Encryption/Keys/KeyPair.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace boost;

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
: rd(),
  base_gen(rd())
{
	// sk* = p
	// p = random odd number [2^_eta-1, 2^_eta)
	// generate random number between 2^_eta-1 / 2, 2^_eta / 2
	// multiply by 2, subtract 1 to ensure odd number
	var_gen_t generate_p(base_gen,
					   uniform_int<>((int) pow(2.0, (double) _eta-1)/2, (int) pow(2.0, (double) _eta)/2 - 1));

	int_t p = (2 * generate_p()) - 1;
	
	pk_t pk = getPk(p);	
	
	s_t S = getS();
	
	bitmap_t sArrow= getSArrow(S);
	
	theta_t u = getBigTheta();
	
	theta_t u2= getTheta();
	
	int_t u_final = getUFinal(p,u2);

	doSomethingWithU(S,u,u2,u_final);
	
	y_t y = getY(u);

	// private key is sArrow
	privateKey = PrivateKey(sArrow);
	// public key is pk, y, and encrypted private key	
	
   sk_t sk = getSk(sArrow,pk,y);

	publicKey = PublicKey(pk, y, sk);
}




PublicKey KeyPair::getPublicKey()
{
	return publicKey;
}

PrivateKey KeyPair::getPrivateKey()
{	
	return privateKey;
}





KeyPair::pk_t KeyPair::getPk(int_t p)
{
  
  	// pk*
	// for i = 0 to _tau
	// choose random q, [0, 2^_gamma / p)
	// choose random r, (-2^_rho, 2^_rho)
	// x_i = pq+r
	// x_0 largest and restart unless x_0 is odd and x_0 mod p is even
	var_gen_t generate_q(base_gen,
					   uniform_int<>(0, (long int) pow(2.0,(double) _gamma)/p - 1));

	var_gen_t generate_r(base_gen,
					   uniform_int<>(-(int) pow(2.0, (double) _rho) + 1, (int) pow(2.0, (double) _rho) - 1));
  
  	pk_t pk;
	
	while(true) {	
		int largestIndex = 0;
		for (int i = 0; i <= _tau; i++) {		
			int_t q = generate_q();
			int_t r = generate_r();
			int_t x = (p * q) + r;
			
			pk.push_back(x);
			
			if( x > pk[largestIndex])
				largestIndex = i;
		}
		
		// move largest element to front of vector
		// store temp value
		// delete from location
		// insert to front of vector
		int_t temp = pk[largestIndex];
		pk[largestIndex]=pk[0];
		pk[0]=temp;
	
		
		// check if x_0 is odd and x_0 mod p is even
		// if not, restart
		if((temp % 2 == 1) && ((temp % p)%2 == 0))
			break;
		else
			pk.clear();
	}
	
	return pk;
}


KeyPair::s_t KeyPair::getS()
{
 	// sArrow = random big-_theta bit bector with hamming weight _theta
	var_gen_t generate_s(base_gen, uniform_int<>(0,_bigTheta-1));
	
	// choose random S
	s_t S; //Use set to guarantee unique elements
	while(S.size() < (uint_t) _theta) {
		S.insert(generate_s());
	} 
	
	return S;
}


KeyPair::bitmap_t KeyPair::getSArrow(s_t S)
{
	// create sArrow
	// set all values to 0
	// set indices i in S to 1
	vector<bool> sArrow(_bigTheta, false);
	for(s_t::iterator it = S.begin(); it != S.end(); it++)
		sArrow[*it] = true;
	return sArrow;
}


KeyPair::theta_t KeyPair::getBigTheta()
{
		// generate u_i = [0, 2^k+1) for i = 1...big-_theta
	// sum of u_i, where i in S, = x_p mod 2^k+1
	theta_t u;
	var_gen_theta_t generate_u(base_gen,
					   uniform_int<long int>(0, (long int) pow(2.0, (double) _kappa+1) -1));
	
	/* generate _bigTheta - _theta random integers */
	for(int i = 0; i < _bigTheta - _theta; i++)
		u.push_back(generate_u());
	
	return u;
}


KeyPair::theta_t KeyPair::getTheta()
{
		// generate u_i = [0, 2^k+1) for i = 1...big-_theta
	// sum of u_i, where i in S, = x_p mod 2^k+1
	theta_t u2;
	var_gen_theta_t generate_u(base_gen,
					   uniform_int<long int>(0, (long int) pow(2.0, (double) _kappa+1) -1));
	
	/* generate _theta - 1 more random integers */
	for(int i = 0; i < _theta - 1; i++)
		u2.push_back(generate_u());
	
	return u2;
}

KeyPair::int_t KeyPair::getUFinal(int_t p, theta_t u2)
{
	int_t xP = (int_t) round(pow(2.0, (double) _kappa) / p);
	
		/* calculate a final integer such that the sum
	 * of the u2 integers = xP mod 2^k+1 */
	int_t sum = 0;
	BOOST_FOREACH(int_t i , u2)
	{
		sum += i;
		sum %= (int_t) pow(2.0, (double) _kappa +1);
	}
	
	return (xP - sum) % (int_t) pow(2.0, (double) _kappa +1);
}

void KeyPair::doSomethingWithU(s_t S, theta_t & u, theta_t u2, int_t u_final)
{
	for(s_t::iterator it = S.begin(); it != S.end(); it++) {
		vector<long int>::iterator ind = u.begin() + *it;
		if(!u2.empty()) {
			u.insert(ind, u2.back());
			u2.pop_back();
		}
		else 
			u.insert(ind, u_final);
	}
}



KeyPair::y_t KeyPair::getY(theta_t u)
{
	// calculate y_i = u_i/2^k
	y_t y;
	for(int i = 0; i < _bigTheta; i++)
		y.push_back(rational<long int>(u[i], (long int) pow(2.0, (double) _kappa)));
	
	return y;
}	

KeyPair::sk_t  KeyPair::getSk(bitmap_t sArrow, pk_t pk, y_t y)
{
	sk_t sk;
	
	for(unsigned int z = 0; z < sArrow.size(); z++)
		sk.push_back(Encryptor::encrypt(sArrow[z], PublicKey(pk, y, sk)));
	return sk;
}