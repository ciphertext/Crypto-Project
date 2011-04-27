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
	// == (2 << _eta-2)/2, (2 << _eta-1)/2 == 2 << _eta-3, 2 << _eta-2
	// multiply by 2, subtract 1 to ensure odd number
	var_gen_t generate_p(base_gen,
					     uniform_int<>((int) 2 << (_eta-3), (int) 2 << (_eta - 2) - 1));

	int_t p = (2 * generate_p()) - 1;
	
	publicKey_array_t pk = getPk(p);	
	
	s_set_t S = getS();
	
	bitmap_t sArrow= getSArrow(S);
	
	u_array_t u = getU(p,S);
	
	y_rational_array_t y = getY(u);

	// private key is sArrow
	privateKey = shared_ptr<PrivateKey> (new PrivateKey(sArrow));
	// public key is pk, y, and encrypted private key	
	
   encryptedSecretKey_array_t sk = getSk(sArrow,pk,y);

	publicKey = shared_ptr<PublicKey> (new PublicKey(pk, y, sk));
}




shared_ptr<PublicKey> KeyPair::getPublicKey()
{
	return publicKey;
}

shared_ptr<PrivateKey> KeyPair::getPrivateKey()
{	
	return privateKey;
}



KeyPair::publicKey_array_t KeyPair::getPk(int_t p)
{
  
  	// pk*
	// for i = 0 to _tau
	// choose random q, [0, 2^_gamma / p)
	// choose random r, (-2^_rho, 2^_rho)
	// x_i = pq+r
	// x_0 largest and restart unless x_0 is odd and x_0 mod p is even
	var_gen_t generate_q(base_gen,
					   uniform_int<>(0, (2 << (_gamma-1))/p - 1));

	var_gen_t generate_r(base_gen,
					   uniform_int<>((int) -(2 << (_rho-1)) + 1, (int) (2 << (_rho-1)) - 1));
  
  	publicKey_array_t pk;
	
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


KeyPair::s_set_t KeyPair::getS()
{
 	// sArrow = random big-_theta bit bector with hamming weight _theta
	var_gen_t generate_s(base_gen, uniform_int<>(0,_bigTheta-1));
	
	// choose random S
	s_set_t S; //Use set to guarantee unique elements
	while(S.size() < (uint_t) _theta) {
		S.insert(generate_s());
	} 
	
	return S;
}


KeyPair::bitmap_t KeyPair::getSArrow(s_set_t S)
{
	// create sArrow
	// set all values to 0
	// set indices i in S to 1
	vector<bool> sArrow(_bigTheta, false);
	for(s_set_t::iterator it = S.begin(); it != S.end(); it++)
		sArrow[*it] = true;
	return sArrow;
}


KeyPair::u_array_t KeyPair::getU(int_t p, s_set_t S)
{
	// generate u_i = [0, 2^k+1) for i = 1...big-_theta
	// where, 2^k+1 == 2 << k
	u_array_t u;
	var_gen_u_t generate_u(base_gen,
						   uniform_int<int_t>(0, (2L << _kappa) -1));
	
	/* generate _bigTheta - 1 random integers */
	for(int i = 0; i < _bigTheta - 1; i++)
		u.push_back(generate_u());
	
	// xP = round(2^k/p)
	int_t xP = (int_t) round((2L << (_kappa -1)) / p);

	// then, ensure that 
	// sum of u_i, where i in S, = x_p mod 2^k+1
	// by generating the final u_i from the
	// theta - 1 other u_i, i in S
	int_t sum = 0;
	unsigned int final_index = 0;
	for(s_set_t::iterator it = S.begin(); it != S.end(); it++)
	{
		// only sum S.size() - 1 elements,
		// skipping any element of S >= u.size(),
		// or the last element of S.
		if(*it >= u.size() || (final_index == 0 && it == S.end()))
			final_index = *it;
		else {
			sum += u[*it];
			sum %= 2L << _kappa;
		}
	}
	
	int_t u_final = xP - sum % (2L << _kappa);
	if(u_final < 0) {
		u_final += 2L << _kappa;
	}
	if(final_index < u.size())
		u.insert(u.begin() + final_index, u_final);
	else
		u.push_back(u_final);
	
	return u;
}

KeyPair::y_rational_array_t KeyPair::getY(u_array_t u)
{
	// calculate y_i = u_i/2^k
	y_rational_array_t y;
	for(int i = 0; i < _bigTheta; i++)
		y.push_back(rational<int_t>(u[i], 2L << (_kappa - 1)));
	
	return y;
}	

KeyPair::encryptedSecretKey_array_t  KeyPair::getSk(bitmap_t sArrow, publicKey_array_t pk, y_rational_array_t y)
{
	encryptedSecretKey_array_t sk;
	
	for(unsigned int z = 0; z < sArrow.size(); z++)
		sk.push_back(Encryptor::encrypt(sArrow[z], PublicKey(pk, y, sk)));
	return sk;
}
