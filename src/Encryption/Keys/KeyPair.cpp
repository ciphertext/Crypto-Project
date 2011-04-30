#include "Encryption/Keys/KeyPair.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace boost;

// Lambda - security parameter
const long int _lambda = 7;

// Key generation parameters calculated based off lamdba
// rho - bit length of noise = lambda
// rho' = 2 * lambda
// eta - bit length of secret key = lambda^2
// gamma - bit length of integers of public key = lambda^2
// tau - number of integers in public key = gamma + lambda
// kappa = (gamma * eta)/rho'
// theta = lambda
// big-theta = k * log_2(lambda)
const long int _rho		 = 7;
const long int _rho2	 = 14;
const long int _eta		 = 49;
const long int _gamma	 = 98;
const long int _tau		 = 105;
const long int _kappa	 = 343;
const long int _theta	 = 7;
const long int _bigTheta = 375;

KeyPair::KeyPair()
: rd(),
  rand_gen(gmp_randinit_mt)
{
	rand_gen.seed(rd());

	// p = random odd number in [2^_eta-1, 2^_eta)
	// generate random number between 2^_eta-1 / 2, 2^_eta / 2
	// == 2^_eta-2, 2^_eta-1 == 2 << _eta-3, 2 << _eta-2
	// by generating a number in [0, 2^_eta-2) and adding 2^_eta-2
	// then multiply by 2, subtract 1 to ensure odd number

	mpz_class exp = mpz_class(2) << (_eta - 3);
	mpz_class p = (2 * (rand_gen.get_z_range(exp) + exp)) - 1;
	
	publicKey_array_t pk = getPk(p);	
	
 	// sArrow = random big-_theta bit vector with hamming weight _theta
	s_set_t S = getS();
	bitmap_t sArrow= getSArrow(S);
	
	u_array_t u = getU(p,S);
	
	y_rational_array_t y = getY(u);

	// private key is sArrow
	privateKey = PrivateKey(sArrow);
	// public key is pk, y, and encrypted private key	
	
   encryptedSecretKey_array_t sk = getSk(sArrow,pk,y);

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



KeyPair::publicKey_array_t KeyPair::getPk(mpz_class p)
{
  
  	// pk*
	// for i = 0 to _tau
	// choose random q, [0, 2^_gamma / p)
	// choose random r, (-2^_rho, 2^_rho)
	// x_i = pq+r
	// x_0 largest and restart unless x_0 is odd and x_0 mod p is even
  	publicKey_array_t pk;
	
	while(true) {	
		unsigned int largestIndex = 0;
		mpz_class q_ubound = (mpz_class(2) << (_gamma - 1))/p;
		mpz_class r_lbound = -(mpz_class(2) << (_rho - 1)) + 1;
		mpz_class r_ubound = mpz_class(2) << (_rho - 1);
		for (unsigned int i = 0; i <= _tau; i++) {
			mpz_class q = rand_gen.get_z_range(q_ubound);
			mpz_class r = rand_gen.get_z_range(r_ubound - r_lbound) + r_lbound;
			mpz_class x = (p * q) + r;
			
			pk.push_back(x);
			
			if( x > pk[largestIndex])
				largestIndex = i;
		}
		
		// move largest element to front of vector
		// store temp value
		// delete from location
		// insert to front of vector
		mpz_class temp = pk[largestIndex];
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
	// choose random S
	mpz_class s_ubound = _bigTheta;
	s_set_t S; //Use set to guarantee unique elements
	while(S.size() < (unsigned int) _theta) {
		S.insert((unsigned int) mpz_get_ui(((mpz_class) rand_gen.get_z_range(s_ubound)).get_mpz_t()));
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


KeyPair::u_array_t KeyPair::getU(mpz_class p, s_set_t S)
{
	// generate u_i = [0, 2^k+1) for i = 1...big-_theta
	// where, 2^k+1 == 2 << k
	u_array_t u;
	mpz_class u_ubound = mpz_class(2) << _kappa;
	
	/* generate _bigTheta - 1 random integers */
	for(unsigned int i = 0; i < _bigTheta - 1; i++)
		u.push_back(rand_gen.get_z_range(u_ubound));
	
	// xP = round(2^k/p)
	mpz_class k2 = mpz_class(2) << (_kappa -1);
	mpq_class xPq = mpq_class(k2,p);
	xPq.canonicalize();
	mpz_class xP = r_round(xPq);

	// then, ensure that 
	// sum of u_i, where i in S, = x_p mod 2^k+1
	// by generating the final u_i from the
	// theta - 1 other u_i, i in S
	mpz_class sum = 0;
	unsigned int final_index = 0;
	for(s_set_t::iterator it = S.begin(); it != S.end(); it++)
	{
		// only sum S.size() - 1 elements,
		// skipping any element of S >= u.size(),
		// or the last element of S.
		if(*it >= u.size() || (final_index == 0 && distance(it,S.end()) == 1))
			final_index = *it;
		else
			sum += u[*it];
	}
	
	mpz_class u_final = (xP - sum) % (mpz_class(2) << _kappa);
	if(u_final < 0)
		u_final += mpz_class(2) << _kappa;

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
	for(unsigned int i = 0; i < _bigTheta; i++) {
		y.push_back(mpq_class(u[i], mpz_class(2) << (_kappa - 1)));
		y.back().canonicalize();
	}
	
	return y;
}	

KeyPair::encryptedSecretKey_array_t  KeyPair::getSk(bitmap_t sArrow, publicKey_array_t pk, y_rational_array_t y)
{
	encryptedSecretKey_array_t sk;
	
	for(unsigned int z = 0; z < sArrow.size(); z++)
		sk.push_back(Encryptor::encrypt(sArrow[z], PublicKey(pk, y, sk)));
	return sk;
}



