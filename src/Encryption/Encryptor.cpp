#include "Encryption/Encryptor.hpp"
using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

/* XXX: these should be defined in terms of lambda,
 *      which should be stored as part of the public
 *      and private keys. */
const int lambda = 4; // small so we don't need bigint types
const int secondary_noise = 8;
const int tau = 20;
const int precision_bits = 5;

boost::rational<long int> r_floor(boost::rational<long int> n) {
	return boost::rational<long int>(n.numerator() - (n.numerator() % n.denominator()), n.denominator());
}

boost::rational<long int> r_round(boost::rational<long int> n) {
	boost::rational<long int> half(1,2);
	return r_floor(n + half);
}

boost::rational<long int> r_modulo(boost::rational<long int> a, int b) {
	return boost::rational<long int>(a.numerator() % (b*a.denominator()),a.denominator());
}

boost::rational<long int> fix_precision_bits(boost::rational<long int> a, int bits) {
	int power = (int) pow(2.0, bits);
	return r_floor(a * power) / power;
}

Cipherbit Encryptor::encrypt(bool aM, PublicKey aPk)
{
	// generate a random number r in the range (-2^{\rho'},2^{\rho'})
	boost::rand48 base_gen(time(0)); // Seed based on current time; TODO: better seed
	boost::variate_generator<boost::rand48, boost::uniform_int<> >
			generator_1(base_gen&,
						boost::uniform_int<>((int) -pow(2.0,secondary_noise)+1, (int) pow(2.0,secondary_noise)-1));

	int r = generator_1();

	/* select a random subset S of {1,2,...,\tau}
	 * by selecting a random integer count in [1,\tau],
	 * and selecting count random integers in [1,\tau],
	 * not counting duplicates */
	boost::variate_generator<boost::rand48, boost::uniform_int<> >
			generator_2(base_gen&, boost::uniform_int<>(1,tau));
	
	unsigned int count = generator_2();
	set<int> S;
	while(S.size() < count)
		S.insert(generator_2());
	
	/* compute the sum of x_i \in aPk.X, i \in S */
	int sum_x = 0;
	set<int>::iterator it;
	for(it = S.begin(); it != S.end(); it++)
		sum_x += aPk.getX(*it);
	
	/* c* = (m + 2r + 2sum_x) mod 2, as in the
	 * original (non-squashed) scheme */
	int c_val = (aM + 2*r + 2*sum_x) % aPk.getX(0);

	/* calculate z_i = (c* . y_i) mod 2, i \in {0,...,\Theta} */
	int i;
	vector<boost::rational<long int> > Z;
	for(i = 0; i < aPk.size(); i++)
		Z.push_back(fix_precision_bits(r_modulo(c_val * aPk.getY(i), 2),precision_bits));
	
	return Cipherbit(c_val, Z);
}


bool Encryptor::decrypt(Cipherbit aC, PrivateKey aSk)
{
	int i;
	boost::rational<long int> sum;
	for(i = 0; i < aSk.size(); i++) {
		sum += aSk.getBit(i) * aC.getZ(i);
	}

	return (r_modulo((aC.getValue() - r_round(sum)),2) == 1)? true : false;
}
