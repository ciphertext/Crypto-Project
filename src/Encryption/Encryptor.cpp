#include "Encryption/Encryptor.hpp"
using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

/* XXX: these should be defined in terms of lambda,
 *      which should be stored as part of the public
 *      and private keys. */
const int secondary_noise = 8;
const int _tau = 20;
const int precision_bits = 5;

Cipherbit Encryptor::encrypt(bool aM, PublicKey aPk)
{
	// generate a random number r in the range (-2^{\rho'},2^{\rho'})
	boost::random_device rd;
	gmp_randclass rand_gen(gmp_randinit_mt);
	rand_gen.seed(rd());

	mpz_class r_lbound = -(mpz_class(2) << (secondary_noise - 1)) + 1;
	mpz_class r_ubound = (mpz_class(2) << (secondary_noise - 1));
	mpz_class r = rand_gen.get_z_range(r_ubound - r_lbound) + r_ubound;

	/* select a random subset S of {1,2,...,\tau}
	 * by selecting a random integer count in [1,\tau],
	 * and selecting count random integers in [1,\tau],
	 * not counting duplicates */
	unsigned int count = (unsigned int) mpz_get_ui(((mpz_class) rand_gen.get_z_range(mpz_class(_tau))).get_mpz_t()) + 1;
	set<unsigned int> S;
	while(S.size() < count)
		S.insert((unsigned int) mpz_get_ui(((mpz_class) rand_gen.get_z_range(mpz_class(_tau))).get_mpz_t()) + 1);
	
	/* compute the sum of x_i \in aPk.X, i \in S */
	mpz_class sum_x = 0;
	for(set<unsigned int>::iterator it = S.begin(); it != S.end(); it++)
		sum_x += aPk.getX(*it);
	
	/* c* = (m + 2r + 2sum_x) mod 2, as in the
	 * original (non-squashed) scheme */
	mpz_class c_val = (aM + 2*r + 2*sum_x) % aPk.getX(0);

	/* calculate z_i = (c* . y_i) mod 2, i \in {0,...,\Theta} */
	vector<mpq_class> Z;
	for(unsigned int i = 0; i < aPk.ysize(); i++)
		Z.push_back(fix_precision_bits(r_modulo((c_val * aPk.getY(i)), 2),precision_bits));
	
	return Cipherbit(c_val, Z);
}


bool Encryptor::decrypt(Cipherbit aC, PrivateKey aSk)
{
	mpq_class sum;
	for(unsigned int i = 0; i < aSk.size(); i++) {
		// GMP does not automatically convert bool to int
		sum += ((int) aSk.getBit(i)) * aC.getZ(i);
	}

	return (r_modulo((aC.getValue() - r_round(sum)),2) == 1)? true : false;
}
