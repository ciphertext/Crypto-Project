
#include "Encryption/Cipherbit.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;
using namespace Encryption::Operations;

const unsigned int _theta = 7;
const int precision_bits = 6;

Cipherbit::Cipherbit(mpz_class c, vector<mpq_class> z, const PublicKey & pubkey)
:pubkey(boost::shared_ptr<PublicKey>(new PublicKey(pubkey)))
{
	this->value = c;
	this->Z = z;
	
	//this->saturated = true;
}

Cipherbit::Cipherbit(const Cipherbit & c)
:pubkey(c.pubkey)
{
	value=c.value;
	Z = c.Z;
	//saturated = c.saturated;
}

Cipherbit Cipherbit::operator = (const Cipherbit & c)
{
	pubkey=c.pubkey;
	value=c.value;
	Z = c.Z;
	//saturated = c.saturated;
	return *this;
}

mpz_class Cipherbit::getValue() const
{
	return this->value;
}

mpq_class Cipherbit::getZ(unsigned int index) const
{
	return this->Z.at(index);
}

/*void Cipherbit::setSaturated(bool s)
{
	this->saturated = s;
}*/

Cipherbit Cipherbit::operator & ( const Cipherbit & cb) const
{
	
	//TODO: check for ciphertext with different public keys
	mpz_class val = value * cb.value;

	/* calculate z_i = (c* . y_i) mod 2, i \in {0,...,\Theta} */
	vector<mpq_class> Z;
	for(unsigned int i = 0; i < pubkey->ysize(); i++)
		Z.push_back(fix_precision_bits(r_modulo((val * pubkey->getY(i)), 2),precision_bits));
	
	Cipherbit ret(val, Z, *pubkey);
	if(saturated)
		ret.recrypt();
	else
		ret.setSaturated(false);*/

	return ret;
}


Cipherbit Cipherbit::operator ^ ( const Cipherbit & cb) const
{
	
	//TODO: check for ciphertext with different public keys
	mpz_class val = value + cb.value;

	/* calculate z_i = (c* . y_i) mod 2, i \in {0,...,\Theta} */
	vector<mpq_class> Z;
	for(unsigned int i = 0; i < pubkey->ysize(); i++)
		Z.push_back(fix_precision_bits(r_modulo((val * pubkey->getY(i)), 2),precision_bits));
	
	Cipherbit ret(val, Z, *pubkey);
	if(saturated)
		ret.recrypt();
	else
		ret.setSaturated(false); */

	return ret;
}

Cipherbit Cipherbit::operator | ( const Cipherbit & cb) const
{
	return (*this & cb) ^ (*this ^ cb);
}
/*
void Cipherbit::recrypt()
{


	// Encrypt value
	bitstring_t cbits = mpzToBitstring(value);
	Cipherstring c_bar;
	for(unsigned int i = 0; i < cbits.size(); i++)
		c_bar.push_back(Encryptor::encrypt(cbits[i],*pubkey));
	c_bar.unsaturate();

	//compute A = {a_i}, i in {0,...,_bigtheta = Z.size()}
	vector<Cipherstring> A;
	for(unsigned int i = 0; i < Z.size(); i++) {
		bitstring_t z_bits = mpqToBitstring(Z[i]);
		Cipherstring z_bar;
		for(unsigned int j = 0; j < z_bits.size(); j++)
			z_bar.push_back(Encryptor::encrypt(z_bits[j],*pubkey));
		z_bar.unsaturate();

		//compute a_i = s_i * z_i
		Cipherstring a;
		for(unsigned int j = 0; j < z_bar.size(); j++) {
			// because s_i is one bit,
			// s_i * z_i = s_i & z_i[j] for each bit of z_i
			a.push_back(pubkey->getEncryptedSkBit(i) & z_bar[j]);
		}
		a.unsaturate();
		A.push_back(a);
	}

	// compute W_j = sum_i(a_i[j])
	// if we view A as a matrix of bits (whose rows are a_i),
	// W_j is the sum (aka Hamming weight) of column j
	vector<Cipherstring> W;
	for(unsigned int j = 0; j < A[0].size(); j++)
		W.push_back(getHammingColumn(A,j));
	
	// compute w_j = 2^-j W_j mod 2
	deque<Cipherstring> w;
	for(unsigned int j = 0; j < W.size(); j++)
	{
		Cipherstring scale;
		for(unsigned int i = 0; i < W.size(); i++) {
			W[j].push_back(Encryptor::encrypt(false,*pubkey));
			if(i == j)
				scale.push_back(Encryptor::encrypt(true,*pubkey));
			else
				scale.push_back(Encryptor::encrypt(false,*pubkey));
		}

		W[j].unsaturate();
		w.push_back(scale*W[j]);
		w.back().unsaturate();
	}

	// compute sum(w_j) === sum(a_i) mod 2
	// use the "three-for-two" trick that takes
	// three summands, (a,b,c) and replaces them
	// with two (u,v) that have the same sum
	// apply the trick repeatedly, until w contains
	// exactly two numbers, then sum those numbers
	deque<Cipherstring> w2;
	while(w.size() >= 3) {
		while(w.size() >= 3) {
			Cipherstring a = w.front(); w.pop_front(); a.unsaturate();
			Cipherstring b = w.front(); w.pop_front(); b.unsaturate();
			Cipherstring c = w.front(); w.pop_front(); c.unsaturate();

			 Cipherstring u = (a & b) | (b & c) | (a & c);
			// u is a collection of carry-bits, and there can
			// be no carry-in bit, so append 0
			u.push_back(Encryptor::encrypt(false,*pubkey));

			u.unsaturate();

			// v = a xor b xor c
			//Cipherstring v = xorer.operate(a, xorer.operate(b,c));
			Cipherstring v = a ^ b ^ c;

			w2.push_back(u);
			w2.push_back(v);
		}
		while(w2.size() > 0) {
			w.push_front(w2.back());
			w2.pop_back();
		}
	}

	Cipherstring sum = w[0] + w[1];
	sum.unsaturate();

	// finally, compute c* - sum
	// by calculating the two's complement
	// of sum, then adding
	Cipherstring inv;
	for(unsigned int i = 0; i < sum.size(); i++)
		inv.push_back(Encryptor::encrypt(true,*pubkey));
	inv.unsaturate();
	
	Cipherstring one;
	one.push_back(Encryptor::encrypt(true,*pubkey));
	one.unsaturate();

	Cipherstring diff = c_bar + (sum^inv) + one;

	// the result is diff mod 2 == the last bit of diff
	diff.back().setSaturated(true);
	*this = diff.back();
}

// XXX This does not work!!!
Cipherstring Cipherbit::getHammingColumn(vector<Cipherstring> M, unsigned int col)
{
	//TODO: check that the upper bound on j, 2^i == _theta
	vector<Cipherstring> P;
	//P[0][0] = 1
	P.push_back(Cipherstring(1, Encryptor::encrypt(true, *pubkey)));
	P.back().unsaturate();

	//P[j][0] = 0 for j = 1,...,_theta
	for(unsigned int j = 0; j < _theta; j++) {
		P.push_back(Cipherstring(1, Encryptor::encrypt(false, *pubkey)));
		P.back().unsaturate();
	}
	
	for(unsigned int k = 1; k <= M.size(); k++) {
		for(unsigned int j = _theta; j > 0; j--) {
			P[j].push_back((M[k-1][col] & P[j-1][k-1]) ^ P[j][k-1]);
		}
	}

	Cipherstring ret;
	for(unsigned int i = 1; i <= _theta; i++)
		ret.push_back(P[i][M.size()]);
	
	return ret;
}

Cipherbit::bitstring_t Cipherbit::mpzToBitstring(mpz_class a)
{
	string s = a.get_str(2);
	bitstring_t bits;
	// Push the binary representation of a onto
	// bits, using one's complement if negative
	for(unsigned int i = 0; i < s.size(); i++) {
		if(s[0] == '-') {
			if(i != 0)
				bits.push_back(s[i] == '0'?true:false);
		} else
			bits.push_back(s[i] == '0'?false:true);
	}
	// If a is negative, convert one's complement
	// to two's complement by adding 1
	if(s[0] == '-') {
		for(unsigned int i = bits.size() - 1; i >= 0; i--) {
			bits[i] = ~bits[i];
			if(bits[i])	// only continue adding a carry bit
				break;  // as long as bits[i] is one (~bits[i] is 0) 
		}
	}
	return bits;
}

// Convert an mpq in [0,2) to binary. only works on elemnts of Z
Cipherbit::bitstring_t Cipherbit::mpqToBitstring(mpq_class a)
{
	double frac = 1;
	unsigned int i = 0;
	bitstring_t bits;
	while(i++ < precision_bits + 1) {
		if(a >= frac) {
			bits.push_back(true);
			frac += frac/2;
			if(a == frac)
				break;
		} else
			frac -= frac/2;
	}

	return bits;
}


void Cipherbit::clearPubkey()
{
	pubkey= boost::shared_ptr<PublicKey>(new PublicKey());
} */
