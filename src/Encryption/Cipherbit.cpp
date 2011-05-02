
#include "Encryption/Cipherbit.hpp"

using namespace std;
using namespace Encryption;
using namespace Encryption::Keys;

const unsigned int _theta = 7;
const int precision_bits = 6;

Cipherbit::Cipherbit(mpz_class c, vector<mpq_class> z, PublicKey pubkey)
{
	this->value = c;
	this->Z = z;
	this->pubkey=pubkey;
	this->saturated = true;
}

mpz_class Cipherbit::getValue() const
{
	return this->value;
}

mpq_class Cipherbit::getZ(unsigned int index) const
{
	return this->Z.at(index);
}

void setSaturated(bool s)
{
	this->saturated = s;
}

Cipherbit Cipherbit::operator & ( const Cipherbit & cb) const
{
	
	//TODO: check for ciphertext with different public keys
	mpz_class val = value * cb.value;

	/* calculate z_i = (c* . y_i) mod 2, i \in {0,...,\Theta} */
	vector<mpq_class> Z;
	for(unsigned int i = 0; i < aPk.ysize(); i++)
		Z.push_back(fix_precision_bits(r_modulo((c_val * aPk.getY(i)), 2),precision_bits));
	
	if(saturated)
		recrypt();
	
	return Cipherbit(val, Z, pubkey);
}


Cipherbit Cipherbit::operator ^ ( const Cipherbit & cb) const
{
	
	//TODO: check for ciphertext with different public keys
	mpz_class val = value + cb.value;

	/* calculate z_i = (c* . y_i) mod 2, i \in {0,...,\Theta} */
	vector<mpq_class> Z;
	for(unsigned int i = 0; i < aPk.ysize(); i++)
		Z.push_back(fix_precision_bits(r_modulo((c_val * aPk.getY(i)), 2),precision_bits));
	
	if(saturated)
		recrypt();
	
	return Cipherbit(val, Z, pubkey);
}

//TODO: set saturated = false
void Cipherbit::recrypt()
{
	AddOperation adder();
	MultOperation multer();
	AndOperation ander();
	OrOperation orer();
	XorOperation xorer();

	// Encrypt value
	bitstring_t cbits = mpzToBitstring(value);
	Cipherstring c_bar;
	for(unsigned int i = 0; i < cbits.size(); i++)
		c_bar.push_back(Encryptor::encrypt(cbits[i],pubkey));
	c_bar.unsaturate();

	//compute A = {a_i}, i in {0,...,_bigtheta = Z.size()}
	vector<Cipherstring> A();
	for(unsigned int i = 0; i < Z.size(); i++) {
		bitstring_t z_bits = mpqToBitstring(Z[i]);
		Cipherstring z_bar;
		for(unsigned int j = 0; j < z_bits.size(); j++)
			z_bar.push_back(Encryptor::encrypt(Zbits[i],pubkey));
		z_bar.unsaturate();

		//compute a_i = s_i * z_i
		Cipherstring a();
		for(unsigned int j = 0; j < z_bar.size(); j++) {
			// because s_i is one bit,
			// s_i * z_i = s_i & z_i[j] for each bit of z_i
			a.push_back(pubkey.getEncryptedSkBit(i) & z_bar[j]);
		}
		a.unsaturate();
		A.push_back(a);
	}

	// compute W_j = sum_i(a_i[j])
	// if we view A as a matrix of bits (whose rows are a_i),
	// W_j is the sum (aka Hamming weight) of column j
	vector<Cipherstring> W();
	for(unsigned int j = 0; j < A[0].size(); j++)
		W.push_back(getHammingColumn(A,j));
	
	// compute w_j = 2^-j W_j mod 2
	dequeue<Cipherstring> w();
	for(unsigned int j = 0; j < W.size(); j++)
	{
		Cipherstring scale();
		for(unsigned int i = 0; i < W.size(); i++) {
			W[j].push_back(Encryptor:encrypt(false,pubkey));
			if(i == j)
				scale.push_back(Encryptor::encrypt(true,pubkey));
			else
				scale.push_back(Encryptor::encrypt(false,pubkey));
		}

		W[j].unsaturate();
		w.push_back(multer.operate(scale,W[j]));
		w.back().unsaturate();
	}

	// compute sum(w_j) === sum(a_i) mod 2
	// use the "three-for-two" trick that takes
	// three summands, (a,b,c) and replaces them
	// with two (u,v) that have the same sum
	// apply the trick repeatedly, until w contains
	// exactly two numbers, then sum those numbers
	dequeue<Cipherstring> w2();
	while(w.size() >= 3) {
		while(w.size() >= 3) {
			Cipherstring a = w.front(); w.pop_front(); a.unsaturate();
			Cipherstring b = w.front(); w.pop_front(); b.unsaturate();
			Cipherstring c = w.front(); w.pop_front(); c.unsaturate();

			// u = (a & b) | (b & c) | (a & c)
			Cipherstring u = orer.operate(
								ander.operate(a,b),
								orer.operate(
									ander.operate(b,c),
									ander.operate(a,c)));

			// u is a collection of carry-bits, and there can
			// be no carry-in bit, so append 0
			u.push_back(Encryptor::encrypt(false,pubkey));

			u.unsaturate();

			// v = a xor b xor c
			Cipherstring v = xorer.operate(a, xorer.operate(b,c));

			v.unsaturate();

			w2.push_back(u);
			w2.push_back(v);
		}
		while(w2.size() > 0) {
			w.push_front(w2.back());
			w2.pop_back();
		}
	}

	Cipherstring sum = adder.operate(w[0], w[1]);
	sum.unsaturate();

	// finally, compute c* - sum
	// by calculating the two's complement
	// of sum, then adding
	Cipherstring inv();
	for(unsigned int i = 0; i < sum.size(); i++)
		inv.push_back(Encryptor::encrypt(true,pubkey));
	inv.unsaturate();
	
	Cipherstring one();
	one.push_back(Encryptor::encrypt(true,pubkey));
	one.unsaturate();

	Cipherstring diff = adder.operate(c_bar,adder.operate(xorer.operate(sum,inv),one));

	// return diff mod 2 == the last bit of diff
	diff.back().setSaturated(true);
	return diff.back();
}

Cipherstring Cipherbit::getHammingColumn(vector<Cipherstring> M, unsigned int col)
{
	//TODO: check that the upper bound on j, 2^i == _theta
	vector< vector<Cipherbit> > P();
	//P[0][0] = 1
	P.push_back(vector<Cipherbit>(1, Encryptor::encrypt(true, pubkey)));
	//P[j][0] = 0 for j = 1,...,_theta
	for(unsigned int j = 0; j < _theta; j++)
		P.push_back(vector<Cipherbit>(1, Encryptor::encrypt(false, pubkey)));
	
	for(unsigned int k = 1; k <= M.size(); k++) {
		for(unsigned int j = _theta; j > 0; j--) {
			P[j].push_back((M[k][col] & P[j-1][k-1]) ^ P[j][k-1]);
		}
	}

	Cipherstring ret;
	for(unsigned int i = 1; i <= _theta; i++)
		ret.push_back(P[i][M.size()]);
	
	return ret;
}

bitstring_t mpzToBitstring(mpz_class a);
{
	string s = a.get_str(2);
	bitstring_t bits();
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
bitstring_t mpqToBitstring(mpq_class a)
{
	double frac = 1;
	unsigned int i = 0;
	bitstring_t bits();
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
