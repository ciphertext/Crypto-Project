#include "Encryption/Operations/CipherStringOperators.hpp"


using namespace std;

namespace Encryption {
namespace Operations {


//TODO: Need to figure out default behavior for ANDing strings of different length.
Cipherstring operator &( Cipherstring  aA,  Cipherstring  aB)
{
	Cipherstring s;
	for(unsigned int i=0; i < min(aA.size(),aB.size()); i++)
		s.push_back(aA[i] & aB[i]);
	
	return s;
}


Cipherstring operator ^( Cipherstring  aA,  Cipherstring  aB)
{
	Cipherstring s;
	for(unsigned int i=0; i < min(aA.size(),aB.size()); i++)
		s.push_back(aA[i] ^ aB[i]);
	
	return s;
}


//TODO: Need to figure out default behavior for ANDing strings of different length.
Cipherstring operator |( Cipherstring  aA,  Cipherstring  aB)
{
	return (aA & aB) ^ (aA ^ aB);
}


Cipherstring operator +( Cipherstring  aA,   Cipherstring  aB)
{
	Cipherstring s;
	Cipherbit carry;
	int i;
	for(i = min(aA.size(),aB.size()) - 1; i >= 0; i--) {
		if(i == 0) {
			s.insert(s.begin(), aA[i] ^ aB[i]);
			carry = aA[i] & aB[i];
		} else {
			s.insert(s.begin(), aA[i] ^ aB[i] ^ carry);
			carry = (aA[i] & aB[i]) | (aA[i] & carry) | (aB[i] & carry);
		}
	}
	/*if(aA.size() > i) {
		for(unsigned int j = i; j < aA.size(); j++) {
			s.push_back(aA[i] & carry);
			carry = aA[j] & carry;
		}
	} else if(aB.size() > i) {
		for(unsigned int j = i; j < aB.size(); j++) {
			s.push_back(aB[i] & carry);
			carry = aB[j] & carry;
		}
	}*/
	//s.push_back(carry); // We no longer support overflow
	
	return s;
}


Cipherstring operator *( Cipherstring aA,  Cipherstring aB)
{
	Cipherstring prod;
	Cipherstring carry;
	unsigned int k = 0, m = 0;
	while(k < aA.size() && m < aA.size()) {
		if(k == aA.size() - 1)
			m++;
		else
			k++;

		Cipherstring summands;
		unsigned int x = aA.size() - m - 1;
		unsigned int y = aB.size() - k - 1;
		while(x > aA.size() - k && y < aB.size() - m) {
			summands.push_back(aA.at(x) & aB.at(y));
			x--; y++;
		}

		Cipherstring sum;
		for(vector<Cipherbit>::iterator it = summands.begin(); it != summands.end(); it++) {
			Cipherstring temp;
			temp.push_back(*it);
			if(it == summands.begin())
				sum = temp;
			else
				sum = sum + temp;
		}

		if(!carry.empty())
			carry = carry + sum;
		else
			carry = sum;

		prod.insert(prod.begin(), carry.back());
		carry.pop_back();
	}
	if(!carry.empty()) {
		prod.insert(prod.begin(), carry.back());
		carry.pop_back();
	}

	return prod;
}

} //namespace Operations
} //namespace Encryption
