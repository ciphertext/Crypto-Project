
#include "Encryption/Operations/MultOperation.hpp"

#include <exception>
#include <algorithm>
using namespace std;
using namespace Encryption;
using namespace Encryption::Operations;


Cipherstring MultOperation::operate(Cipherstring aA, Cipherstring aB)
{
	Cipherstring prod();
	Cipherstring carry();
	unsigned int k = 0, m = 0;
	while(k < aA.size() && m < aA.size()) {
		if(k == aA.size() - 1)
			m++;
		else
			k++;

		Cipherstring summands();
		unsigned int x = aA.size() - m - 1;
		unsigned int y = aB.size() - k - 1;
		while(x > aA.size - k && y < aB.size() - m) {
			summands.push_back(aA[x] & aB[y]);
			x--; y++;
		}

		Cipherstring sum;
		for(vector<Cipherbit>::iterator it = summands.begin(); it != summands.end(); it++) {
			Cipherstring temp();
			temp.push_back(*it);
			if(it == summands.begin())
				sum = temp;
			else
				sum = AddOperation::operate(sum, temp);
		}

		if(!carry.empty())
			carry = AddOperation::operate(carry, sum);
		else
			carry = sum;

		prod.insert(prod.begin(), carry.pop_back());
	}
	if(!carry.empty())
		prod.insert(prod.begin(), carry.pop_back());

	return prod;
}
