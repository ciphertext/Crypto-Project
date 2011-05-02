#ifndef CIPHERSTRING_OPERATOR_H
#define CIPHERSTRING_OPERATOR_H
#include "Encryption/Cipherstring.hpp"
#include <vector>


namespace Encryption{
	class Cipherstring;
	class Cipherbit;
	
	namespace Operations{
		
		Cipherstring operator &( Cipherstring  aA,  Cipherstring  aB);
		Cipherstring operator ^( Cipherstring  aA,  Cipherstring  aB);
		Cipherstring operator |( Cipherstring  aA,  Cipherstring  aB);
		Cipherstring operator +( Cipherstring  aA,  Cipherstring  aB);
		Cipherstring operator *( Cipherstring  aA,  Cipherstring  aB);

	}
}

#endif
