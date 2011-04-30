#ifndef TEST_UTILITY_H
#define TEST_UTILITY_H

#include "Encryption/Cipherbit.hpp"
#include "Encryption/Cipherstring.hpp"
#include "Encryption/Keys/PrivateKey.hpp"
#include "Encryption/Keys/PublicKey.hpp"
bool operator == (const Encryption::Cipherbit& c1, const Encryption::Cipherbit& c2)
{	
   for(unsigned int i=0;i<1000;i++)
	  if(c1.getZ(i) != c2.getZ(i)) 
	    return false;
	if(c1.getValue()!=c2.getValue())
		return false;
	
	return true;
}



bool operator == (const Encryption::Cipherstring & c1, const Encryption::Cipherstring & c2)
{	
	if(c1.size()!=c2.size())
		return false;
	
	for(unsigned int i=0; i < c1.size(); i++)
		if(!(c1.at(i)==c2.at(i)))
			return false;
	
	return true;	
}


bool operator == (const Encryption::Keys::PublicKey & p1, const Encryption::Keys::PublicKey & p2)
{
	if(p1.xsize()!=p2.xsize())
		return false;
	if(p1.ysize()!=p2.ysize())
		return false;
	if(p1.encryptedKeySize()!=p2.encryptedKeySize())
		return false;
	
	for(unsigned int i=0; i < p1.xsize(); i++)
	  if(p1.getX(i)!=p2.getX(i))
		  return false;

	for(unsigned int i=0; i < p1.ysize(); i++)
		if(p1.getY(i)!=p2.getY(i))
		  return false;

	for(unsigned int i=0; i < p1.encryptedKeySize(); i++)
		if(!(p1.getEncryptedSkBit(i)==p2.getEncryptedSkBit(i)))
			return false;
	
	return true;
}


bool operator == (const Encryption::Keys::PrivateKey & p1, const  Encryption::Keys::PrivateKey & p2)
{
	if(p1.size()!=p2.size())
		return false;
	
	for(unsigned int i=0; i < p1.size(); i++)
	  if(p1.getBit(i)!=p2.getBit(i))
		  return false;
	
	  return true;
}
#endif