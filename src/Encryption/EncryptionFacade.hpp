


#ifndef __Encryption__EncryptionFacade_h__
#define __Encryption__EncryptionFacade_h__


#include "Encryption/Encryptor.hpp"
#include "Encryption/Operations/CipherStringBinaryOperation.hpp"
#include "Encryption/Operations/AddOperation.hpp"
#include "Encryption/Operations/AndOperation.hpp"
#include "Encryption/Operations/MultOperation.hpp"
#include "Encryption/Operations/OrOperation.hpp"
#include "Encryption/Operations/XorOperation.hpp"

#include "Encryption/Keys/KeyPair.hpp"
#include "Encryption/Keys/PublicKey.hpp"
#include "Encryption/Keys/PrivateKey.hpp"
#include <exception>
#include <string>
#include <list>
#include <map>
#include <boost/serialization/string.hpp>
#include <sstream>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/foreach.hpp>
#include <boost/serialization/shared_ptr.hpp>

namespace Encryption
{
	class EncryptionFacade
	{
		public:
			EncryptionFacade();
			
			std::string executeOperation(std::string command, std::string arg1, std::string arg2, std::string aPublicKey);
			
			std::string decrypt(std::string aCiphertext, std::string aPrivateKey);
			
			std::string encrypt(std::string aMessage, std::string aPublicKey);
			
			std::pair<std::string,std::string> genKeyPair();
			
		private:
			typedef boost::ptr_map<std::string, Encryption::Operations::CipherStringBinaryOperation> CommandMap;
			typedef boost::dynamic_bitset<unsigned char> bitstring_t;
			
			CommandMap mCmdMap;
			Cipherstring encryptString(std::string message, boost::shared_ptr<Keys::PublicKey>  pk) const;
			bitstring_t decryptString(const Cipherstring & ciphertext, boost::shared_ptr<Keys::PrivateKey>  sk) const;
			
		   bitstring_t toBits(std::string text) const; 
			std::string toString(bitstring_t bits) const;
			
			void addOperation(std::string opname, Encryption::Operations::CipherStringBinaryOperation * operation);
			
			
			
	};   
	
	template<typename T>
	std::string serialize(T t)
	{
		std::ostringstream oss;
		boost::archive::text_oarchive ar(oss);
		ar << t;
		return oss.str();
	};


	template<typename T>
	T unserialize(std::string s)
	{
		//nothing to see here... move along.
		char allocation[sizeof(T)];
		T * t = reinterpret_cast<T*>(allocation);
		boost::serialization::access::construct<T>(t);
		
		std::istringstream iss(s);
		boost::archive::text_iarchive ar(iss);
		
		ar >> *t;
		//TODO: Destructor
		return *t;
	};
}

#endif
