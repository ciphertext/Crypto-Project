#ifndef GMP_SERIALIZATION_H
#define GMP_SERIALIZATION_H
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/split_free.hpp>
#include <boost/serialization/string.hpp>
#include <string>
#include <gmpxx.h>

BOOST_SERIALIZATION_SPLIT_FREE(mpz_class)


namespace boost { 
	namespace serialization {
		

		template<class Archive>
		void save(Archive & ar, const mpz_class & t, unsigned int version)
		{

			ar & t.get_str(10);
			
		}

		template<class Archive>
		void load(Archive & ar,  mpz_class & t, unsigned int version)
		{
			std::string num;
			ar & num;
			t.set_str(num,10);
			
		}
			
			
		template<class Archive>
		void serialize(Archive & ar, mpq_class & t, unsigned int version)
		{
			ar & t.get_num();
			ar & t.get_den();
		}

	}
}



#endif