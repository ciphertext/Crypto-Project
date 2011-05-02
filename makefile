#name of the default executable to compile to for build target 'all'
EXECUTABLE = encrypt

#classes (effectively all .cpp files that need compiled)
CLASSES = Encryption/Encryptor \
          Encryption/Cipherbit \
          Encryption/Keys/PublicKey \
          Encryption/Keys/PrivateKey \
          Encryption/Keys/KeyPair \
          Encryption/Operations/CipherStringOperators \
          Encryption/Operations/AddOperation \
          Encryption/Operations/MultOperation \
          Encryption/Operations/OrOperation \
          Encryption/Operations/AndOperation \
          Encryption/Operations/XorOperation \
          Encryption/Cipherstring \
          Encryption/EncryptionFacade \
          UI/UserInterface \
          main

#list of testcases
TESTCASES = Phase1Test \
            SerializationTest \
            EncryptionFacadeTest

#directory of source
SRCDIR = ./src

#directory of test cases
TESTDIR = test

#include and library directories
INCLUDES = -I/home/004/t/ts/tss063000/boost -I$(SRCDIR)
CLIBRARIES= -L/home/004/t/ts/tss063000/boost/lib 
LLIBRARIES= -L/home/004/t/ts/tss063000/boost/lib

#compiler
CC = g++

#compiler and linker flags
CFLAGS = -g -c -Wall $(INCLUDES) $(CLIBRARIES)
LFLAGS = $(LLIBRARIES) -lboost_random -l boost_serialization  -lgmpxx -lgmp



#------------------------------
#Dependency calculation
#------------------------------

SRCS = $(foreach SRC, $(CLASSES),$(SRCDIR)/$(SRC).cpp)
OBJS = $(foreach SRC, $(CLASSES),$(SRCDIR)/$(SRC).o)

TCSRCS = $(foreach SRC, $(TESTCASES),$(TESTDIR)/$(SRC).cpp)
TCOBJS = $(foreach SRC, $(TESTCASES),$(TESTDIR)/$(SRC).o)

%.o : %.cpp
	$(CC) $(CFLAGS) -MMD -o $@ $<
#	 @cp $*.d $*.P; \
#	   sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
#	     -e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $*.P; \
#	   rm -f $*.d



#  dependencies
-include $(SRCS:.cpp=.d)

#  test cases
-include $(TCSRCS:.cpp=.d)


#link
all: $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o $(EXECUTABLE)

tests: $(OBJS) $(TCOBJS)
	@for tc in $(TESTCASES); do $(CC) $(LFLAGS) $(OBJS) $(TESTDIR)/$$tc.o -o $$tc ; done

clean:
	rm -f $$(find $(SRCDIR) $(TESTDIR) | grep \\.o$$ ) $(EXECUTABLE) $$(find $(SRCDIR) $(TESTDIR) | grep \\.P$$ ) $$(find $(SRCDIR) $(TESTDIR) | grep \\.d$$ ) $(TESTCASES)

