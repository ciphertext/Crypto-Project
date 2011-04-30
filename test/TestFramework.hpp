#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <iostream>
#include <string>

//------------------------------------------
//               Test Framework
//------------------------------------------
#define TESTASSERT(_exprname,_expr) testAssert(_exprname,_expr); if(!_expr) return false;
#define TESTASSERTV(_exprname,_expr,_extra) testAssert(_exprname,_expr,_extra); if(!_expr) return false;

const bool verbose=true;


void logmsg(std::string msg)
{
	if(verbose)
	{
		std::cout<<"INFO: "<<msg<<std::endl;
		std::cout.flush();
	}
}

void testAssert(std::string exprname, bool expr, std::string extra="")
{
	if(!expr)
		std::cout<<"Testing ("<<exprname<<") : Failed. "<<extra<< std::endl;
	else if(verbose)
		std::cout<<"Testing ("<<exprname<<") : Passed. "<<extra<< std::endl;
}

void startTest(std::string testname)
{
	std::cout<<"Starting test " << testname<<"..."<<std::endl;
}

void endTest()
{
	std::cout << "Test succeeded "<<std::endl<<"-----------------"<<std::endl;
}

void failTest()
{
	std::cout << "Test failed"<<std::endl<<"-----------------"<<std::endl;
}


bool runTest(bool(test)(void), std::string name)
{
	bool success;
	startTest(name);
	success=test();
	if(success)
		endTest();
	else
		failTest();
	return success;
}

#endif