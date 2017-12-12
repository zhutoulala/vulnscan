#include "gtest/gtest.h"
#include "binary_file.h"

TEST(BinaryFile, printResult)
{
	std::string test("test");
    BinaryFile bin(test);
	bin.scan();
    
}
