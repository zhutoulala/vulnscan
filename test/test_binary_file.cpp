#include "gtest/gtest.h"
#include "binary_file.h"

TEST(BinaryFile, printResult)
{
	std::string test("test");
    BinaryFile bin(test);
	VulnReport *pReport;
	SCAN_RESULT sr = bin.scan(&pReport);
	ASSERT_EQ(sr, SCAN_RESULT_SUCCESS);
    
}
