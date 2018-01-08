#include "gtest/gtest.h"
#include "binary_file.h"

TEST(BinaryFile, printResult)
{
	std::string test("test");
	IBinaryFile *pBinaryFile = nullptr;
	SCAN_RESULT sr = BinaryFactory::GetBinary(test, &pBinaryFile);
	ASSERT_EQ(sr, SCAN_RESULT_SUCCESS);

	ASSERT_NE(pBinaryFile, nullptr);
	VulnReport *pReport;
	sr = pBinaryFile->scan(&pReport);
	ASSERT_EQ(sr, SCAN_RESULT_SUCCESS);
    
}
