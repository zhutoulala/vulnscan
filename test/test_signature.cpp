#include "signature.h"

#include "gtest/gtest.h"

#include <vector>

TEST(ISignature, CSignature)
{
	CSignature signature("CVE-test");
	std::vector<std::string> vStr = {"a", "bb", "ccc"};
	std::vector<std::string> vSubSet = { "a", "bb" };
	
	ASSERT_TRUE(signature.isSubSet(vSubSet, vStr));
	ASSERT_FALSE(signature.isSubSet(vStr, vSubSet));

	std::vector<std::string> vIncorrectOder = { "bb", "a" };
	ASSERT_FALSE(signature.isSubSet(vIncorrectOder, vStr));

	std::vector<std::string> vUpperStr = { "A", "bB", "cCC" };
	std::vector<std::string> vUpperSubSet = { "a", "BB" };
	ASSERT_TRUE(signature.isSubSet(vUpperSubSet, vUpperStr));
}