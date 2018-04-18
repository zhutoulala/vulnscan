#include "signature.h"

#include "gtest/gtest.h"

#include <vector>

TEST(CSignature, isSubSet) {
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

TEST(CSignature, hasFunctionSig) {
	CSignature signature("CVE-test");
	std::string sFunction("test-func");
	signature.setFunctionName(sFunction);

	ASSERT_FALSE(signature.hasFunctionSig());
	signature.setPostiveCalls({ "abc", "ef" });
	ASSERT_TRUE(signature.hasFunctionSig());
	ASSERT_EQ(signature.getFunctionName(), sFunction);
	ASSERT_EQ(signature.getCVE(), "CVE-test");
}

TEST(CSignature, stringMatch) {
	CSignature signature("CVE-test");
	signature.addPostiveString("abc");
	signature.addPostiveString("ef");
	signature.addNegativeString("qwe");
	ASSERT_EQ(signature.stringMatch({"abc", "ef", "qwe", "123"}),
		DETECTION_STRING_MATCH | DETECTION_POSITIVE_MATCH | DETECTION_NEGATIVE_MATCH);
}

TEST(CSignature, callSequenceMatch) {
	CSignature signature("CVE-test");
	std::vector<std::string> vStr = { "a", "bb", "ccc" };
	signature.setFunctionName("test_func");
	signature.setPostiveCalls(vStr);	
	ASSERT_EQ(signature.callSequenceMatch({ "a", "bb", "ccc", "d" }),
		DETECTION_ASM_MATCH | DETECTION_POSITIVE_MATCH);
	signature.setNegativeCalls(vStr);
	ASSERT_EQ(signature.callSequenceMatch({ "a", "bb", "ccc", "d" }),
		DETECTION_ASM_MATCH | DETECTION_POSITIVE_MATCH | DETECTION_NEGATIVE_MATCH);
}