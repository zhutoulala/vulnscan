#pragma once

#include <vector>
#include <stack>
#include <memory>
#include "gtest/gtest_prod.h"
#include "disassembler.h"
#include "scan_results.h"

class ISignature {
public:
	/**
	 * does this signature contain a function signature
	 */
	virtual bool hasFunctionSig() = 0;

	/**
	 * does this signature contain any string signature
	 */
	virtual bool hasStringSig() = 0;

	/**
	 * get the CVE name for which this signature is
	 */
	virtual std::string getCVE() = 0;

	/**
	 * get the function name if there is a function signature
	 */
	virtual std::string getFunctionName() = 0;

	/**
	 * for function signature, does it match the given call sequence inside the function
	 */
	virtual DETECTION_STATUS callSequenceMatch(const std::vector<std::string>& vCallSequence) = 0;

	/**
	 * for string signature, does all given strings match the signature string list
	 */
	virtual DETECTION_STATUS stringMatch(const std::vector<std::string>& vLookupStrings) = 0;
};

class CSignature : public ISignature{
public:
	CSignature(std::string sCVE);

public:
	inline bool hasFunctionSig() { 
		return !sFunction.empty() && vPostiveCalls.size() > 0; 
	}

	inline bool hasStringSig() {
		return vPostiveStrings.size() > 0;
	}
	inline std::string getCVE() { return sCVE; }
	inline std::string getFunctionName() { return sFunction; }
	DETECTION_STATUS callSequenceMatch(const std::vector<std::string>& vCallSequence);
	DETECTION_STATUS stringMatch(const std::vector<std::string>& vLookupStrings);

public:

	inline void setFunctionName(std::string sFunctionName) {
		sFunction = sFunctionName;
	}

	inline void setPostiveCalls(const std::vector<std::string>& vCallSequence) {
		vPostiveCalls = vCallSequence;
	}

	inline void setNegativeCalls(const std::vector<std::string>& vCallSequence) {
		vNegativeCalls = vCallSequence;
	}

	inline void addPostiveString(std::string& sPostiveString) {
		vPostiveStrings.push_back(sPostiveString);
	}

	inline void addNegativeString(std::string& sNegativeString) {
		vNegativeStrings.push_back(sNegativeString);
	}

	/**
	 * check if v1 is a subset of v2
 	 */
	template<class T>
	bool isSubSet(const std::vector<T>& v1, const std::vector<T>& v2);

private:
	std::string sCVE;
	std::string sFunction;
	std::vector<std::string> vPostiveStrings;
	std::vector<std::string> vNegativeStrings;
	std::vector<std::string> vPostiveCalls;
	std::vector<std::string> vNegativeCalls;
};

class SignatureLoader {
public:
	SignatureLoader() {};

public:
	bool load(std::string sSigsFilePath);
	inline size_t getSize() {
		return vspSignatures.size();
	}

	inline std::shared_ptr<ISignature> getSignature(size_t index) {
		return vspSignatures.at(index);
	};

private:
	FRIEND_TEST(SignatureLoader, loadSigs);
	void loadSigs(std::istream& in);

private:
	std::vector<std::shared_ptr<CSignature>> vspSignatures;
};