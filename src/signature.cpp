#include "signature.h" 
#include <fstream>
#include <sstream>
#include <iterator>
#include <algorithm>

CSignature::CSignature(std::string sCVE) : sCVE(sCVE) {

}

DETECTION_STATUS CSignature::stringMatch(const std::vector<std::string>& vLookupStrings) {
	size_t iPositiveCount = 0;
	size_t iNegativeCount = 0;
	for (auto eachLookup : vLookupStrings) {
		for (auto eachPositive : vPostiveStrings) {
			if (eachLookup.find(eachPositive) != std::string::npos)
				iPositiveCount++;
		}
		for (auto eachNegative : vNegativeStrings) {
			if (eachLookup.find(eachNegative) != std::string::npos)
				iNegativeCount++;
		}
	}

	DETECTION_STATUS status = DETECTION_NOMATCH;
	if (iPositiveCount == vPostiveStrings.size()) {
		status = DETECTION_STRING_MATCH | DETECTION_POSITIVE_MATCH;
	}

	if (iNegativeCount > 0)
		status |= DETECTION_STRING_MATCH | DETECTION_NEGATIVE_MATCH;
	return status;
}

DETECTION_STATUS CSignature::callSequenceMatch(
	const std::vector<std::string>& vCallSequence) {
	
	DETECTION_STATUS status = DETECTION_NOMATCH;
	if (vCallSequence.empty()) {
		return status;
	}
	if (!vPostiveCalls.empty() && isSubSet(vPostiveCalls, vCallSequence)) {
		status = DETECTION_ASM_MATCH | DETECTION_POSITIVE_MATCH;
	}

	if (!vNegativeCalls.empty() && isSubSet(vNegativeCalls, vCallSequence)) {
		status |= DETECTION_ASM_MATCH | DETECTION_NEGATIVE_MATCH;
	}

	return status;
}

template<class T>
bool CSignature::isSubSet(const std::vector<T>& v1, 
	const std::vector<T>& v2) {
	auto it1 = v1.begin();
	auto it2 = v2.begin();
	
	while (it1 != v1.end()) {
		while (it2 != v2.end()) {
			std::string sLowerCase1(*it1), sLowerCase2(*it2);
			
			std::transform(sLowerCase1.begin(), sLowerCase1.end(), 
				sLowerCase1.begin(), ::tolower);
			std::transform(sLowerCase2.begin(), sLowerCase2.end(), 
				sLowerCase2.begin(), ::tolower);
			if (sLowerCase1 != sLowerCase2) {
				it2++;
				continue;
			}
			else {
				it2++;
				break;
			}
		}
		if (it2 == v2.end()) {
			return false;
		}
		else 
			it1++;
	}
	return true;
}

bool SignatureLoader::load() {
	return loadSigs();
}

bool SignatureLoader::loadSigs()
{
    std::ifstream in("vulnscan.sigs");
    if (!in) {
        return false;
    }
	std::string sLine;
	while (std::getline(in, sLine)) {
		if (sLine.compare(0, 3, "CVE-")) {
			std::shared_ptr<CSignature> spSignature = std::make_shared<CSignature>(sLine);
			vspSignatures.push_back(spSignature);
			if (std::getline(in, sLine) && (sLine == "STRING:")) {
				while (std::getline(in, sLine)) {
					if (sLine.empty()) break;
					else if (sLine.at(0) == '+') {
						std::string strSig = sLine.substr(2);
						spSignature->addPostiveString(strSig);
					}
					else if (sLine.at(0) == '-') {
						std::string strSig = sLine.substr(2);
						spSignature->addNegativeString(strSig);
					}
					else
					{
						// bad STRING
						break;
					}
				}
				if (sLine == "ASM:") {
					while (std::getline(in, sLine)) {
						if (sLine.empty()) break;
						else if (sLine.at(0) == '+') {
							std::string sFunctionCalls(sLine.substr(2));
							size_t iPos = sFunctionCalls.find(':');
							spSignature->setFunctionName(sFunctionCalls.substr(0, iPos));
							std::istringstream iss(sFunctionCalls.substr(iPos+1));
							std::vector<std::string> vSplits(std::istream_iterator<std::string>{iss},
								std::istream_iterator<std::string>());
							spSignature->setPostiveCalls(vSplits);
						}
						else if (sLine.at(0) == '-') {
							std::string sFunctionCalls(sLine.substr(2));
							size_t iPos = sFunctionCalls.find(':');
							spSignature->setFunctionName(sFunctionCalls.substr(0, iPos));
							std::istringstream iss(sFunctionCalls.substr(iPos + 1));
							std::vector<std::string> vSplits(std::istream_iterator<std::string>{iss},
								std::istream_iterator<std::string>());
							spSignature->setNegativeCalls(vSplits);
						}
						else
						{
							// bad STRING
							break;
						}
					}
				}
			}

		}
	}
	return true;
}
