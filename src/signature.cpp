#pragma once
#include "signature.h" 
#include <fstream>
#include <sstream>


bool Signature::stringMatch(const std::vector<std::string>& vLookupStrings) {
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

	return ((iPositiveCount == vPostiveStrings.size()) && (iNegativeCount == 0));
}

bool Signature::asmCodeMatch(const Disassembler::InstructionSet& instructionSet) {
	size_t iPositiveCount = 0;
	size_t iNegativeCount = 0;
	for (size_t i = 0; i < instructionSet.count; i++) {
		for (auto eachPositive : vPostiveASM) {
			if (((eachPositive.find(instructionSet.pInsn[i].mnemonic) != std::string::npos))
				&& (eachPositive.find(instructionSet.pInsn[i].op_str) != std::string::npos))
				iPositiveCount++;
		}
		for (auto eachNegative : vNegativeASM) {
			if (((eachNegative.find(instructionSet.pInsn[i].mnemonic) != std::string::npos))
				&& (eachNegative.find(instructionSet.pInsn[i].op_str) != std::string::npos))
				iNegativeCount++;
		}
		instructionSet.pInsn[i].mnemonic,
			instructionSet.pInsn[i].op_str;
	}
	
	return ((iPositiveCount == vPostiveStrings.size()) && (iNegativeCount == 0));
}

bool SignatureLoader::load(std::string sSigsFilePath) {
	std::ifstream in(sSigsFilePath);

	if (!in) {
		return false;
	}

	std::string sLine;
	while (std::getline(in, sLine)) {
		if (sLine.compare(0, 3, "CVE-")) {
			std::shared_ptr<Signature> spSignature = std::make_shared<Signature>(sLine);
			vspSignatures.push_back(spSignature);
			if (std::getline(in, sLine) && (sLine == "STRING:")) {
				while (std::getline(in, sLine)) {
					if (sLine.empty()) break;
					else if (sLine.at(0) == '+') {
						spSignature->addPostiveString(sLine.substr(2));
					}
					else if (sLine.at(0) == '-') {
						spSignature->addNegativeString(sLine.substr(2));
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
						}
						else if (sLine.at(0) == '-') {
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

	in.close();
	return true;
}
