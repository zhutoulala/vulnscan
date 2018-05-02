#include "scanner.h"
#include <iostream>

CASMScanner::CASMScanner(std::shared_ptr<SignatureLoader> spSigLoader, 
	std::shared_ptr<IBinaryFile> spBinaryFile) 
	: spSigLoader(spSigLoader), iCurrentOffset(0){
	assert(spBinaryFile != nullptr);
	this->spBinaryFile = spBinaryFile;
	ullCodeSectionBase = spBinaryFile->getCodeSectionBase();
	iCodeSectionLength = spBinaryFile->getCodeSectionSize();

	iBatchSize = 1024; //disassemble 1k instructions each time
}


SCAN_RESULT CASMScanner::scan(std::shared_ptr<IVulnReport>& spVulnReport) {

	SCAN_RESULT sr = spBinaryFile->analyze();
	if (SCAN_FAILED(sr)) {
		std::cout << "Failed to analyze binary" << std::endl;
		return sr;
	}

	if (spVulnReport == nullptr)
		spVulnReport = CVulnReportFactory::createReport();

	std::string sFunction;
	while (getNextFunction(sFunction)) {
		if (sFunction.empty()) continue;
		for (size_t i = 0; i < spSigLoader->getSize(); i++) {
			auto spSignature = spSigLoader->getSignature(i);
			if (spSignature->getFunctionName() == sFunction) {
				std::vector<std::string> sCallSequence;
				if (getCallSequence(sFunction, sCallSequence)) {
					spVulnReport->addDetection(spSignature->getCVE(), 
						spSignature->callSequenceMatch(sCallSequence));
				}
			}
		}
	}
	return sr;
}


bool CASMScanner::getNextFunction(std::string& sFunction) {
	iCurrentOffset = seekToInstruction(iCurrentOffset + 1, 
		iBatchSize, "push", { "ebp", "rbp" });

	if (iCurrentOffset == 0) {
		std::cout << "Couldn't get next function" << std::endl;
		return false;
	}

	sFunction = getCurrentSymbol();
	return true;
}

size_t CASMScanner::seekToInstruction(uint64_t iStartPos, size_t iBatchSize, 
	std::string sMnemonic, const std::vector<std::string>& vsOperand) {
	if (iStartPos >= iCodeSectionLength) {
		std::cout << "No more code to scan" << std::endl;
		return 0;
	}

	while (iStartPos < iCodeSectionLength) {

		std::unique_ptr<Disassembler::InstructionSet> spInstSet;

		if (SCAN_FAILED(spBinaryFile->getInstFromAddress(
			ullCodeSectionBase + iStartPos, iBatchSize, spInstSet))) {
			std::cout << "Failed to get instruction from address: " << iStartPos << std::endl;
			return 0;
		}
		
		for (size_t i = 0; i < spInstSet->count; i++) {
			//printf("0x%" PRIx64 ":\t%s\t\t%s", spInstSet->pInsn[i].address, 
			//spInstSet->pInsn[i].mnemonic, spInstSet->pInsn[i].op_str);
			
			if (sMnemonic.compare(spInstSet->pInsn[i].mnemonic) == 0) {
				for (auto sOperand : vsOperand) {
					if (sOperand.compare(spInstSet->pInsn[i].op_str) == 0) {
						uint64_t ullOffset = spInstSet->pInsn[i].address - ullCodeSectionBase;
						assert(ullOffset < SIZE_MAX);
						return (size_t)ullOffset;
					} //if
				} //for
			} //if
		} //for
		iStartPos += iBatchSize;
	} //while

	std::cout << "No more code to scan" << std::endl;
	return 0;
}

bool CASMScanner::getFunctionEnding(const std::string sFunction) {
	iCurrentOffset = seekToInstruction(iCurrentOffset, iBatchSize, "pop", { "ebp", "rbp" });
	if (iCurrentOffset == 0) {
		std::cout << "Couldn't find function ending" << std::endl;
		return false;
	}

	
	if (getCurrentSymbol() != sFunction) {
		std::cout << "Symbol for function ending doesn't match given function" << std::endl;
		return false;
	}
	return true;
}

bool CASMScanner::getSymbolAtAddress(uint64_t ullAddress, std::string& sSymbol) {
	SYMBOLMAP symbolMap;
	symbolMap.iAddress = ullAddress;
	if (SCAN_FAILED(spBinaryFile->getSymbols()->getSymbolFromAddress(&symbolMap))) {
		return false;
	}
	sSymbol = symbolMap.sName;
	return true;
}

bool CASMScanner::getSymbolAtOffset(size_t iOffset, std::string& sSymbol) {
	return getSymbolAtAddress(iOffset + ullCodeSectionBase, sSymbol);
}

std::string CASMScanner::getCurrentSymbol() {
	std::string sSymbol;
	getSymbolAtOffset(iCurrentOffset, sSymbol);
	return sSymbol;
}

bool CASMScanner::getCallSequence(std::string sFunction, std::vector<std::string>& vCalls) {
	
	std::string sCurrentFunction;
	if (getCurrentSymbol() != sFunction) {
		std::cout << "Function name doesn't match current offset" << std::endl;
		return false;
	}

	size_t iFunctionStart = iCurrentOffset;
	if (!getFunctionEnding(sFunction)) {
		std::cout << "Couldn't get function end" << std::endl;
		return false;
	}

	std::unique_ptr<Disassembler::InstructionSet> spInstSet;
	if (SCAN_FAILED(spBinaryFile->getInstFromAddress(
		ullCodeSectionBase + iFunctionStart, 
		iCurrentOffset - iFunctionStart, spInstSet))) {
		std::cout << "Failed to get instructions from function: " << sFunction << std::endl;
		return false;
	}


	for (size_t i = 0; i < spInstSet->count; i++) {
		std::string sMnemonic(spInstSet->pInsn[i].mnemonic);
		std::string sOperand(spInstSet->pInsn[i].op_str);
		if ((sMnemonic == "jmp") || (sMnemonic == "call")
			|| (sMnemonic == "je") || (sMnemonic == "jne")) {

			uint64_t ullAddress = std::strtoull(sOperand.c_str(), nullptr, 0);
			if (ullAddress != 0) {
				std::string sSymbol;
				if (getSymbolAtAddress(ullAddress, sSymbol))
					vCalls.push_back(sSymbol);
			}
		}

		else if (sMnemonic.find("dword ptr [") != std::string::npos) {
			size_t iLeft = sOperand.find("[");
			std::string sAddress = sOperand.substr(iLeft + 1, sOperand.find("]") - iLeft - 1);
			uint64_t ullAddress = std::strtoull(sAddress.c_str(), nullptr, 0);
			if (ullAddress != 0) {
				std::string sSymbol;
				if (getSymbolAtAddress(ullAddress, sSymbol))
					vCalls.push_back(sSymbol);
			}
		}
			
	} 
	return true;
}