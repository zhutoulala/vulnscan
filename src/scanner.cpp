#include "scanner.h"
#include <iostream>

CScanner::CScanner() {
	spSigLoader = std::make_shared<SignatureLoader>();
	bSigLoaded = false;
}


SCAN_RESULT CScanner::LoadSignatures() {
	if (!bSigLoaded && !spSigLoader->load("vulnscan.sigs")) {
		return SCAN_RESULT_NO_SIGS;
	}
	bSigLoaded = true;
	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT CScanner::scanFile(std::unique_ptr<IBinaryFile>& spBinaryFile, std::unique_ptr<IVulnReport>& spVulnReport) {
	assert(spVulnReport == nullptr);

	SCAN_RESULT sr = spBinaryFile->analyze();
	if (SCAN_FAILED(sr)) {
		std::cout << "Failed to analyze binary" << std::endl;
		return sr;
	}

	spVulnReport = CVulnReportFactory::createReport();

	uint64_t ullCodeSectionBase = spBinaryFile->getCodeSectionBase();
	size_t iCodeSectionLength = spBinaryFile->getCodeSectionSize();

	size_t iCurrent = 0;
	size_t iBatchSize = 1024; //disassemble 1k instructions each time
	while (iCurrent < iCodeSectionLength)
	{
		std::unique_ptr<Disassembler::InstructionSet> spInstSet;

		sr = spBinaryFile->getInstFromAddress(ullCodeSectionBase + iCurrent, iBatchSize, spInstSet);
		for (size_t i = 0; i < spInstSet->count; i++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s", spInstSet->pInsn[i].address, spInstSet->pInsn[i].mnemonic, spInstSet->pInsn[i].op_str);
			std::string sSymbol = getSymbolIfNeed(spBinaryFile->getSymbols(), &spInstSet->pInsn[i]);
			
			if (!sSymbol.empty())
				std::cout << "\t\t#" << sSymbol;
			std::cout << std::endl;
		}

		iCurrent += iBatchSize;
	}

	/*std::vector<std::string> vStrings;
	SCAN_RESULT sr = getStrings(vStrings);
	if SCAN_SUCCEED(sr) {
	sr = (*ppReport)->SearchForCVEbyString(vStrings);
	if SCAN_FAILED(sr) {
	return sr;
	}
	}*/

	return SCAN_RESULT_SUCCESS;
}


std::string CScanner::getSymbolIfNeed(std::shared_ptr<ISymbols> spSymbols, const Disassembler::PInstruction pInst) {
	assert(spSymbols != nullptr);
	assert(pInst != nullptr);
	
	std::string sMnemonic(pInst->mnemonic);
	std::string sOperand(pInst->op_str);
	// push ebp
	if ((sMnemonic == "push") && (sOperand == "ebp") || (sOperand == "rbp")) {
		SYMBOLMAP symbolMap;
		// get current address symbol
		symbolMap.iAddress = pInst->address;
		if (SCAN_SUCCEED(spSymbols->getSymbolFromAddress(&symbolMap))) {
			return symbolMap.sName;
		}
	}

	// jmp or call [address]
	else if ((sMnemonic == "jmp") || (sMnemonic == "call")
		|| (sMnemonic == "je") || (sMnemonic == "jne")) {
		SYMBOLMAP symbolMap;
		// get target address symbol
		symbolMap.iAddress = std::strtoull(pInst->op_str, nullptr, 0);
		if (symbolMap.iAddress != 0) {
//			symbolMap.iAddress -= ullBaseAddress;
//			symbolMap.iAddress &= 0x00000000ffffffff;
			if (SCAN_SUCCEED(spSymbols->getSymbolFromAddress(&symbolMap)))
				return symbolMap.sName;
		}
	}

	// op_str might be like "dword ptr [0x12345]"
	else if (sMnemonic.find("dword ptr [") != std::string::npos) {
		size_t iLeft = sOperand.find("[");
		std::string sOffset = sOperand.substr(iLeft+1, sOperand.find("]")-iLeft-1);
		SYMBOLMAP symbolMap;
		symbolMap.iAddress = std::strtoull(sOffset.c_str(), nullptr, 0);
		if (SCAN_SUCCEED(spSymbols->getSymbolFromAddress(&symbolMap)))
			return symbolMap.sName;
	}

	return "";
}