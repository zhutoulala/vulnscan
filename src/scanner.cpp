#include "scanner.h"
#include <iostream>

CScanner::CScanner() {
	spSigLoader = std::make_shared<SignatureLoader>();
	bSigLoaded = false;
}


SCAN_RESULT CScanner::LoadSignatures(){
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
			if ((strcmp(spInstSet->pInsn[i].mnemonic, "push") == 0) && (strcmp(spInstSet->pInsn[i].op_str, "ebp") == 0)) {
				SYMBOLMAP symbolMap;
				symbolMap.iAddress = spInstSet->pInsn[i].address;
				if (SCAN_SUCCEED(spBinaryFile->getSymbols()->getSymbolFromAddress(&symbolMap))) {
					std::cout << "\t\t#" << symbolMap.sName;
				}
			}
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