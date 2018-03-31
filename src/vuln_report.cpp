#include "vuln_report.h"
#include <assert.h>
#include <iostream>

CVulnReport::CVulnReport() {
	vspVulnerablities = std::vector<std::shared_ptr<Vulnerablity>>();
	
}

std::string CVulnReport::toString() {
	if (vspVulnerablities.size() == 0) {
		return "No vulnerability found";
	}
	
	std::string sReport = "Found vulnerability: \n\n";
	for (auto it : vspVulnerablities) {
		sReport += it->getCVE();
		sReport += '\n';
	}
	return sReport;
}

/*
SCAN_RESULT CVulnReport::SearchForCVEbyCode(Disassembler::InstructionSet& instructionSet, std::unique_ptr<ISymbols>& spSymbols) {
	assert(spSymbols != nullptr);
	

	for (size_t i = 0; i < spSigLoader->getSize(); i++) {
		Signature *pSignature = spSigLoader->getSignature(i);
		if ((pSignature != nullptr) && (pSignature->asmCodeMatch(instructionSet))) {
			vspVulnerablities.push_back(std::make_shared<Vulnerablity>(pSignature->getCVE()));
		}
	}

	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT CVulnReport::SearchForCVEbyString(std::vector<std::string>& vLookupStrings) {
	for (size_t i = 0; i < spSigLoader->getSize(); i++) {
		Signature *pSignature = spSigLoader->getSignature(i);
		if ((pSignature != nullptr) && (pSignature->stringMatch(vLookupStrings))) {
			vspVulnerablities.push_back(std::make_shared<Vulnerablity>(pSignature->getCVE()));
		}
	}
	
	return SCAN_RESULT_SUCCESS;
}*/