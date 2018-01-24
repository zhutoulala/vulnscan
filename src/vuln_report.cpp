#include "vuln_report.h"
#include <iostream>

VulnReport::VulnReport() {
	vspVulnerablities = std::vector<std::shared_ptr<Vulnerablity>>();
	spSigLoader = std::make_shared<SignatureLoader>();
	bSigLoaded = false;
}

std::string VulnReport::toString() {
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

SCAN_RESULT VulnReport::SearchForCVEbyCode(Disassembler::InstructionSet& instructionSet) {
	LoadSignature();
	// print first 30 KB
	if (instructionSet.count > 30000) {
		for (size_t i = 0; i < 30000; i++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", instructionSet.pInsn[i].address, instructionSet.pInsn[i].mnemonic,
								  instructionSet.pInsn[i].op_str);
		}
	}
	for (size_t i = 0; i < spSigLoader->getSize(); i++) {
		Signature *pSignature = spSigLoader->getSignature(i);
		if ((pSignature != nullptr) && (pSignature->asmCodeMatch(instructionSet))) {
			vspVulnerablities.push_back(std::make_shared<Vulnerablity>(pSignature->getCVE()));
		}
	}

	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT VulnReport::SearchForCVEbyString(std::vector<std::string>& vLookupStrings) {
	LoadSignature();
	for (size_t i = 0; i < spSigLoader->getSize(); i++) {
		Signature *pSignature = spSigLoader->getSignature(i);
		if ((pSignature != nullptr) && (pSignature->stringMatch(vLookupStrings))) {
			vspVulnerablities.push_back(std::make_shared<Vulnerablity>(pSignature->getCVE()));
		}
	}
	
	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT VulnReport::LoadSignature() {
	if (!bSigLoaded && !spSigLoader->load("vulnscan.sigs")) {
		return SCAN_RESULT_NO_SIGS;
	}
	bSigLoaded = true;
	return SCAN_RESULT_SUCCESS;
}