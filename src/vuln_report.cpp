#include "vuln_report.h"
#include <iostream>

VulnReport::VulnReport() {
	vVulnerablities = std::vector<std::shared_ptr<Vulnerablity>>();
}

std::string VulnReport::toString() {
	if (vVulnerablities.size() == 0) {
		return "No vulnerability found";
	}
	
	std::string sReport = "Found vulnerability: \n\n";
	for (auto it : vVulnerablities) {
		sReport += it->getCVE();
		sReport += '\n';
	}
	return sReport;
}

size_t VulnReport::SearchForCVE(Disassembler::InstructionSet& instructionSet) {
	for (size_t i = 0; i < instructionSet.count; i++) {
		printf("0x%" PRIx64 ":\t%s\t\t%s\n", instructionSet.pInsn[i].address, instructionSet.pInsn[i].mnemonic,
			                  instructionSet.pInsn[i].op_str);
	}
	return 0;
}