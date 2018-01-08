#include "vuln_report.h"

VulnReport::VulnReport() {
	spFoundVulnerablities = std::unique_ptr<std::vector<Vulnerablity>>(new std::vector<Vulnerablity>());
}

std::string VulnReport::toString() {
	if (spFoundVulnerablities->size() == 0) {
		return "No vulnerability found";
	}
	
	std::string sReport = "Found vulnerability: \n\n";
	for (std::vector<Vulnerablity>::iterator it = spFoundVulnerablities->begin();
		it != spFoundVulnerablities->end(); it ++) {
		sReport += it->getCVE();
		sReport += '\n';
	}
	return sReport;
}

size_t VulnReport::SearchForCVE(Disassembler::InstructionSet& instructionSet) {
	return 0;
}