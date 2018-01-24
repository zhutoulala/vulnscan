#pragma once

#include "vulnerability.h"
#include "disassembler.h"
#include "signature.h"
#include <string>
#include <vector>
#include <memory>

class VulnReport {
private:
	std::vector<std::shared_ptr<Vulnerablity>> vspVulnerablities;

public:
	VulnReport();

public:
	bool isVulnerablityFound() { return vspVulnerablities.size() > 0; };
	SCAN_RESULT SearchForCVEbyCode(Disassembler::InstructionSet& instructionSet);
	SCAN_RESULT SearchForCVEbyString(std::vector<std::string>& vLookupStrings);
	SCAN_RESULT LoadSignature();
	std::string toString();

private:
	std::shared_ptr<SignatureLoader> spSigLoader;
	bool bSigLoaded;
};