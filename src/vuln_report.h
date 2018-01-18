#pragma once

#include "vulnerability.h"
#include "disassembler.h"
#include <string>
#include <vector>
#include <memory>

class VulnReport {
private:
	std::vector<std::shared_ptr<Vulnerablity>> vVulnerablities;

public:
	VulnReport();

public:
	bool isVulnerablityFound() { return vVulnerablities.size() > 0; };
	size_t SearchForCVE(Disassembler::InstructionSet& instructionSet);
	std::string toString();
};