#pragma once

#include "vulnerability.h"
#include <string>
#include <vector>
#include <memory>

class VulnReport {
private:
	std::unique_ptr<std::vector<Vulnerablity>> spFoundVulnerablities;

public:
	VulnReport();

public:
	bool isVulnerablityFound() { return spFoundVulnerablities->size() > 0; };

	std::string toString();
};