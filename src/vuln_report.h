#pragma once

#include "vulnerability.h"
#include "disassembler.h"
#include "signature.h"
#include "symbols.h"
#include <string>
#include <vector>
#include <memory>

class IVulnReport {
public:
	virtual bool isVulnerablityFound() = 0;

	virtual std::string toString() = 0;
};

class CVulnReport : public IVulnReport {
private:
	std::vector<std::shared_ptr<Vulnerablity>> vspVulnerablities;

public:
	CVulnReport();

public:
	bool isVulnerablityFound() { return vspVulnerablities.size() > 0; };

	std::string toString();
};


class CVulnReportFactory {
public:
	static std::unique_ptr<IVulnReport> createReport() {
		return std::make_unique<CVulnReport>();
	}
};