#pragma once

#include "vulnerability.h"
#include "disassembler.h"
#include "signature.h"
#include "symbols.h"
#include <string>
#include <vector>
#include <memory>
#include <assert.h>
class IVulnReport {
public:
	virtual bool isVulnerablityFound() = 0;
	virtual void addVulnerablity(std::shared_ptr<IVulnerablity> spVulnerablity) = 0;
	virtual std::string toString() = 0;
	virtual std::shared_ptr<IVulnerablity> getVulnerablity(std::string sCVE) = 0;
	virtual void addDetection(std::string sCVE, DETECTION_STATUS status) = 0;
	virtual size_t numberOfVuln() = 0;
};

class CVulnReport : public IVulnReport {
private:
	std::vector<std::shared_ptr<IVulnerablity>> vspVulnerablities;

public:
	CVulnReport();

public:
	inline bool isVulnerablityFound() { return vspVulnerablities.size() > 0; };
	inline size_t numberOfVuln() { return vspVulnerablities.size(); };
	void addVulnerablity(std::shared_ptr<IVulnerablity> spVulnerablity);
	std::string toString();
	std::shared_ptr<IVulnerablity> getVulnerablity(std::string sCVE);
	void addDetection(std::string sCVE, DETECTION_STATUS status);
};


class CVulnReportFactory {
public:
	static std::unique_ptr<IVulnReport> createReport() {
		return std::make_unique<CVulnReport>();
	}
};