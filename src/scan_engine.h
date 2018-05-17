#pragma once

#include "binary_file.h"
#include "scanner.h"
#include "vuln_report.h"
#include <map>

class IScanEngine {
public:

	/**
	 * scan target path, could be a folder or file
	 */
	virtual bool scanPath(std::string sTargetPath) = 0;

	/**
	 * start the target binary file
	 * @param[in] sTargetPath - path to target file
	 * @return true if succeed
	 */
	virtual bool scanFile(std::string sTargetPath) = 0;

	/**
	 * print scan results
	 */
	virtual void printResults() = 0;
};


class CScanEngine : public IScanEngine {
	
public:
	CScanEngine();
	CScanEngine(std::shared_ptr<IScanner> spASMScanner, std::shared_ptr<IScanner> spStringScanner);

public:
	bool scanPath(std::string sTargetPath);
	bool scanFile(std::string sTargetPath);
	void printResults();
	inline const std::vector<std::string>& getScanList() {
		return vScanList;
	}

	/**
	 * collect files need to be scan
	 */
	void collectFile(std::string sTargetPath);

private:
	std::shared_ptr<SignatureLoader> spSigLoader;
	std::vector<std::string> vScanList;
	std::map<std::string, std::shared_ptr<IVulnReport>> mSucceedScans;

	std::shared_ptr<IScanner> spASMScanner;
	std::shared_ptr<IScanner> spStringScanner;
};


class CScanEngineFactory {
public:
	static std::unique_ptr<IScanEngine> getScanEgnine() {
		return std::make_unique<CScanEngine>();
	}
};