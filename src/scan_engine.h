#pragma once

#include "binary_file.h"
#include "scanner.h"
#include "vuln_report.h"
#include "utils\thread_pool.h"
#include <map>
#include <mutex>

class IScanEngine {
public:

	/**
	 * scan target path, could be a folder or file
	 */
	virtual bool scanPath(std::string sTargetPath) = 0;

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
	void scanFile(std::string sTargetPath);
	void printResults();


private:
    std::mutex m_mutex;
	std::shared_ptr<SignatureLoader> spSigLoader;
	std::map<std::string, std::shared_ptr<IVulnReport>> mSucceedScans;
    std::vector<std::string> vFailedScans;
    std::unique_ptr<CThreadPool> m_threadPool;
};


class CScanEngineFactory {
public:
	static std::unique_ptr<IScanEngine> getScanEgnine() {
		return std::make_unique<CScanEngine>();
	}
};