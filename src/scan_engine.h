#pragma once

#include "binary_file.h"
#include "scanner.h"
#include "vuln_report.h"

class IScanEngine {
public:

	/**
	 * start the target binary file
	 * @param[in] sTargetPath - path to target file
	 * @param[out] spVulnReport - pointer to IVulnReport
	 * @return 0 if succeed
	 */
	virtual int scanFile(std::string sTargetPath) = 0;

};


class CScanEngine : public IScanEngine {
	
public:
	CScanEngine();
public:
	
	int scanFile(std::string sTargetPath);

private:
	/**
	* load precompiled vulnerability signatures
	*
	* @return true if succeed
	*/
	bool LoadSignatures();

private:
	std::shared_ptr<SignatureLoader> spSigLoader;
	bool bSigLoaded;
};


class CScanEngineFactory {
public:
	static std::unique_ptr<IScanEngine> getScanEgnine() {
		return std::make_unique<CScanEngine>();
	}
};