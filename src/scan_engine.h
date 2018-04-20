#pragma once

#include "binary_file.h"
#include "scanner.h"
#include "vuln_report.h"


class IScanEngine {
public:

	/**
	 * scan target path, could be a folder or file
	 */
	virtual int scanPath(std::string sTargetPath) = 0;

	/**
	 * start the target binary file
	 * @param[in] sTargetPath - path to target file
	 * @return 0 if succeed
	 */
	virtual int scanFile(std::string sTargetPath) = 0;

};


class CScanEngine : public IScanEngine {
	
public:
	CScanEngine();
public:
	int scanPath(std::string sTargetPath);
	int scanFile(std::string sTargetPath);
	inline const std::vector<std::string>& getScanList() {
		return vScanList;
	}

	/**
	 * collect files need to be scan
	 */
	void collectFile(std::string sTargetPath);
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
	std::vector<std::string> vScanList;
};


class CScanEngineFactory {
public:
	static std::unique_ptr<IScanEngine> getScanEgnine() {
		return std::make_unique<CScanEngine>();
	}
};