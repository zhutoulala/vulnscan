#pragma once

#include "binary_file.h"
#include "vuln_report.h"

class IScanner {
public:
	
	/**
	 * load precompiled vulnerability signatures
	 * 
	 * @return SCAN_RESULT_SUCCESS if succeed
	 */
	virtual SCAN_RESULT LoadSignatures() = 0;
	

	/**
	 * start the target binary file
	 * @param[in] spBinaryFile - pointer to IBinaryFile
	 * @param[out] spVulnReport - pointer to IVulnReport
	 * @return SCAN_RESULT_SUCCESS if succeed
	 */
	virtual SCAN_RESULT scanFile(std::unique_ptr<IBinaryFile>& spBinaryFile, std::unique_ptr<IVulnReport>& spVulnReport) = 0;
	

};


class CScanner : public IScanner {
	
public:
	CScanner();

public:
	SCAN_RESULT LoadSignatures();
	SCAN_RESULT scanFile(std::unique_ptr<IBinaryFile>& spBinaryFile, std::unique_ptr<IVulnReport>& spVulnReport);

private:
	std::shared_ptr<SignatureLoader> spSigLoader;
	bool bSigLoaded;
};


class CScannerFactory {
public:
	static SCAN_RESULT getScanner(std::unique_ptr<IScanner>& spScanner) {
		spScanner = std::make_unique<CScanner>();
		return SCAN_RESULT_SUCCESS;
	}
};