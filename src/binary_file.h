#pragma once

#include "scan_results.h"
#include "vuln_report.h"
#include <string>

class BinaryFile {

private:
    std::string sFilePath;
	bool scanned;

public:
    BinaryFile(std::string& sFilePath);

public:
	SCAN_RESULT scan(VulnReport** pReport);

    //llvm::MemoryBuffer* getCodeSection();
private:
	SCAN_RESULT scanEXE(VulnReport** pReport);
	SCAN_RESULT scanELF(VulnReport** pReport);
	
};