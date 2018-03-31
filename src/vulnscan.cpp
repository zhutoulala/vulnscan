//============================================================================
// Name        : vulnscan.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "binary_file.h"
#include "scanner.h"
#include "vuln_report.h"
#include <iostream>
#include <memory>

void printUsage() {
	std::cout << "vulnscan [binary file] [symbol file]\n";
}


int main(int argc, char **argv) {

	if (argc < 2) {
		printUsage();
		return -1;
	}

	std::string sTargetPath(argv[1]);

	std::unique_ptr<IBinaryFile> spBinaryFile;
	SCAN_RESULT sr = BinaryFactory::GetBinary(sTargetPath, spBinaryFile);
	if (SCAN_FAILED(sr) || (spBinaryFile == nullptr)) {
		std::cout << "GetBinary failed: " << scanResultToString(sr) << std::endl;
		return -1;
	}

	std::unique_ptr<IScanner> spScanner;
	
	sr = CScannerFactory::getScanner(spScanner);
	if (SCAN_FAILED(sr) || (spScanner == nullptr)) {
		std::cout << "GetScanner failed: " << scanResultToString(sr) << std::endl;
		return -1;
	}

	sr = spScanner->LoadSignatures();
	if (SCAN_FAILED(sr)) {
		std::cout << scanResultToString(sr) << std::endl;
		return -1;
	}

	std::unique_ptr<IVulnReport> spVulnReport;
	sr = spScanner->scanFile(spBinaryFile, spVulnReport);
	if (SCAN_FAILED(sr) || (spVulnReport == nullptr)) {
		std::cout << "scanFile failed: " << scanResultToString(sr) << std::endl;
		return -1;
	}

	std::cout << spVulnReport->toString();

	return 0;
}
