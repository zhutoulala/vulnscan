//============================================================================
// Name        : vulnscan.cpp
// Author      : 
// Version     :
// Copyright   : zhutoulala@gmail.com
// Description : a static binary vulnerability scanner
//============================================================================

#include "binary_file.h"
#include "scan_engine.h"
#include "vuln_report.h"
#include <iostream>
#include <memory>

void printUsage() {
	std::cout << "vulnscan [binary file]\n";
}


int main(int argc, char **argv) {

	if (argc < 2) {
		printUsage();
		return -1;
	}

	auto spScanEngine = CScanEngineFactory::getScanEgnine();
	if (spScanEngine == nullptr) {
		std::cout << "Failed to initialize ScanEngine.\n";
		return -1;
	}

	std::string sTargetPath(argv[1]);

	return spScanEngine->scanPath(sTargetPath);
}
