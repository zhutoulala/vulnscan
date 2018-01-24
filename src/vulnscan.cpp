//============================================================================
// Name        : vulnscan.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "binary_file.h"
#include "scan_results.h"
#include "vuln_report.h"
#include <iostream>
#include <memory>

void printUsage() {
	std::cout << "vulnscan [path to file]\n";
}


int main(int argc, char **argv) {

	if (argc < 2) {
		printUsage();
		return -1;
	}

	std::string sTargetPath(argv[1]);
	IBinaryFile *pBinaryFile = nullptr;
	SCAN_RESULT sr = BinaryFactory::GetBinary(sTargetPath, &pBinaryFile);
	if (SCAN_FAILED(sr) || (pBinaryFile == nullptr)) {
		std::cout << "GetBinary failed: " << scanResultToString(sr) << std::endl;
		return -1;
	}
	
	VulnReport* pReport;
	sr = pBinaryFile->scan(&pReport);
	std::cout << scanResultToString(sr) << std::endl;
	if SCAN_SUCCEED(sr)
		std::cout << pReport->toString();
	//std::string sSearch("test");
	//sr = pBinaryFile->searchString(sSearch);
	return 0;
}
