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
		std::cout << "GetBinart failed: " << scanResultToString(sr) << std::endl;
		return -1;
	}
	
	VulnReport* pReport;
	sr = pBinaryFile->scan(&pReport);
	std::cout << scanResultToString(sr) << ':' << pReport->toString();
	return 0;

	/*
    std::string inputFile = argv[1];
    clang::CompilerInstance compInst;

    clang::EmitLLVMOnlyAction codegenAction;
    codegenAction.BeginSourceFile(compInst,
            FrontendInputFile(inputFile, IK_CXX, false));
    codegenAction.Execute();
    codegenAction.EndSourceFile();

    llvm::Module* module = codegenAction.takeModule();
	*/

    //return 0;
}
