//============================================================================
// Name        : vulnscan.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "binary_file.h"

#include <iostream>

void printUsage() {
	std::cout << "vulnscan [path to file]\n";
}


int main(int argc, char **argv) {

	if (argc < 2) {
		printUsage();
		return -1;
	}

	std::string sTargetPath(argv[1]);
    BinaryFile target(sTargetPath);
    target.scan();
	target.printResult();
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
