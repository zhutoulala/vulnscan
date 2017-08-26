//============================================================================
// Name        : vulnscan.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "binary_file.h"

#include "clang/CodeGen/CodeGenAction.h"
#include "clang/Frontend/CompilerInstance.h"

#include <iostream>
using namespace std;

int main(int argc, char **argv) {

    BinaryFile target(argv[1]);
    return target.scan();

    std::string inputFile = argv[1];
    clang::CompilerInstance compInst;

    clang::EmitLLVMOnlyAction codegenAction;
    codegenAction.BeginSourceFile(compInst,
            FrontendInputFile(inputFile, IK_CXX, false));
    codegenAction.Execute();
    codegenAction.EndSourceFile();

    llvm::Module* module = codegenAction.takeModule();

    return 0;
}
