#pragma once

#ifndef BINARY_FILE_H
#define BINARY_FILE_H

#include <string>

#include "scan_results.h"

class BinaryFile {

private:
    std::string sFilePath;
	bool scanned;
	SCAN_RESULT sr;

public:
    BinaryFile();
    BinaryFile(std::string& sFilePath);

public:
    void scan();
	void printResult();

    //llvm::MemoryBuffer* getCodeSection();
private:
	void scanEXE();
	void scanELF();
	
};

#endif //BINARY_FILE_H