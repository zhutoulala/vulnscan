#pragma once

#include <string>

#include "scan_results.h"

class BinaryFile {

public:
    enum class FORMAT {
        EXE, //windows
        ELF, //linux
        UNKNOWN
    };

private:
    FORMAT format;
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

};
