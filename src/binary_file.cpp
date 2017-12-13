#include "binary_file.h"
#include "file_typer.h"
#include <iostream>

BinaryFile::BinaryFile(std::string& sFilePath) : 
	scanned(false), sFilePath(sFilePath){
	
}

void BinaryFile::scan() {
	FileTyper typer(sFilePath);
	if (!typer.isBinary()) {
		sr = SCAN_RESULT_NOT_BINARY;

	}
	else if (typer.isEXE()) {
		scanEXE();
	}
	else if (typer.isELF()) {
		scanELF();
	}
	else {
		sr = SCAN_RESULT_NOT_SUPPORT;
	}
	scanned = true;
}

void BinaryFile::scanEXE() {
	sr = SCAN_RESULT_SUCCESS;
}

void BinaryFile::scanELF() {
	sr = SCAN_RESULT_SUCCESS;
}

void BinaryFile::printResult() {
	if (scanned) {
		std::cout << scanResultToString(sr) << std::endl;
	}
	else {
		std::cout << "File yet to be scanned\n";
	}
}