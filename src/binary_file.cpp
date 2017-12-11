#include "binary_file.h"
#include "file_typer.h"
#include <iostream>


BinaryFile::BinaryFile() : scanned(false), format(FORMAT::UNKNOWN){
	
}

BinaryFile::BinaryFile(std::string& sFilePath) : 
	scanned(false), format(FORMAT::UNKNOWN), sFilePath(sFilePath){
	
}

void BinaryFile::scan() {
	FileTyper typer(sFilePath);
	if (!typer.isBinary()) {
		sr = SCAN_RESULT_NOT_BINARY;
	}
	scanned = true;
}

void BinaryFile::printResult() {
	if (scanned) {
		//std::cout << scanResultToString(sr) << std::endl;
	}
	else {
		std::cout << "File yet to be scanned\n";
	}
}