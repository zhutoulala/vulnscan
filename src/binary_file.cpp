#include "binary_file.h"
#include "file_typer.h"
#include <iostream>
#include <assert.h>

BinaryFile::BinaryFile(std::string& sFilePath) : 
	scanned(false), sFilePath(sFilePath){
	
}

SCAN_RESULT BinaryFile::scan(VulnReport** pReport) {
	SCAN_RESULT sr;

	FileTyper typer(sFilePath);
	if (!typer.isBinary()) {
		sr = SCAN_RESULT_NOT_BINARY;
	}
	else if (typer.isEXE()) {
		sr = scanEXE(pReport);
	}
	else if (typer.isELF()) {
		sr = scanELF(pReport);
	}
	else {
		sr = SCAN_RESULT_NOT_SUPPORT;
	}
	return sr;
}

SCAN_RESULT BinaryFile::scanEXE(VulnReport** pReport) {
	assert(pReport == nullptr);
	*pReport = new VulnReport();

	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT BinaryFile::scanELF(VulnReport** pReport) {
	assert(pReport == nullptr);
	*pReport = new VulnReport();

	return SCAN_RESULT_SUCCESS;
}