#include "binary_file.h"
#include "file_typer.h"
#include "disassembler.h"
#include <iostream>
#include <assert.h>


SCAN_RESULT BinaryFactory::GetBinary(std::string sFilePath, IBinaryFile** ppBinaryFile) {
	FileTyper typer(sFilePath);
	if (!typer.isBinary()) {
		return SCAN_RESULT_NOT_BINARY;
	}
	else if (typer.isEXE()) {
		*ppBinaryFile = new WindowsBinary(sFilePath);
		return SCAN_RESULT_SUCCESS;
	}
	else if (typer.isELF()) {
		*ppBinaryFile = new LinuxBinary(sFilePath);
	}
	
	return SCAN_RESULT_NOT_SUPPORT;
}


WindowsBinary::WindowsBinary(std::string sFilePath) : IBinaryFile(sFilePath){

}

SCAN_RESULT WindowsBinary::scan(VulnReport** ppReport) {
	assert(ppReport == nullptr);
	
	std::vector<uint8_t> vCode;
	SCAN_RESULT sr = getCodeSection(vCode);
	if SCAN_FAILED(sr) {
		return sr;
	}
	Disassembler::InstructionSet instructionSet;
	sr = Disassembler::Disassembly(vCode, instructionSet);
	if SCAN_FAILED(sr) {
		return sr;
	}

	*ppReport = new VulnReport();
	(*ppReport)->SearchForCVE(instructionSet);

	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT WindowsBinary::getCodeSection(std::vector<uint8_t>& vCode) {
	return SCAN_RESULT_SUCCESS;
}

LinuxBinary::LinuxBinary(std::string sFilePath) : IBinaryFile(sFilePath) {

}


SCAN_RESULT LinuxBinary::scan(VulnReport** ppReport) {
	assert(ppReport == nullptr);

	return SCAN_RESULT_NOT_SUPPORT;
}

SCAN_RESULT LinuxBinary::getCodeSection(std::vector<uint8_t>& vCode) {
	return SCAN_RESULT_NOT_SUPPORT;
}