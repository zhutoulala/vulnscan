#include "binary_file.h"
#include "file_typer.h"
#include "disassembler.h"
#include "parser-library/parse.h"

#include <iostream>
#include <vector>
#include <memory>
#include <fstream>
#include <future>
#include <assert.h>



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

SCAN_RESULT WindowsBinary::ReadEntireFile()
{
	std::ifstream ifile(sFilePath, std::ios::binary | std::ios::in | std::ios::ate);
	if (ifile.is_open())
	{
		auto size = ifile.tellg();
		ifile.seekg(0, std::ios::beg);
		ifile.read(vBuffer.data, size);
		ifile.close();
		return SCAN_RESULT_SUCCESS;
	}
	return SCAN_RESULT_NOT_FOUND;
}

SCAN_RESULT WindowsBinary::ParsePE()
{
	
}