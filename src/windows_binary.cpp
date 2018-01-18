#include "binary_file.h"
#include "file_typer.h"
#include "disassembler.h"
#include "parser-library/parse.h"

#include <iostream>
#include <vector>
#include <memory>
#include <fstream>
#include <future>




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
	peparse::parsed_pe *pParsedPE = peparse::ParsePEFromFile(sFilePath.c_str());
	if (pParsedPE == nullptr)
		return SCAN_RESULT_PE_PARSE_ERROR;

	peparse::VA entryPoint;
	if (peparse::GetEntryPoint(pParsedPE, entryPoint)) {
		// read the first 10000 bytes for now
		for (size_t i = 0; i < 10000; i++) {
			uint8_t b;
			peparse::ReadByteAtVA(pParsedPE, i + entryPoint, b);
			vCode.push_back(b);
		}
	}
	return SCAN_RESULT_SUCCESS;
}