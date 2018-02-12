#include "binary_file.h"
#include "file_typer.h"
#include "disassembler.h"

#include "string_parser.h"

#include <iostream>
#include <vector>
#include <memory>
#include <fstream>
#include <future>


uint64_t WindowsBinary::codeSectionBase;
uint32_t WindowsBinary::codeSectionSize;

WindowsBinary::WindowsBinary(std::string sFilePath) : IBinaryFile(sFilePath){

}

SCAN_RESULT WindowsBinary::scan(VulnReport** ppReport) {	
	*ppReport = new VulnReport();

	std::vector<std::string> vStrings;
	SCAN_RESULT sr = getStrings(vStrings);
	if SCAN_SUCCEED(sr) {
		sr = (*ppReport)->SearchForCVEbyString(vStrings);
		if SCAN_FAILED(sr) {
			return sr;
		}
	}
	
	std::vector<uint8_t> vCode;
	sr = getCodeSection(vCode);
	if SCAN_SUCCEED(sr) {
		Disassembler::InstructionSet instructionSet;
		sr = Disassembler::Disassembly(vCode, instructionSet);
		if SCAN_FAILED(sr) {
			return sr;
		}	
		sr = (*ppReport)->SearchForCVEbyCode(instructionSet);
		if SCAN_FAILED(sr) {
			return sr;
		}
	}

	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT WindowsBinary::getCodeSection(std::vector<uint8_t>& vCode) {
	peparse::parsed_pe *pParsedPE = peparse::ParsePEFromFile(sFilePath.c_str());
	if (pParsedPE == nullptr) {
		std::cout << "Error: " << peparse::GetPEErr() << " (" << peparse::GetPEErrString() << ")" << endl;
		std::cout << "Location: " << peparse::GetPEErrLoc() << endl;
		return SCAN_RESULT_PE_PARSE_ERROR;
	}
	IterSec(pParsedPE, WindowsBinary::locateCodeSection, NULL);
	/*peparse::VA entryPoint;
	if (peparse::GetEntryPoint(pParsedPE, entryPoint)) {
		// read the first 1000 bytes for now
		for (size_t i = 0; i < 10000; i++) {
			uint8_t b;
			peparse::ReadByteAtVA(pParsedPE, i + entryPoint, b);
			vCode.push_back(b);
		}
	}*/
	for (size_t i = 0; i < WindowsBinary::codeSectionSize; i++) {
		uint8_t b;
		peparse::ReadByteAtVA(pParsedPE, i + WindowsBinary::codeSectionBase, b);
		vCode.push_back(b);
	}
	return SCAN_RESULT_SUCCESS;
}

int WindowsBinary::locateCodeSection(void *N,
	peparse::VA secBase,
	std::string &secName,
	peparse::image_section_header s,
	peparse::bounded_buffer *data) {
	static_cast<void>(N);
	static_cast<void>(s);
	if (secName == ".text") {
		WindowsBinary::codeSectionBase = secBase;
		WindowsBinary::codeSectionSize = data->bufLen;
		return 1; // to break the callback loop
	}
	return 0;
}

SCAN_RESULT WindowsBinary::getStrings(std::vector<std::string>& vStrings) {
	STRING_OPTIONS options;
	options.printUniqueGlobal = false;
	options.printUniqueLocal = false;
	options.printAsciiOnly = false;
	options.printUnicodeOnly = false;
	options.printASM = true;
	options.printNormal = true;
	options.minCharacters = 4;

	string_parser* parser = new string_parser(options);
	FILE *pFile = fopen(sFilePath.c_str(), "rb");
	if (!pFile) {
		perror("Failed to read file\n");
		return SCAN_RESULT_NOT_FOUND;
	}
	bool bResult = parser->parse_stream(pFile, sFilePath.c_str());
	fclose(pFile);
	vStrings = parser->getBuffer();
	delete parser;
	if (bResult)
		return SCAN_RESULT_SUCCESS;
	else
		return SCAN_RESULT_PE_PARSE_ERROR;
}