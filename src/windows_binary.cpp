#include "binary_file.h"
#include "file_typer.h"
#include "disassembler.h"

#include "string_parser.h"

#include <iostream>
#include <vector>
#include <memory>
#include <fstream>
#include <future>
#include <algorithm>


uint64_t WindowsBinary::codeSectionBase;
uint32_t WindowsBinary::codeSectionSize;

WindowsBinary::WindowsBinary(std::string sFilePath){
	this->sFilePath = sFilePath;
	vCode = std::vector<uint8_t>();
	vStrings = std::vector<std::string>();
	bAnalyzed = false;
}

void WindowsBinary::addSymbols(std::string sSymbolPath) {
	spSymbols = CSymbolsFactory::getSymbols(sSymbolPath);
	assert(spSymbols != nullptr);

	spSymbols->loadSymbols();
}

SCAN_RESULT WindowsBinary::analyze() {
	if (bAnalyzed)
		return SCAN_RESULT_SUCCESS;
	addSymbols(sFilePath); // use self contained symbols
	SCAN_RESULT sr = readStrings();
	if (SCAN_FAILED(sr))
		return sr;
	sr = readCodeSection(); // read code section into memory
	if (SCAN_FAILED(sr))
		return sr;
	bAnalyzed = true;
	return SCAN_RESULT_SUCCESS;
}


uint64_t WindowsBinary::getCodeSectionBase() {
	return WindowsBinary::codeSectionBase;
}

size_t WindowsBinary::getCodeSectionSize() {
	return WindowsBinary::codeSectionSize;
}

SCAN_RESULT WindowsBinary::getInstFromAddress(uint64_t ullAddress, size_t iLength, 
	std::unique_ptr<Disassembler::InstructionSet>& spInstSet) {
	assert(spInstSet == nullptr);

	spInstSet = std::make_unique<Disassembler::InstructionSet>();
	return Disassembler::Disassembly(vCode.data() + ullAddress - codeSectionBase, iLength, ullAddress, is64bit(), *spInstSet);
}

SCAN_RESULT WindowsBinary::readCodeSection() {

	if (vCode.size() > 0) {
		return SCAN_RESULT_SUCCESS; // already loaded
	}
	peparse::parsed_pe *pParsedPE = peparse::ParsePEFromFile(sFilePath.c_str());
	if (pParsedPE == nullptr) {
		std::cout << "Error: " << peparse::GetPEErr() << " (" << peparse::GetPEErrString() << ")" << endl;
		std::cout << "Location: " << peparse::GetPEErrLoc() << endl;
		return SCAN_RESULT_PE_PARSE_ERROR;
	}
	IterSec(pParsedPE, WindowsBinary::locateCodeSection, NULL);

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

SCAN_RESULT WindowsBinary::readStrings() {
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

bool WindowsBinary::searchStrings(std::string sSearch) {
	return std::find(vStrings.begin(), vStrings.end(), sSearch) != vStrings.end();
}