#pragma once
#include "file_typer.h"
#include "scan_results.h"
#include "symbols.h"
#include "vuln_report.h"
#include "parser-library/parse.h"
#include <string>
#include <assert.h>

class IBinaryFile {

public:

	/**
	 * Add addtioanal symbol file for the binary. 
	 * The default symbol info from binary will be used if this is not called.
	 * @param sSymbolPath[in] - the path to addtional symbol file
	 */
	virtual void addSymbols(std::string sSymbolPath) = 0;

	/**
	 * Start analyzing the target binary file. This method needs to be called before rest methods
	 */
	virtual SCAN_RESULT analyze() = 0;

	/**
	 * Get the base address of the code section
	 */
	virtual uint64_t getCodeSectionBase() = 0;

	/**
	 * Get the length of code section
	 */
	virtual size_t getCodeSectionSize() = 0;

	/**
	 * Get code instructions from given address
	 * @param ullAddress[in] - address of the code instruction to get, must within code section address range
	 * @param iLength[in] - the length of instructions
	 * @param spInstSet[out] - pointer to the instruction set
	 * @return SCAN_RESULT_SUCCESS if succeed
	 */
	virtual SCAN_RESULT getInstFromAddress(uint64_t ullAddress, size_t iLength, 
		std::unique_ptr<Disassembler::InstructionSet>& spInstSet) = 0;
	
	/**
	 * Find target string in the binary
	 * @param[in] - string to search
	 * @return true if found else false
	 */
	virtual bool searchStrings(std::string sSearch) = 0;

	/**
	 * Get the symbol information for currect binary file
	 */
	virtual std::shared_ptr<ISymbols> getSymbols() = 0;

	/**
	 * Check if the binary file 64-bit
	 */
	virtual bool is64bit() = 0;
};


class WindowsBinary : public IBinaryFile {

public:
	WindowsBinary(std::string sFilePath);

public:
	void addSymbols(std::string sSymbolPath);

	SCAN_RESULT analyze();

	uint64_t getCodeSectionBase();
	size_t getCodeSectionSize();

	SCAN_RESULT getInstFromAddress(uint64_t ullAddress, size_t iLength,
		std::unique_ptr<Disassembler::InstructionSet>& spInstSet);
	
	bool searchStrings(std::string sSearch);

	

	inline std::shared_ptr<ISymbols> getSymbols() { return spSymbols; }

	inline bool is64bit() {
		return codeSectionBase > 0xffffffff;
	}

public:
	static int locateCodeSection(void *N,
		peparse::VA secBase,
		std::string &secName,
		peparse::image_section_header s,
		peparse::bounded_buffer *data);

public:
	static uint64_t codeSectionBase;
	static uint32_t codeSectionSize;

private:
	SCAN_RESULT readCodeSection();
	SCAN_RESULT readStrings();

private:
	std::string sFilePath;
	std::vector<uint8_t> vCode;
	std::vector<std::string> vStrings;
	std::shared_ptr<ISymbols> spSymbols;
};


class LinuxBinary : public IBinaryFile {
public:
	LinuxBinary(std::string sFilePath);

public:
	void addSymbols(std::string sSymbolPath);

	SCAN_RESULT analyze();

	uint64_t getCodeSectionBase();
	size_t getCodeSectionSize();

	SCAN_RESULT getInstFromAddress(uint64_t ullAddress, size_t iLength,
		std::unique_ptr<Disassembler::InstructionSet>& spInstSet);

	SCAN_RESULT getCodeSection(std::vector<uint8_t>& vCode);

	bool searchStrings(std::string sSearch);

	

	inline std::shared_ptr<ISymbols> getSymbols() { return spSymbols; }
	bool is64bit() { return false; }

private:
	SCAN_RESULT readStrings();

private:
	std::shared_ptr<ISymbols> spSymbols;
};


class BinaryFactory {
public:
	static SCAN_RESULT GetBinary(std::string sFilePath, std::unique_ptr<IBinaryFile>& spBinaryFile) {
		FileTyper typer(sFilePath);
		if (!typer.isBinary()) {
			return SCAN_RESULT_NOT_BINARY;
		}
		else if (typer.isEXE()) {
			spBinaryFile = std::make_unique<WindowsBinary>(sFilePath);
			return SCAN_RESULT_SUCCESS;
		}
		else if (typer.isELF()) {
			spBinaryFile = std::make_unique<LinuxBinary>(sFilePath);
		}

		return SCAN_RESULT_NOT_SUPPORT;
	}
};

