#pragma once

#include "scan_results.h"
#include "binary_file.h"
#include <memory>
#include <list>

enum ScannerType {
	EStringScanner = 0,
	EASMScanner,
};

class IScanner {
public:

	virtual SCAN_RESULT scan(std::shared_ptr<IVulnReport>& spVulnReport) = 0;

	virtual std::string getType() = 0;
};

class CStringScanner : public IScanner {
public:
	CStringScanner(std::shared_ptr<SignatureLoader> spSigLoader,
		std::shared_ptr<IBinaryFile> spBinaryFile);

public:

	SCAN_RESULT scan(std::shared_ptr<IVulnReport>& spVulnReport);

	std::string getType() { return "String Scanner"; }

private:
	std::shared_ptr<SignatureLoader> spSigLoader;
	std::shared_ptr<IBinaryFile> spBinaryFile;

};


class CASMScanner : public IScanner {

public:
	CASMScanner(std::shared_ptr<SignatureLoader> spSigLoader, 
		std::shared_ptr<IBinaryFile> spBinaryFile);

public:
	SCAN_RESULT scan(std::shared_ptr<IVulnReport>& spVulnReport);

	std::string getType() { return "Assembly Scanner"; }

private:
	

	bool getNextFunction(std::string& sFunction);
	bool getFunctionEnding(const std::string sFunction);
	bool getCallSequence(std::string sFunction, std::vector<std::string>& vCalls);
	
private:
	size_t seekToInstruction(uint64_t iStartPos, size_t iBatchSize,
		std::string sMnemonic, const std::vector<std::string>& vsOperand);
	/**
	 * get function at current offset
	 */
	std::string getCurrentSymbol();
	bool getSymbolAtAddress(uint64_t ullAddress, std::string& sSymbol);
	bool getSymbolAtOffset(size_t iOffset, std::string& sSymbol);

private:
	std::shared_ptr<SignatureLoader> spSigLoader;
	std::shared_ptr<IBinaryFile> spBinaryFile;
	std::shared_ptr<ISymbols> spSymbols;
	size_t iCurrentOffset; // current scan offset of target binary file
	uint64_t ullCodeSectionBase;
	size_t iCodeSectionLength;

	size_t iBatchSize; // default scan batch size, read how many bits each time
};

class CScannerFactory {
public:
	static std::shared_ptr<IScanner> getScanner(ScannerType scannerType, 
		std::shared_ptr<SignatureLoader> spSigLoader, 
		std::shared_ptr<IBinaryFile> spBinaryFile) {
		switch (scannerType)
		{
		case EStringScanner:
			return std::make_shared<CStringScanner>(spSigLoader, spBinaryFile);
		case EASMScanner:
			return std::make_shared<CASMScanner>(spSigLoader, spBinaryFile);
		default:
			return nullptr;
		}
	}
};