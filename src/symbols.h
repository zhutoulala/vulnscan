#pragma once

#include "scan_results.h"
#include <memory>

typedef void *HANDLE;
typedef uint64_t DWORD64;

typedef struct _SYMBOLMAP {
	int64_t iAddress;
	int64_t iDisplacement;
	std::string sName;
} SYMBOLMAP, *PSYMBOLMAP;

class ISymbols {
public:
	virtual void setSymbolsPath(std::string sSymbolFile) = 0;
	virtual SCAN_RESULT loadSymbols() = 0;
	virtual SCAN_RESULT unloadSymbols() = 0;
	virtual SCAN_RESULT getSymbolFromAddress(PSYMBOLMAP pSymbolMap) = 0;
	virtual uint64_t getLoadedAddress() = 0;
};


class CPDBSymbols : public ISymbols {

public:
	CPDBSymbols(std::string sSymbolFile);
	~CPDBSymbols();
public:
	void setSymbolsPath(std::string sSymbolFile) {sSymbolPath = sSymbolFile;}
	SCAN_RESULT loadSymbols();
	SCAN_RESULT unloadSymbols();
	SCAN_RESULT getSymbolFromAddress(PSYMBOLMAP pSymbolMap);
	SCAN_RESULT enumSymbols(DWORD64 ModBase);
	bool ShowSymbolInfo(DWORD64 ModBase);
	inline uint64_t getLoadedAddress() { return dwLoadedAddr; }

private:
	std::string sSymbolPath;
	bool bSymbolLoaded;
	HANDLE hProcess;
	DWORD64 dwLoadedAddr;
};


class CSymbolsFactory {
public:
	static std::unique_ptr<ISymbols> getSymbols(std::string sSymbolFile) {
		/*std::string sExtension = ".pdb";
		if (sSymbolFile.compare(sSymbolFile.length() - sExtension.length(),
			sExtension.length(), sExtension) == 0) {
			return std::make_unique<CPDBSymbols>(sSymbolFile);
		}
		return nullptr;*/
		return std::make_unique<CPDBSymbols>(sSymbolFile);
	}
};