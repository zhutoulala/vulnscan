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
	/**
	 * set current symbol file path
	 */
	virtual void setSymbolsPath(std::string sSymbolFile) = 0;

	/**
	 * load symbols from current symbol file path
	 */
	virtual void loadSymbols() = 0;

	/**
	 * unload current symbols
	 * this method has to be called before trying to load another symbol file
	 */
	virtual void unloadSymbols() = 0;

	/**
	 * get symbol from given address
	 */
	virtual SCAN_RESULT getSymbolFromAddress(PSYMBOLMAP pSymbolMap) = 0;
	
	/**
	 * get symbol file loaded address
	 */
	virtual uint64_t getLoadedAddress() = 0;
};


class CPDBSymbols : public ISymbols {

public:
	CPDBSymbols();
	~CPDBSymbols();
public:
	void setSymbolsPath(std::string sSymbolFile) { sCurrentSymbol = sSymbolFile; };
	void loadSymbols();
	void unloadSymbols();
	SCAN_RESULT getSymbolFromAddress(PSYMBOLMAP pSymbolMap);
	SCAN_RESULT enumSymbols(DWORD64 ModBase);
	bool ShowSymbolInfo(DWORD64 ModBase);
	inline uint64_t getLoadedAddress() { return dwLoadedAddr; }

private:
	std::string sCurrentSymbol;
	bool bSymbolLoaded;
	HANDLE hProcess;
	DWORD64 dwLoadedAddr;
};


class CSymbolsFactory {
public:
	static std::shared_ptr<ISymbols> getSymbols(std::string sSymbolFile) {
		/*std::string sExtension = ".pdb";
		if (sSymbolFile.compare(sSymbolFile.length() - sExtension.length(),
			sExtension.length(), sExtension) == 0) {
			return std::make_unique<CPDBSymbols>(sSymbolFile);
		}
		return nullptr;*/
		if (g_spSymbols == nullptr) {
			g_spSymbols = std::make_shared<CPDBSymbols>();
		}
		g_spSymbols->setSymbolsPath(sSymbolFile);
		g_spSymbols->loadSymbols();
		return g_spSymbols;
	}
private:
	static std::shared_ptr<ISymbols> g_spSymbols;
};