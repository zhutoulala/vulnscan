#ifdef _WIN32 // will need DbgHelp
#include "symbols.h"

#include <Windows.h>
#include <tchar.h>
#include <assert.h>
#include <DbgHelp.h>
#include <iostream>
#pragma comment(lib, "dbghelp.lib")


CPDBSymbols::CPDBSymbols(std::string sSymbolFile){
	sSymbolPath = sSymbolFile;
	bSymbolLoaded = false;
	hProcess = nullptr;
}

SCAN_RESULT CPDBSymbols::loadSymbols() {
	DWORD  error;

	SymSetOptions(SYMOPT_UNDNAME);

	hProcess = GetCurrentProcess();

	if (!SymInitialize(hProcess, NULL, TRUE))
	{
		// SymInitialize failed
		error = GetLastError();
		printf("SymInitialize returned error : %d\n", error);
		return FALSE;
	}

	DWORD64 dwLoadedAddr = SymLoadModuleEx(hProcess,    // target process 
		NULL,        // handle to image - not used
		sSymbolPath.c_str(), // name of image file
		NULL,        // name of module - not required
		0,			 // can't be zero since loading from .pdb
		0,           // size of image - not required
		NULL,        // MODLOAD_DATA used for special cases 
		0);          // flags - not required

	if (!dwLoadedAddr){
		DWORD error = GetLastError();
		printf("SymLoadModuleEx returned error : %d\n", error);
		return SCAN_RESULT_SYMBOL_NOT_LOADED;
	}
	bSymbolLoaded = true;
	//ShowSymbolInfo(dwLoadedAddr);
	//enumSymbols(dwLoadedAddr);
	return SCAN_RESULT_SUCCESS;
}

BOOL CALLBACK EnumSymProc(
	PSYMBOL_INFO pSymInfo,
	ULONG SymbolSize,
	PVOID UserContext)
{
	UNREFERENCED_PARAMETER(UserContext);
	std::string sSymbolName(pSymInfo->Name, pSymInfo->NameLen);
	printf("0x%llx\t", pSymInfo->Address);
	std::cout << sSymbolName << std::endl;
	return TRUE;
}

SCAN_RESULT CPDBSymbols::enumSymbols(DWORD64 ModBase) {
	if (!bSymbolLoaded)
		return SCAN_RESULT_SYMBOL_NOT_LOADED;

	if (!SymEnumSymbols(hProcess,     // Process handle from SymInitialize.
		ModBase,   // Base address of module.
		NULL,        // Name of symbols to match.
		EnumSymProc, // Symbol handler procedure.
		NULL))       // User context.
	{
		// SymEnumSymbols failed
		printf("SymEnumSymbols failed: %d\n", GetLastError());
	}

	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT CPDBSymbols::getSymbolFromAddress(PSYMBOLMAP pSymbolMap) {
	assert(pSymbolMap != nullptr);
	assert(pSymbolMap->iAddress != 0);

	if (!bSymbolLoaded)
		return SCAN_RESULT_SYMBOL_NOT_LOADED;

	DWORD64  dwDisplacement = 0;

	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	PDWORD64 pDisplacement = reinterpret_cast<PDWORD64>(&pSymbolMap->iDisplacement);
	if (!SymFromAddr(hProcess, pSymbolMap->iAddress, pDisplacement, pSymbol))
	{
		// SymFromAddr failed
		DWORD error = GetLastError();
		//printf("SymFromAddr returned error : %d\n", error);
		return SCAN_RESULT_SYMBOL_NOT_FOUND;
	}
	pSymbolMap->sName = std::string(pSymbol->Name, pSymbol->NameLen);
	return SCAN_RESULT_SUCCESS;
}

SCAN_RESULT CPDBSymbols::unloadSymbols() {
	if (!bSymbolLoaded)
		return SCAN_RESULT_SYMBOL_NOT_LOADED;

	assert(hProcess != nullptr);
	assert(dwLoadedAddr != 0);
	if (!SymUnloadModule64(hProcess, dwLoadedAddr))
	{
		// SymUnloadModule64 failed
		DWORD error = GetLastError();
		printf("SymUnloadModule64 returned error : %d\n", error);

	}

	return SCAN_RESULT_SUCCESS;
}

void CPDBSymbols::ShowSymbolInfo(DWORD64 ModBase)
{
	// Get module information 

	IMAGEHLP_MODULE64 ModuleInfo;

	memset(&ModuleInfo, 0, sizeof(ModuleInfo));

	ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);

	BOOL bRet = ::SymGetModuleInfo64(GetCurrentProcess(), ModBase, &ModuleInfo);

	if (!bRet)
	{
		_tprintf(_T("Error: SymGetModuleInfo64() failed. Error code: %u \n"), ::GetLastError());
		return;
	}


	// Display information about symbols 

	// Kind of symbols 

	switch (ModuleInfo.SymType)
	{
	case SymNone:
		_tprintf(_T("No symbols available for the module.\n"));
		break;

	case SymExport:
		_tprintf(_T("Loaded symbols: Exports\n"));
		break;

	case SymCoff:
		_tprintf(_T("Loaded symbols: COFF\n"));
		break;

	case SymCv:
		_tprintf(_T("Loaded symbols: CodeView\n"));
		break;

	case SymSym:
		_tprintf(_T("Loaded symbols: SYM\n"));
		break;

	case SymVirtual:
		_tprintf(_T("Loaded symbols: Virtual\n"));
		break;

	case SymPdb:
		_tprintf(_T("Loaded symbols: PDB\n"));
		break;

	case SymDia:
		_tprintf(_T("Loaded symbols: DIA\n"));
		break;

	case SymDeferred:
		_tprintf(_T("Loaded symbols: Deferred\n")); // not actually loaded 
		break;

	default:
		_tprintf(_T("Loaded symbols: Unknown format.\n"));
		break;
	}

	// Image name 

	if (_tcslen(ModuleInfo.ImageName) > 0)
	{
		_tprintf(_T("Image name: %s \n"), ModuleInfo.ImageName);
	}

	// Loaded image name 

	if (_tcslen(ModuleInfo.LoadedImageName) > 0)
	{
		_tprintf(_T("Loaded image name: %s \n"), ModuleInfo.LoadedImageName);
	}

	// Loaded PDB name 

	if (_tcslen(ModuleInfo.LoadedPdbName) > 0)
	{
		_tprintf(_T("PDB file name: %s \n"), ModuleInfo.LoadedPdbName);
	}

	// Is debug information unmatched ? 
	// (It can only happen if the debug information is contained 
	// in a separate file (.DBG or .PDB) 

	if (ModuleInfo.PdbUnmatched || ModuleInfo.DbgUnmatched)
	{
		_tprintf(_T("Warning: Unmatched symbols. \n"));
	}

	// Contents 

	// Line numbers available ? 

	_tprintf(_T("Line numbers: %s \n"), ModuleInfo.LineNumbers ? _T("Available") : _T("Not available"));

	// Global symbols available ? 

	_tprintf(_T("Global symbols: %s \n"), ModuleInfo.GlobalSymbols ? _T("Available") : _T("Not available"));

	// Type information available ? 

	_tprintf(_T("Type information: %s \n"), ModuleInfo.TypeInfo ? _T("Available") : _T("Not available"));

	// Source indexing available ? 

	_tprintf(_T("Source indexing: %s \n"), ModuleInfo.SourceIndexed ? _T("Yes") : _T("No"));

	// Public symbols available ? 

	_tprintf(_T("Public symbols: %s \n"), ModuleInfo.Publics ? _T("Available") : _T("Not available"));


}
#endif //  _WIN32
