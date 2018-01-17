#pragma once

#include "scan_results.h"
#include "vuln_report.h"
#include <string>
#include <Windows.h>

class IBinaryFile {

protected:
	std::string sFilePath;

public:
	IBinaryFile(std::string sFilePath){}
    virtual ~IBinaryFile(){}

public:
	virtual SCAN_RESULT scan(VulnReport** ppReport) = 0;
	virtual SCAN_RESULT getCodeSection(std::vector<uint8_t>& vCode) = 0;
};

class BinaryFactory {
public:
	static SCAN_RESULT GetBinary(std::string sFilePath, IBinaryFile** ppBinaryFile) {
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
};

class WindowsBinary : public IBinaryFile {

public:
	WindowsBinary(std::string sFilePath);

public:
	SCAN_RESULT scan(VulnReport** ppReport);
	SCAN_RESULT getCodeSection(std::vector<uint8_t>& vCode);

private:
	SCAN_RESULT ReadEntireFile();
	SCAN_RESULT ParsePE();

private:
	std::vector<uint8_t> vBuffer;
};


class LinuxBinary : public IBinaryFile {
public:
	LinuxBinary(std::string sFilePath);

public:
	SCAN_RESULT scan(VulnReport** ppReport);
	SCAN_RESULT getCodeSection(std::vector<uint8_t>& vCode);
};