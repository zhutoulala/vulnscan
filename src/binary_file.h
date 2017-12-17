#pragma once

#include "scan_results.h"
#include "vuln_report.h"
#include <string>

class IBinaryFile {

private:
	std::string sFilePath;

public:
	IBinaryFile(std::string sFilePath){}
    virtual ~IBinaryFile(){}
public:
	virtual SCAN_RESULT scan(VulnReport** ppReport) = 0;	
};

class BinaryFactory {
public:
	SCAN_RESULT GetBinary(std::string sFilePath, IBinaryFile** ppBinaryFile);
};

class WindowsBinary : public IBinaryFile {
public:
	WindowsBinary(std::string sFilePath);

public:
	SCAN_RESULT scan(VulnReport** ppReport);

};


class LinuxBinary : public IBinaryFile {
public:
	LinuxBinary(std::string sFilePath);

public:
	SCAN_RESULT scan(VulnReport** ppReport);

};