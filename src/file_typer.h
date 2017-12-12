#pragma once

#include <string>

class FileTyper {
	
	
public:
    enum class TYPE {
        EXE, //windows executable
        ELF, //linux executable
		BIN, //other binaries
		TEXT,
        UNKNOWN
    };
	
private:
	std::string sFilePath;
	TYPE type;
	
public:
    FileTyper(std::string& sFilePath);
	
	
public:
	bool isBinary();

	void typing();
};