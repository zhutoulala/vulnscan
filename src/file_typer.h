#pragma once

#ifndef FILE_TYPER_H
#define FILE_TYPER_H
#include "gtest/gtest_prod.h"
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
	inline bool isBinary() {return type != TYPE::TEXT;};
	inline bool isEXE() {return type == TYPE::EXE;};
	inline bool isELF() {return type == TYPE::ELF;};
	
private:
	FRIEND_TEST(FileTyper, typing);
	void typing();
};

#endif //FILE_TYPER_H