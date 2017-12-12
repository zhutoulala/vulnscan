#include "file_typer.h"
#include <stdio.h>

FileTyper::FileTyper(std::string& sFilePath) : sFilePath(sFilePath), type(TYPE::UNKNOWN){
}

void FileTyper::typing() {
	
	FILE * pFile = fopen(sFilePath.c_str(), "rb");
	if (pFile == NULL) {
		perror("Error opening file");
		return;
	}
	
	uint8_t firstByte = getc(pFile);
	if ((firstByte == 'M') && (getc(pFile) == 'Z')) {
		type = TYPE::EXE;
	}
	else if ((firstByte == 0x7f) && (getc(pFile) == 'E') && (getc(pFile) == 'L') && (getc(pFile) == 'F')) {
		type = TYPE::ELF;
	}

	else { 
		// a quick dirty way to check if file is binary
		// check if there is any NUL character in first 100 bytes
		size_t checkLength = 100;
		for (size_t i = 0; i < checkLength; i++) {
			if (getc(pFile) == '\n') {
				type = TYPE::BIN;
				break;
			}
		}
		if (type != TYPE::BIN) {
			type = TYPE::TEXT;
		}
	}
	fclose(pFile);
}

bool FileTyper::isBinary() {
	return type != TYPE::TEXT;
}