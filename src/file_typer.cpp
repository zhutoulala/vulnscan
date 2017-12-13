#include "file_typer.h"
#include <stdio.h>

FileTyper::FileTyper(std::string& sFilePath) : sFilePath(sFilePath), type(TYPE::UNKNOWN){
	typing();
}

void FileTyper::typing() {
	FILE *pFile;
	if (fopen_s(&pFile, sFilePath.c_str(), "rb") != 0 || !pFile) {
		perror("Failed to read file\n");
		return;
	}
	uint8_t firstByte = getc(pFile);
	if (firstByte == 'M') {
		if (getc(pFile) == 'Z') {
			type = TYPE::EXE;
		}
	}
	else if (firstByte == 0x7f) {
		if ((getc(pFile) == 'E') && (getc(pFile) == 'L' && (getc(pFile) == 'F'))) {
			type = TYPE::ELF;
		}
	}
	else { 
		// a quick dirty way to check if file is binary
		// check if there is any NUL character in the first 100 bytes
		size_t checkLength = 100;
		for (size_t i = 0; i < checkLength; i++) {
			if (getc(pFile) == '\0') {
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