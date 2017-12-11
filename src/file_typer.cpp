#include "file_typer.h"

FileTyper::FileTyper(std::string& sFilePath) : sFilePath(sFilePath){
}

bool FileTyper::isBinary() {
	return true;
}