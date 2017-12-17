#include "binary_file.h"
#include "file_typer.h"
#include <iostream>
#include <assert.h>

SCAN_RESULT BinaryFactory::GetBinary(std::string sFilePath, IBinaryFile** ppBinaryFile) {
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
	else {
		return SCAN_RESULT_NOT_SUPPORT;
	}
}


WindowsBinary::WindowsBinary(std::string sFilePath) : IBinaryFile(sFilePath){

}

SCAN_RESULT WindowsBinary::scan(VulnReport** pReport) {
	assert(pReport == nullptr);
	*pReport = new VulnReport();

	return SCAN_RESULT_SUCCESS;
}
