#include "binary_file.h"

LinuxBinary::LinuxBinary(std::string sFilePath) : IBinaryFile(sFilePath) {

}


SCAN_RESULT LinuxBinary::scan(VulnReport** ppReport) {
	assert(ppReport == nullptr);

	return SCAN_RESULT_NOT_SUPPORT;
}

SCAN_RESULT LinuxBinary::getCodeSection(std::vector<uint8_t>& vCode) {
	return SCAN_RESULT_NOT_SUPPORT;
}