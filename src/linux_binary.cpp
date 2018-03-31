#include "binary_file.h"

LinuxBinary::LinuxBinary(std::string sFilePath) {

}

void LinuxBinary::addSymbols(std::string sSymbolPath) {

}

SCAN_RESULT LinuxBinary::analyze() {
	return SCAN_RESULT_NOT_SUPPORT;
}

uint64_t LinuxBinary::getCodeSectionBase() {
	return 0;
}
size_t LinuxBinary::getCodeSectionSize() {
	return 0;
}

SCAN_RESULT LinuxBinary::getInstFromAddress(uint64_t ullAddress, size_t iLength,
	std::unique_ptr<Disassembler::InstructionSet>& spInstSet) {
	return SCAN_RESULT_NOT_SUPPORT;
}

SCAN_RESULT LinuxBinary::getCodeSection(std::vector<uint8_t>& vCode) {
	return SCAN_RESULT_NOT_SUPPORT;
}

SCAN_RESULT LinuxBinary::readStrings() {
	return SCAN_RESULT_NOT_SUPPORT;
}

bool LinuxBinary::searchStrings(std::string sSearch) {
	return false;
}