#include "disassembler.h"
#include "capstone.h"
#include "binary_file.h"

namespace Disassembler {

SCAN_RESULT Disassembly(const uint8_t* code, size_t size, 
	uint64_t baseAddress, bool b64bit, InstructionSet& instructions) {
	csh handle;
	if (cs_open(CS_ARCH_X86, b64bit ? 
		CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK) {
		return SCAN_RESULT_NOT_FOUND;
	}
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	instructions.count = cs_disasm(handle, code, size, 
		baseAddress, 0, &(instructions.pInsn));
	cs_close(&handle);
	if (instructions.count <= 0) {
		return SCAN_RESULT_NOT_SUPPORT;
	}
	return SCAN_RESULT_SUCCESS;
}
};