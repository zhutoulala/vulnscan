#include "disassembler.h"
#include "capstone.h"

namespace Disassembler {

SCAN_RESULT Disassembly(const std::vector<uint8_t>& vCode, InstructionSet& instructions) {
	csh handle;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		return SCAN_RESULT_NOT_FOUND;
	}
	instructions.count = cs_disasm(handle, vCode.data(), vCode.size()-1, 0x1000, 0, &(instructions.pInsn));
	cs_close(&handle);
	if (instructions.count <= 0) {
		return SCAN_RESULT_NOT_SUPPORT;
	}
	return SCAN_RESULT_SUCCESS;
}
};