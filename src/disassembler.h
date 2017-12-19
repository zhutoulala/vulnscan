#include "capstone.h"

#include <vector>

namespace Disassembler {

typedef cs_insn InstructionSet;
	
SCAN_RESULT Disassembly(const std::vector<uint8_t>& vCode, InstructionSet** ppInstructions);
};