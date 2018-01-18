#pragma once

#include "scan_results.h"
#include "capstone.h"

#include <vector>

namespace Disassembler {

typedef struct _InstructionSet {
	cs_insn *pInsn;
	size_t count;
} InstructionSet;

//typedef cs_insn InstructionSet;
	
SCAN_RESULT Disassembly(const std::vector<uint8_t>& vCode, InstructionSet& instructions);
};