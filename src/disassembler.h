#pragma once

#include "scan_results.h"
#include "capstone.h"

#include <vector>

namespace Disassembler {

typedef struct cs_insn Instruction, *PInstruction;

typedef struct _InstructionSet {
	cs_insn* pInsn;
	size_t count;

	~_InstructionSet() { cs_free(pInsn, count); }
} InstructionSet;
	
SCAN_RESULT Disassembly(const uint8_t* code, size_t size, uint64_t baseAddress, bool b64bit, InstructionSet& instructions);
};