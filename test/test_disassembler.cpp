#include "gtest/gtest.h"
#include "disassembler.h"

#include <vector>

TEST(Disassembler, Disassembly)
{
	// CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
	std::vector<uint8_t> vCode;
	vCode.push_back(0x55);
	vCode.push_back(0x48);
	vCode.push_back(0x8b);
	vCode.push_back(0x05);
	vCode.push_back(0xb8);
	vCode.push_back(0x13);
	vCode.push_back(0x00);
	vCode.push_back(0x00);

	Disassembler::InstructionSet instructions;
	SCAN_RESULT sr = Disassembler::Disassembly(vCode.data(), vCode.size(), 0, false, instructions);
	ASSERT_EQ(sr, SCAN_RESULT_SUCCESS);
	ASSERT_EQ(instructions.count, 3);

	Disassembler::InstructionSet instructions64;
	sr = Disassembler::Disassembly(vCode.data(), vCode.size(), 0, true, instructions64);
	ASSERT_EQ(sr, SCAN_RESULT_SUCCESS);
	ASSERT_EQ(instructions64.count, 2);
}