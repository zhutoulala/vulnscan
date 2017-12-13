#include "gtest/gtest.h"
#include "file_typer.h"
#include <string>
#include <fstream>

TEST(FileTyper, typing)
{
	std::string tempFile("typing_test.temp");
	std::ofstream out;
	out.open(tempFile, std::ios::out);
	
	out << "This is a text file.\n";
	out.close();
	FileTyper typer(tempFile);
	typer.typing();
    EXPECT_EQ(typer.isBinary(), false);
	
	out.open(tempFile, std::ios::out | std::ios::binary);
	out << "MZ";
	out.close();
	typer.typing();
	EXPECT_EQ(typer.isEXE(), true);
	
	out.open(tempFile, std::ios::out | std::ios::binary);
	char bytes1[4] = { 0x7f, 'E','L','F' };
	out.write(bytes1, 4);
	out.close();
	typer.typing();
	EXPECT_EQ(typer.isELF(), true);
	
	out.open(tempFile, std::ios::out | std::ios::binary);
	char bytes2[4] = { 'A', 'B','C','\0' };
	out.write(bytes2, 4);
	out.close();
	typer.typing();
	EXPECT_EQ(typer.isBinary(), true);

	std::remove(tempFile.c_str());
}