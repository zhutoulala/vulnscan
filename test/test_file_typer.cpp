#include "gtest/gtest.h"
#include "file_typer.h"
#include <string>


TEST(FileTyper, isBinary)
{
	std::string text("data\\1.txt");
	FileTyper typer(text);
	typer.typing();

    EXPECT_EQ(typer.isBinary(), false);
}
