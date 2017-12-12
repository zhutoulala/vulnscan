#include "gtest/gtest.h"
#include "file_typer.h"
#include <string>


TEST(FileTyper, isBinary)
{
	std::string test("test");
	FileTyper typer(test);
    EXPECT_EQ(typer.isBinary(), true);
}
