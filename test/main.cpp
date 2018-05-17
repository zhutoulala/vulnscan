
#include "gtest/gtest.h"

int main(int argc, char** argv)
{
	int tmpDbgFlag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	tmpDbgFlag |= _CRTDBG_ALLOC_MEM_DF;
	tmpDbgFlag |= _CRTDBG_LEAK_CHECK_DF;
	_CrtSetDbgFlag(tmpDbgFlag);
	//_CrtMemState memoryState = { 0 };
	//_CrtMemCheckpoint(&memoryState);
    ::testing::InitGoogleTest(&argc, argv);


	int retval = RUN_ALL_TESTS();
	//_CrtDumpMemoryLeaks();
	// Check for leaks after tests have run
	//_CrtMemDumpAllObjectsSince(&memoryState);
	return retval;
}
