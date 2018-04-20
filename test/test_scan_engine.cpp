#include "scan_engine.h"
#include "gtest\gtest.h"

TEST(CScanEngine, getScanList) {
	CScanEngine engine;
	engine.collectFile(".");
	ASSERT_TRUE(engine.getScanList().size() > 0);
}