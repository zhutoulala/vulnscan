#include "scan_engine.h"
#include "scanner.h"
#include "gtest\gtest.h"
#include "gmock\gmock.h"
//#include <vld.h>


class CMockScanner : public IScanner {
public:
	MOCK_METHOD1(scan, SCAN_RESULT(std::shared_ptr<IVulnReport>& spVulnReport));
	MOCK_METHOD0(getType, std::string());
};


TEST(CScanEngine, scanFile) {
	std::shared_ptr<IScanner> spMockScanner = std::make_shared<CMockScanner>();
	CScanEngine engine(spMockScanner, spMockScanner);
	engine.scanFile(".");
}