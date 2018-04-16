#include "scanner.h"

class CStringScanner : public IScanner {
public:
	CStringScanner();

public:
	SCAN_RESULT initialize(std::shared_ptr<Signature> SignatureLoader);
	SCAN_RESULT scan(std::shared_ptr<IBinaryFile> spBinaryFile, std::unique_ptr<IVulnReport>& spVulnReport);

};