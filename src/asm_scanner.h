#include "scanner.h"

class CASMScanner : public IScanner {

public:
	CASMScanner();

public:
	SCAN_STATUS initialize(std::shared_ptr<Signature> SignatureLoader);
	SCAN_STATUS scan(std::shared_ptr<IBinaryFile> spBinaryFile, std::unique_ptr<IVulnReport>& spVulnReport);
};