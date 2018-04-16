#include "scan_engine.h"
#include <iostream>

CScanEngine::CScanEngine() {
	spSigLoader = std::make_shared<SignatureLoader>();
	bSigLoaded = false; // wait till scanning to load signatures
}


bool CScanEngine::LoadSignatures() {
	if (!bSigLoaded && !spSigLoader->load("vulnscan.sigs")) {
		return false;
	}
	bSigLoaded = true;
	return bSigLoaded;
}

int CScanEngine::scanFile(std::string sTargetPath) {
	if (!LoadSignatures()) {
		std::cout << "Failed to load signatures. " << std::endl;
		return -1;
	}

	std::shared_ptr<IBinaryFile> spBinaryFile;
	SCAN_RESULT sr = BinaryFactory::GetBinary(sTargetPath, spBinaryFile);
	if (SCAN_FAILED(sr) || (spBinaryFile == nullptr)) {
		std::cout << "GetBinary failed: " << scanResultToString(sr) << std::endl;
		return -1;
	}

	std::shared_ptr<IVulnReport> spVulnReport;

	auto spStringScanner = CScannerFactory::getScanner(EStringScanner, spSigLoader, spBinaryFile);
	
	sr = spStringScanner->scan(spVulnReport);
	if (SCAN_FAILED(sr)) {
		std::cout << spStringScanner->getType() << " failed to scan: " << scanResultToString(sr) << std::endl;
		return -1;
	}

	auto spASMScanner = CScannerFactory::getScanner(EASMScanner, spSigLoader, spBinaryFile);
	sr = spASMScanner->scan(spVulnReport);
	if (SCAN_FAILED(sr)) {
		std::cout << spASMScanner->getType() << " failed to scan: " << scanResultToString(sr) << std::endl;
		return -1;
	}
	std::cout << spVulnReport->toString() << std::endl;

	return 0;
}

