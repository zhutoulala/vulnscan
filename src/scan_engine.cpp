#include "scan_engine.h"
#include <iostream>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

CScanEngine::CScanEngine() {
	spSigLoader = std::make_shared<SignatureLoader>();
	bSigLoaded = false; // wait till scanning to load signatures
	vScanList = std::vector<std::string>();
}


bool CScanEngine::LoadSignatures() {
	if (!bSigLoaded && !spSigLoader->load("vulnscan.sigs")) {
		return false;
	}
	bSigLoaded = true;
	return bSigLoaded;
}

int CScanEngine::scanPath(std::string sTargetPath) {

	if (!LoadSignatures()) {
		std::cout << "Failed to load signatures. " << std::endl;
		return -1;
	}

	collectFile(sTargetPath);

	int iRes = 0;
	for (auto eachFile : vScanList) {
		if (scanFile(eachFile) != 0) {
			iRes = -1;
		}
	}

	return iRes;
}

void CScanEngine::collectFile(std::string sTargetPath) {
	std::vector<std::string> vExtension = { ".exe", ".dll", ".EXE", ".DLL" };
	for (auto& each : fs::recursive_directory_iterator(sTargetPath)) {
		std::string sExtension = each.path().extension().string();
		if (std::find(vExtension.begin(), vExtension.end(), sExtension) != vExtension.end())
			vScanList.push_back(std::string(each.path().string()));
	}
}

int CScanEngine::scanFile(std::string sTargetPath) {

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

