#include "scan_engine.h"
#include <iostream>
#include <experimental/filesystem>
#include <numeric>

namespace fs = std::experimental::filesystem;

CScanEngine::CScanEngine() {
	spSigLoader = std::make_shared<SignatureLoader>();
	bSigLoaded = false; // wait till scanning to load signatures
	vScanList = std::vector<std::string>();
	mSucceedScans = std::map<std::string, std::shared_ptr<IVulnReport>>();
}


bool CScanEngine::LoadSignatures() {
	if (!bSigLoaded && !spSigLoader->load("vulnscan.sigs")) {
		return false;
	}
	bSigLoaded = true;
	return bSigLoaded;
}

bool CScanEngine::scanPath(std::string sTargetPath) {

	if (!LoadSignatures()) {
		std::cout << "Failed to load signatures. " << std::endl;
		return false;
	}

	collectFile(sTargetPath);

	for (auto eachFile : vScanList) {
		scanFile(eachFile);
	}

	return mSucceedScans.size() > 0;
}

void CScanEngine::collectFile(std::string sTargetPath) {
	
	if (fs::is_regular_file(sTargetPath)) {
		vScanList.push_back(sTargetPath);
		return;
	}
	std::vector<std::string> vExtension = { ".exe", ".dll", ".EXE", ".DLL" };
	for (auto& each : fs::recursive_directory_iterator(sTargetPath)) {
		std::string sExtension = each.path().extension().string();
		if (std::find(vExtension.begin(), vExtension.end(), sExtension) != vExtension.end())
			vScanList.push_back(std::string(each.path().string()));
	}
}

bool CScanEngine::scanFile(std::string sTargetPath) {

	std::shared_ptr<IBinaryFile> spBinaryFile;
	SCAN_RESULT sr = BinaryFactory::GetBinary(sTargetPath, spBinaryFile);
	if (SCAN_FAILED(sr) || (spBinaryFile == nullptr)) {
		std::cout << "GetBinary failed: " << scanResultToString(sr) << std::endl;
		return false;
	}

	std::shared_ptr<IVulnReport> spVulnReport;

	auto spStringScanner = CScannerFactory::getScanner(EStringScanner, spSigLoader, spBinaryFile);
	
	sr = spStringScanner->scan(spVulnReport);
	if (SCAN_FAILED(sr)) {
		std::cout << spStringScanner->getType() << " failed to scan: " << scanResultToString(sr) << std::endl;
		return false;
	}

	auto spASMScanner = CScannerFactory::getScanner(EASMScanner, spSigLoader, spBinaryFile);
	sr = spASMScanner->scan(spVulnReport);
	if (SCAN_FAILED(sr)) {
		std::cout << spASMScanner->getType() << " failed to scan: " << scanResultToString(sr) << std::endl;
		return false;
	}

	mSucceedScans.insert(std::make_pair(sTargetPath, spVulnReport));
	return true;
}

void CScanEngine::printResults() {
	if (vScanList.size() == 0) {
		std::cout << "No file is scanned\n";
		return;
	}
		
	std::cout << "\n\n";
	std::cout << "==================================================\n";
	std::cout << "Scan Summary" << std::endl;
	std::cout << "--------------------------------------------------\n";
	std::cout << "Total to scan: \t" << vScanList.size() << std::endl;
	std::cout << "Successfully scanned: \t" << mSucceedScans.size() << std::endl;
	std::cout << "Vulnerability found: \t" << 
		std::accumulate(mSucceedScans.begin(), mSucceedScans.end(), 0, 
		[](size_t count, std::map<std::string, std::shared_ptr<IVulnReport>>::value_type &v) {
		return count + v.second->numberOfVuln();
	})
	<<std::endl;

	std::cout << "--------------------------------------------------\n";
	std::cout << "Detailed Report" << std::endl;
	std::cout << "--------------------------------------------------\n";
	for (auto eachFile : vScanList) {
		std::cout << eachFile << " - ";
		auto it = mSucceedScans.find(eachFile);
		if (it != mSucceedScans.end()) {
			std::cout << it->second->toString();
		}
		else {
			std::cout << "failed to scan";
		}
		std::cout << std::endl;
	}
	std::cout << "==================================================\n";
}
