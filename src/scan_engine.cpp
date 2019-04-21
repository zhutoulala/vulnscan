#include "scan_engine.h"
#include "scan_target.h"
#include <iostream>

#include <numeric>

CScanEngine::CScanEngine() {
	spSigLoader = std::make_shared<SignatureLoader>();
	mSucceedScans = std::map<std::string, std::shared_ptr<IVulnReport>>();
    m_threadPool = CThreadPoolFactory::getThreadPool();
}

bool CScanEngine::scanPath(std::string sTargetPath) {
    
	if (!spSigLoader->load()) {
		std::cout << "Failed to load signatures. Does vulnscan.sigs exist?" << std::endl;
		return false;
	}

    std::unique_ptr<IScanTarget> spScanTarget = CScanTargetFactory::createScanTarget(sTargetPath);
    std::cout << "Inspecting scan target path..." << std::endl;
    if (!spScanTarget->initialize()) {
        std::cout << "Failed to initalize scan target." << std::endl;
        return false;
    }

    std::vector<CTaskFuture<void>> vTasks;
    std::string sNextFile = spScanTarget->getNextFile();
    while (!sNextFile.empty()) {
        vTasks.push_back(m_threadPool->submit([this](std::string sFilePath) {
            scanFile(sFilePath);
        }, sNextFile));
        sNextFile = spScanTarget->getNextFile();
    }
    for (auto& item : vTasks)
    {
        item.get();
    }
	return true;
}

void CScanEngine::scanFile(std::string sTargetPath) {
    
	std::shared_ptr<IBinaryFile> spBinaryFile;
	SCAN_RESULT sr = BinaryFactory::GetBinary(sTargetPath, spBinaryFile);
	if (SCAN_FAILED(sr) || (spBinaryFile == nullptr)) {
		std::cout << "GetBinary failed: " << scanResultToString(sr) << std::endl;
		return;
	}

	std::cout << "Scanning ===> " << spBinaryFile->getFilePath();
	std::cout << " ......\n";
	std::shared_ptr<IVulnReport> spVulnReport;

    auto spStringScanner = CScannerFactory::getScanner(EStringScanner, spSigLoader, spBinaryFile);
    assert(spStringScanner != nullptr);
    
    sr = spStringScanner->scan(spVulnReport);

	if (SCAN_FAILED(sr)) {
		std::cout << spStringScanner->getType() << " failed to scan: " << scanResultToString(sr) << std::endl;
		return;
	}

    /*auto spASMScanner = CScannerFactory::getScanner(EASMScanner, spSigLoader, spBinaryFile);
    assert(spASMScanner != nullptr);
	
    sr = spASMScanner->scan(spVulnReport);
	if (SCAN_FAILED(sr)) {
		std::cout << spASMScanner->getType() << " failed to scan: " << scanResultToString(sr) << std::endl;
	}*/
    else {
        std::lock_guard<std::mutex> lock{ m_mutex };
	    mSucceedScans.insert(std::make_pair(sTargetPath, spVulnReport));
    }
}

void CScanEngine::printResults() {
    std::lock_guard<std::mutex> lock{ m_mutex };
	if (vFailedScans.size() + mSucceedScans.size() == 0) {
		std::cout << "No file is scanned\n";
		return;
	}
		
	std::cout << "\n\n";
	std::cout << "==================================================\n";
	std::cout << "Scan Summary" << std::endl;
	std::cout << "--------------------------------------------------\n";
	std::cout << "Total to scan: \t" << vFailedScans.size() + mSucceedScans.size() << std::endl;
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
    for (auto each : mSucceedScans) {
        std::cout << each.first << " - " << each.second->toString();;
    }
	std::cout << "==================================================\n";
}
