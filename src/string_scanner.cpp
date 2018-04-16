#include "scanner.h"
#include <iostream>

CStringScanner::CStringScanner(std::shared_ptr<SignatureLoader> spSigLoader,
	std::shared_ptr<IBinaryFile> spBinaryFile)
	: spSigLoader(spSigLoader){
	assert(spBinaryFile != nullptr);
	this->spBinaryFile = spBinaryFile;
}

SCAN_RESULT CStringScanner::scan(std::shared_ptr<IVulnReport>& spVulnReport) {
	SCAN_RESULT sr = spBinaryFile->analyze();
	if (SCAN_FAILED(sr)) {
		std::cout << "Failed to analyze binary" << std::endl;
		return sr;
	}

	if (spVulnReport == nullptr)
		spVulnReport = CVulnReportFactory::createReport();

	auto vStrings = spBinaryFile->getStrings();
	for (size_t i = 0; i < spSigLoader->getSize(); i++) {
		auto spSignature = spSigLoader->getSignature(i);
		if (spSignature->hasStringSig()) {
			DETECTION_STATUS status = spSignature->stringMatch(vStrings);
			if (status != DETECTION_NOMATCH)
				spVulnReport->addDetection(spSignature->getCVE(), status);
		}

	}

	return SCAN_RESULT_SUCCESS;
}