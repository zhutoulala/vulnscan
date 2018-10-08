#pragma once

#include <string>
typedef uint32_t SCAN_RESULT;

#define SCAN_RESULT_SUCCESS 0x00000000
#define SCAN_RESULT_NOT_FOUND 0x00000001
#define SCAN_RESULT_NOT_BINARY 0x00000002
#define SCAN_RESULT_NOT_SUPPORT 0x00000004
#define SCAN_RESULT_PE_PARSE_ERROR 0x00000008
#define SCAN_RESULT_NO_SIGS		0x0000000F
#define SCAN_RESULT_SYMBOL_NOT_LOADED		0x00000010
#define SCAN_RESULT_SYMBOL_NOT_FOUND		0x00000020
#define SCAN_RESULT_OUT_OF_BUFFER           0x00000040

#define SCAN_SUCCEED(x) (((SCAN_RESULT)(x)) == 0)
#define SCAN_FAILED(x) (((SCAN_RESULT)(x)) > 0)


static std::string scanResultToString(SCAN_RESULT sr) {
	switch(sr) {
		case SCAN_RESULT_SUCCESS: 			return "Scan succeed";
		case SCAN_RESULT_NOT_FOUND:			return "Could not find file to scan";
		case SCAN_RESULT_NOT_BINARY:		return "Target file is not binary";
		case SCAN_RESULT_NOT_SUPPORT:		return "Target file is not supported";
		case SCAN_RESULT_PE_PARSE_ERROR:	return "PE parsing error";
		case SCAN_RESULT_NO_SIGS:			return "Signatures are not loaded";
		case SCAN_RESULT_SYMBOL_NOT_LOADED:			return "Symbols are not loaded";
		case SCAN_RESULT_SYMBOL_NOT_FOUND:			return "Symbol could not be found for given address";
        case SCAN_RESULT_OUT_OF_BUFFER:             return "Scan is running of out buffer memory";
		default: return "Invalid scan result";
	}
}


typedef uint32_t DETECTION_STATUS;

#define DETECTION_NOMATCH 0x00000000
#define DETECTION_STRING_MATCH 0x00000001
#define DETECTION_ASM_MATCH 0x00000010
#define DETECTION_POSITIVE_MATCH 0x00000100
#define DETECTION_NEGATIVE_MATCH 0x00001000

static std::string detectionToConfidence(DETECTION_STATUS status) {
	if ((DETECTION_ASM_MATCH & status) &&
		(DETECTION_STRING_MATCH & status) &&
		(DETECTION_POSITIVE_MATCH & status))

		return " (confidence : high)";

	if ((DETECTION_STRING_MATCH & status) && 
		(DETECTION_POSITIVE_MATCH & status))
		return " (confidence : median)";

	if ((DETECTION_ASM_MATCH & status) && 
		(DETECTION_POSITIVE_MATCH & status))
		return " (confidence : low)";

	if (DETECTION_NEGATIVE_MATCH & status)
		return " (patched, no worry)"; 
	return "";
}