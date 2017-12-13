#pragma once

#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

typedef long SCAN_RESULT;

#define SCAN_RESULT_SUCCESS 0x00000000
#define SCAN_RESULT_NOT_FOUND 0x00000001
#define SCAN_RESULT_NOT_BINARY 0x00000002
#define SCAN_RESULT_NOT_SUPPORT 0x00000004

#define SCAN_SUCCEED(x) (((SCAN_RESULT)(x)) == 0)
#define SCAN_FAILED(x) (((SCAN_RESULT)(x)) > 0)


static std::string scanResultToString(SCAN_RESULT sr) {
	switch(sr) {
		case SCAN_RESULT_SUCCESS: 		return "Scan succeed";
		case SCAN_RESULT_NOT_FOUND:		return "Could not find file to scan";
		case SCAN_RESULT_NOT_BINARY:	return "Target file is not binary";
		case SCAN_RESULT_NOT_SUPPORT:	return "Target file is not supported";
		default: return "Invalid scan result";
	}
}

#endif //SCAN_RESULT_H