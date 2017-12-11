#pragma once

#include <string>

class FileTyper {
	
private:
	std::string sFilePath;
	
public:
    FileTyper(std::string& sFilePath);
	
	
public:
	bool isBinary();
	
private:
	void typing();
};