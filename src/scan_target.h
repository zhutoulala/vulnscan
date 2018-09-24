#pragma once

#include <queue>
#include <memory>

class IScanTarget {
public:
    /**
     * get next file to scan
     * @return NULL if no more files to scan
     */
    virtual std::string getNextFile() = 0;

    /**
     * validate and initialize the scan target, collect all scanable files
     */
    virtual bool initialize() = 0;

};

class CScanTarget : public IScanTarget {
public:
    CScanTarget(std::string sTargetPath);
    bool initialize();
    std::string getNextFile();

private:
    void collectFile();

private:
    std::string sTargetPath;
    std::queue<std::string> qScanList;
};

class CScanTargetFactory {
public:
    static std::unique_ptr<IScanTarget> createScanTarget(std::string sTargetPath) {
        return std::make_unique<CScanTarget>(sTargetPath);
    }
};