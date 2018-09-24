#include "scan_target.h"
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;

CScanTarget::CScanTarget(std::string sTargetPath) : sTargetPath (sTargetPath){
    qScanList = std::queue<std::string>();
}

bool CScanTarget::initialize() {
    collectFile();
    return !qScanList.empty();
}

std::string CScanTarget::getNextFile() {
    if (qScanList.empty()) return "";
    
    std::string sNextFile = qScanList.front();
    qScanList.pop();
    return sNextFile;
}

void CScanTarget::collectFile() {

    if (fs::is_regular_file(sTargetPath)) {
        qScanList.push(sTargetPath);
        return;
    }
    std::vector<std::string> vExtension = { ".exe", ".dll", ".EXE", ".DLL" };
    for (auto& each : fs::recursive_directory_iterator(sTargetPath)) {
        std::string sExtension = each.path().extension().string();
        if (std::find(vExtension.begin(), vExtension.end(), sExtension) != vExtension.end())
            qScanList.push(std::string(each.path().string()));
    }
}