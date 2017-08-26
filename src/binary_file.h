#include "llvm/Support/MemoryBuffer.h"

class BinaryFile {

public:
    enum class FORMAT {
        EXE, //windows
        ELF, //linux
        NONPE
    };

private:
    FORMAT format;
    std::string sFilePath;

public:
    BinaryFile();
    BinaryFile(const std::string& sFilePath);

public:
    int scan();
    FORMAT getBinaryFormat();


private:
    int scanELF();
    int scanEXE():

    llvm::MemoryBuffer* getCodeSection();

};
