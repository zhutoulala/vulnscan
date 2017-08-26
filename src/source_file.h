#include "clang/Frontend/FrontendOptions.h"

class SourceFile: clang::FrontendInputFile {

public:
    llvm::MemoryBuffer* getCodeSection() const;
};
