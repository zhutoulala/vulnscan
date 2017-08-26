


int BinaryFile::scan() {
    switch (format) {
    case FORMAT::EXE:
        return scanEXE();
    case FORMAT::ELF:
        return scanELF();
    default:

    }
    return -1;
}
