# vulnscan
It scans binary files to find if they contain known vulnerabilities that come from popular open source libraries.

Currently supported binary compile language: `c++`

Currently supported binary compiler: `visual studio, gcc, clang`

## How to build on Linux
```
mkdir build
cd build
cmake ..
make
```

## How to build on Windows
```
mkdir build
cd 
cmake ..
```
Then build the solution vulnscan.sln

## How to run this tool
copy data/vulnscan.sigs into the same folder as vulnscan, then run below command 
```
vulnscan [path to target binary file]
```
