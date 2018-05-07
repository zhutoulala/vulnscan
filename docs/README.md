# About
vulnscan is a static binary vulnerablity scanner. It could be used to detect if target executable files contain any known vulnerability, that potentially comes from popular 3rd party libraries in use.

This tool is designed to be cross-platformed. It could be compiled and run on both Windows and Linux. Also it could be used to scan Windows executables and Linux executables. The currently supported scan targets include:

Windows executables: `exe dll`

Linux executables: `elf`

## How does it work
vulnscan is consisted of 2 types of scan engine, the string scanner and disassembly scanner. 

String scanner looks through all human readable strings in the target file and match them against predefined signatures of each known vulnerability.

Disassembly scanner uses [capstone](https://www.capstone-engine.org/) to disassemble the whole code section of target file. By examining the call sequence pattern of the potential vulnerable functions, it would be able to tell if those functions contains certain known vulnerabilities or not. 

## Signatures
signature is the information exacted from source code patches, that can uniquely identify one vulnerability. Download the latest [signatures](vulnscan.sigs)

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
copy data/vulnscan.sigs into the same folder as vulnscan, then run either below command
```
vulnscan [path to target binary file]
vulnscan [path to target folder]
```
