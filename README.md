# automated-binary-vuln-scanner

A simple modular binary vulnerability scanner for Linux that statically analyzes ELF binaries to detect potential buffer-overflow calls (e.g., gets, strcpy).

## Features
- Disassembles .text section using objdump.
- Demangles C++ symbols via c++filt.
- Detects unsafe calls (gets, strcpy, sprintf, etc.) and reports:
   - Function name
   - Function start address
   - Instruction address
   - Unsafe call target

## Prerequisites
- Linux (Ubuntu/Debian)
- g++ (C++17 support)
- binutils (provides objdump and c++filt)
- cmake (if using CMake)

## Build

### CMake
```bash
sudo apt update
sudo apt install build-essential cmake binutils

git clone https://github.com/sondt99/automated-binary-vuln-scanner.git
cd automated-binary-vuln-scanner
mkdir build && cd build
cmake ..
make
```
### Direct
```bash
g++ -std=c++17 src/*.cpp -Iinclude -o scanner
```
## Usage
```bash
./scanner /path/to/binary
```
Reports each potential overflow call:
```
[!] Potential overflow in 'vuln()':
    • Function start : 0x401200
    • Instr @        : 0x401215
    • Calls unsafe   : call <gets(char*)>
```

## Extending
Add new detectors by creating modules similar to UnsafeDetector.

Update CMakeLists and include paths accordingly.