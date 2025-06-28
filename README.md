# automated-binary-vuln-scanner

A simple modular binary vulnerability scanner for Linux that statically analyzes ELF binaries to detect potential buffer-overflow issues in both stack and heap contexts.

## Features
- Disassembly of the `.text` section using `objdump`.
- Demangling of C++ symbols via `c++filt`.

- Stack-based overflow detection via `UnsafeDetector`:
  - Flags unsafe calls (`gets`, `strcpy`, `sprintf`, etc.) and repeat-store loops (`rep movs`/`rep stos`).
  - Reports:
    - Function name
    - Function start address
    - Instruction address
    - Unsafe call target

- Heap-based overflow detection via `HeapOverflowDetector`:
    - Tracks dynamic allocations (`malloc`, `calloc`, `realloc`) and their sizes.
    - Flags copy routines (`memcpy`, `memmove`, `strcpy`, `strncpy`) when the number of bytes copied exceeds the allocated buffer size.
    - Detects unbounded `rep movsb`/`rep stosb` operations on heap buffers.
    - Reports:
      - Function name
      - Instruction address of copy or repeat-store
      - Exact bytes copied vs. allocation size and the allocation site address

## Prerequisites
- Linux (Ubuntu/Debian)
- g++ (C++17 support)
- binutils (provides `objdump` and `c++filt`)
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
```bash
[!] Potential unsafe call (stack-based overflows) in 'main':
    • Function start : 0x00000000004011EA
    • Instr @        : 0x401279
    • Calls unsafe   : call <strcpy@plt>

[!] Potential heap-based buffer overflow in 'main':
    • Instr @        : 0x401279
    • Detail         : strcpy at 0x401279 copies 401080 bytes into buffer of size 8 allocated at 0x401270
```

Extending

To add a new detector module:

1. Create a new header/source pair under include/ and src/, following the pattern of UnsafeDetector or HeapOverflowDetector.

2. Implement a detect(const std::vector<Function>&) method that returns a vector of findings.

3. Update CMakeLists.txt (or your build command) to compile the new files.

4. Include and invoke your detector in src/main.cpp, printing its findings similarly to existing modules.

Feel free to submit pull requests for additional vulnerability checks or improvements!