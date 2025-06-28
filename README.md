# automated-binary-vuln-scanner

A modular static vulnerability scanner for Linux ELF binaries. It analyzes binary instructions using `objdump` and identifies unsafe function calls, heap overflows, and potential command injections — all without executing the binary.

## Features

### Stack-based Vulnerability Detection (`UnsafeDetector`)
- Disassembles `.text` section and analyzes instructions.
- Flags unsafe standard library calls:
  - `gets`, `strcpy`, `sprintf`, `scanf`, etc.
- Reports:
  - Instruction address (full virtual address)
  - Called function
  - Risk level (HIGH / MEDIUM)
  - Optional function name (if available via demangling)

### Heap-based Overflow Detection (`HeapOverflowDetector`)
- Tracks dynamic memory allocations (`malloc`, `calloc`)
- Checks copying instructions (`memcpy`, `strcpy`, etc.) that may exceed allocated size
- Detects `rep movsb` / `rep stosb` used on heap buffers
- Reports:
  - Instruction address
  - Number of bytes copied vs. allocation size
  - Allocation site address (if available)

### Command Injection Detection (`CommandInjectionDetector`)
- Identifies uses of:
  - `system`, `popen`, and all `exec*` variants
- Reports:
  - Instruction address
  - Target function (e.g., `system`)
  - Risk detail

## Prerequisites

- Linux (tested on Ubuntu/Debian)
- `g++` with C++17 support
- `binutils` (provides `objdump` and `c++filt`)
- `cmake` (optional but recommended)

## Build Instructions

### Option 1: Using CMake
```bash
sudo apt update
sudo apt install build-essential cmake binutils

git clone https://github.com/sondt99/automated-binary-vuln-scanner.git
cd automated-binary-vuln-scanner
mkdir build && cd build
cmake ..
make
```

### Option 2: Manual Compile
```bash
g++ -std=c++17 src/*.cpp -Iinclude -o scanner
```

## Usage

```bash
./scanner <binary_path>
```

### Sample Output

```
Analyzing binary: ./bof_vuln
Found 16 functions to analyze.

============================================================
 UNSAFE FUNCTION CALLS ANALYSIS
============================================================

[HIGH RISK] Found 1 issues:
--------------------------------------------------
   Address  : 0x0000000000401215
   Calls    : gets
   Analysis : Risk: HIGH - gets() doesn't check buffer bounds

============================================================
 HEAP OVERFLOW ANALYSIS
============================================================
✓ No heap overflow vulnerabilities detected.

============================================================
 COMMAND INJECTION ANALYSIS
============================================================
   Potential command injection:
   Address: 0x0000000000401188
   Calls  : system
   Detail : Call to `system` at 0x0000000000401188 can lead to command injection risks.

============================================================
 SUMMARY
============================================================
Total issues found: 2
├─ Unsafe function calls: 1
├─ Heap overflows       : 0
└─ Command injections   : 1

Review flagged issues carefully — some may be false positives.
Focus on HIGH risk findings first.
```

## Extending

To add your own vulnerability detector:

1. Create a new pair of files: `include/MyDetector.h` and `src/MyDetector.cpp`
2. Implement:
   ```cpp
   std::vector<MyDetector::Finding> detect(const std::vector<Function>& funcs) const;
   ```
3. Add your files to `CMakeLists.txt` or the `g++` compile command
4. Include and invoke your detector from `src/main.cpp` and print results similar to existing modules

## Contributing

Pull requests are welcome. You can contribute by:

- Adding new detectors (e.g., format string, integer overflow)
- Improving disassembly and instruction parsing
- Enhancing reporting formats (e.g., JSON output, IDE integration)
- Performance improvements
